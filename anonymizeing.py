BROADCAST = "ff:ff:ff:ff:ff:ff"
import random
import gzip
import os, time
import hashlib


if not os.path.exists("anon.dat"):
    print("Error: must create anon.dat for anonymizing data! Please run keygen.sh")
    exit(1)
ANON_DATA = open("anon.dat", "rb").read()


# This function will change all user hashes every week
def weeklyStamp():
    anonTimeFactor = ANON_DATA[0] + ANON_DATA[1] + ANON_DATA[2] + ANON_DATA[3]
    return str(
                (
                    int(time.time()) // (7 * 24 * 60 * 60)
                ) ** anonTimeFactor
            )

def anonymize(mac):
    if mac != BROADCAST and mac != None:
        m = hashlib.sha512()
        m.update(mac.encode("utf-8"))              # Mac address goes first
        m.update(ANON_DATA)                        # Unique hashes per user/study
        m.update(weeklyStamp().encode("ascii"))    # Reset hash(s) each week
        return m.hexdigest()
    else:
        return "BROADCAST"
def anonymizedParticapants(packet):
    particapants = set()  # For all we know somebody could be talking to themselves

    if "wlan" in packet:  # Could sniff any format of packets
        if hasattr(packet.wlan, "ta"): # From addr?
            particapants.add(anonymize(packet.wlan.ta))
        if hasattr(packet.wlan, "da"): # Dest addr
            particapants.add(anonymize(packet.wlan.da))
        if hasattr(packet.wlan, "ra"): # Recepient addr?
            particapants.add(anonymize(packet.wlan.ra))

    return list(particapants)



TIMESTAMP_MARGIN = 15*60  # Not too big as not to destroy accuracy but big enough to ensure privacy
BLOCK_SIZE = 900          # This should be relativly big


class AnonymousDataWriter:
    def __init__(self, *args, **kwargs):
        self.file = gzip.open(*args, **kwargs)
        self.lastFlush = time.time()

        self.writeQueue = []
        self.random = random.SystemRandom() # cryptographically secure random number gen
    def writePacket(self, packet):
        return self.writeAnonymizedPacket(float(packet.sniff_timestamp), anonymizedParticapants(packet))
    def writeAnonymizedPacket(self, timestamp, particapants):
        
        # Margin of error added is -TIMESTAMP_MARGIN/2 to +TIMESTAMP_MARGIN/2
        # This protects the subjects privacy, and obfuscates who they are talking to.
        timestamp = int(timestamp + self.random.randrange(TIMESTAMP_MARGIN) - TIMESTAMP_MARGIN//2)
        i = 0
        for particapant in particapants:
            if particapant != "BROADCAST":
                self.writeQueue.append(f"{timestamp} - \"{particapant}\"\n")
                i+=1
        if len(self.writeQueue) > BLOCK_SIZE:
            self.flush()
        return i
    def close(self):
        self.flush(force=True)
        self.file.close()
    def flush(self, force=False):
        print("Flushed writeQueue")
        if time.time()-self.lastFlush < 20 and not force: # Log potential ddos if too many packets are recived (BLOCK_SIZE in 20 secs)
            f = open("warning.log", "a")
            f.write(f"At {time.ctime()} it was detected that a flush delta of {time.time()-self.lastFlush} happended. Suspecting data entegrity loss.")
            f.write("Here are the past 20 lines sent. A ddos or deauth is suspected (or just a of people):")
            f.writelines(self.writeQueue[:-20])
            f.close()

        # Further obfuscates who is talking to whom and the real timestamp
        self.random.shuffle(self.writeQueue)

        self.file.write("".join(self.writeQueue).encode("utf-8"))

        self.writeQueue.clear()

        self.lastFlush = time.time()

    def __enter__(self, *args, **kwargs):
        return self
    def __exit__(self, *args, **kwargs):
        self.close()

class OutputFileManager(AnonymousDataWriter):
    def openNew(self):
        if self.file != None:
            self.file.close()
        self.lastFlush       = time.time()
        self.lastOpenedFile = time.time()
        self.file             = gzip.open(os.path.join(self.dir, time.ctime() + ".txt.gz"), "w")
    def __init__(self, _dir):
        self.dir        = _dir
        self.file       = None
        self.writeQueue = []
        self.random     = random.SystemRandom() # cryptographically secure random number gen
        self.openNew()
    def flush(self, force=False):
        super().flush(force=force)
        if time.time()-self.lastOpenedFile  > 1*60*60: # Once every hour (to keep compression high and memory low)
            self.openNew()