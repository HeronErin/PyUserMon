import subprocess
import pyshark
from wifi import * 
import hashlib
import os, time
import random
from progress.bar import Bar

BROADCAST = "ff:ff:ff:ff:ff:ff"

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
        self.file = open(*args, **kwargs)
        self.last_flush = time.time()

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
        if time.time()-self.last_flush < 20 and not force: # Log potential ddos if too many packets are recived (BLOCK_SIZE in 20 secs)
            f = open("warning.log", "a")
            f.write(f"At {time.ctime()} it was detected that a flush delta of {time.time()-self.last_flush} happended. Suspecting data entegrity loss.")
            f.write("Here are the past 20 lines sent. A ddos or deauth is suspected (or just a of people):")
            f.writelines(self.writeQueue[:-20])
            f.close()

        # Further obfuscates who is talking to whom and the real timestamp
        self.random.shuffle(self.writeQueue)

        self.file.writelines(self.writeQueue)

        self.writeQueue.clear()

        self.last_flush = time.time()

    def __enter__(self, *args, **kwargs):
        return self
    def __exit__(self, *args, **kwargs):
        self.close()


def rootTest():
    proc = subprocess.run(["whoami"], stdout=subprocess.PIPE)
    username = proc.stdout.decode("utf-8").strip()
    if username != "root":
        print("Warning: Not running as root! Tshark often requires you to run as root to capture packets, so no data is likely to be collected! If you are unsure about giving this python script root, feel free to review the source.")
        return False
    return True

class PacketGen:
    def __init__(self, interface):
        self.interface = interface
        self.capture = None
    def __enter__(self, *args, **kwargs):
        rootTest()
        startMonitorMode(self.interface)
        assert self.interface+"mon" in getInterfaces()

        self.capture = pyshark.LiveCapture(interface=self.interface+"mon")
        self.packetItr = iter(self.capture.sniff_continuously())
        return self
    def __exit__(self, *args, **kwargs):
        self.capture.close()
        stopMonitorMode(self.interface)
    def getPacket(self):
        assert self.capture is not None
        return next(self.packetItr)



def main():
    INTERFACE = "wlp0s20f3"
    
    file = AnonymousDataWriter("data/"+time.ctime(), "w")
    barCount = 0
    bar = Bar('Time until next flush', max=BLOCK_SIZE)
    with file:
        with PacketGen(INTERFACE) as p:
            while True:
                for _ in range(file.writePacket(p.getPacket())):
                    bar.next()
                    barCount+=1
                barCount %= BLOCK_SIZE

                if barCount == 0:
                    bar.finish()
                    bar = Bar('Time until next flush', max=BLOCK_SIZE)





if __name__ == "__main__":
    main()