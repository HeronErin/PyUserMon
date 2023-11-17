import subprocess
import pyshark
from wifi import * 
import hashlib
import os, time
import random

BROADCAST = "ff:ff:ff:ff:ff:ff"

if not os.path.exists("anon.dat"):
    print("Error: must create anon.dat for anonymizing data! Please run keygen.sh")
    exit(-1)
ANON_DATA = open("anon.dat", "rb").read()

# This function will change all user hashes every week
def weeklyStamp():
    anonTimeFactor = ANON_DATA[0] + ANON_DATA[1] + ANON_DATA[2] + ANON_DATA[3]
    return str((int(time.time()) // (7 * 24 * 60 * 60)) ** anonTimeFactor)
def anonymize(mac):
    if mac != BROADCAST and mac != None:
        m = hashlib.sha512()
        m.update(mac.encode("utf-8"))
        m.update(ANON_DATA)
        m.update(weeklyStamp().encode("ascii"))
        return m.hexdigest()
    else:
        return "BROADCAST"
def anonymizedParticapants(packet):
    particapants = set()
    if "wlan" in packet:
        if hasattr(packet.wlan, "ta"):
            particapants.add(anonymize(packet.wlan.ta))
        if hasattr(packet.wlan, "da"):
            particapants.add(anonymize(packet.wlan.da))
        if hasattr(packet.wlan, "ra"):
            particapants.add(anonymize(packet.wlan.ra))

    return list(particapants)



TIMESTAMP_MARGIN = 20*60

class AnonymousDataWriter:
    def __init__(self, *args, **kwargs):
        self.file = open(*args, **kwargs)
        self.writeQueue = []
        self.random = random.SystemRandom() # cryptographically secure random number gen
    def writePacket(self, packet):
        self.writeAnonymizedPacket(float(packet.sniff_timestamp), anonymizedParticapants(packet))
    def writeAnonymizedPacket(self, timestamp, particapants):
        
        # Margin of error added is -TIMESTAMP_MARGIN/2 to +TIMESTAMP_MARGIN/2
        # This protects the subjects privacy, and obfuscates who they are talking to.
        timestamp = int(timestamp + self.random.randrange(TIMESTAMP_MARGIN) - TIMESTAMP_MARGIN//2)

        for particapant in particapants:
            if particapant != "BROADCAST":
                self.writeQueue.append(f"{timestamp} - \"{particapant}\"\n")
        if len(self.writeQueue) > 500:
            self.flush()
    def close(self):
        self.flush()
        self.file.close()
    def flush(self):
        print("Flushed writeQueue")

        # Further obfuscates who is talking to who and the real timestamp
        self.random.shuffle(self.writeQueue)

        self.file.writelines(self.writeQueue)

        self.writeQueue.clear()

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
    try:
        with PacketGen(INTERFACE) as p:
            while True:
                file.writePacket(p.getPacket())
                print("Written packet")
    finally:
        file.close()



if __name__ == "__main__":
    main()