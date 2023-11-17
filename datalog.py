import subprocess
import pyshark
from wifi import * 
import hashlib

BROADCAST = "ff:ff:ff:ff:ff:ff"

def rootTest():
    proc = subprocess.run(["whoami"], stdout=subprocess.PIPE)
    username = proc.stdout.decode("utf-8").strip()
    if username != "root":
        print("Warning: Not running as root! Tshark often requires you to run as root to capture packets, so no data is likely to be collected! If you are unsure about giving this python script root, feel free to review the source.")
        return False
    return True

def anonymize(mac):
    if mac != BROADCAST and mac is not None:
        return hashlib.sha256(mac.encode("utf-8")).hexdigest()
    else:
        return "BROADCAST"
def anonymizedParticapants(packet):
    


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
        stopMonitorMode(self.interface)
    def getPacket(self):
        assert self.capture is not None
        return next(self.packetItr)



def main():
    INTERFACE = "wlp0s20f3"
    
    with PacketGen(INTERFACE) as p:
        print(p.getPacket().wlan.da)



if __name__ == "__main__":
    main()