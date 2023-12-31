import subprocess
import pyshark
from wifi import * 
import os, time
from progress.bar import Bar

from anonymizeing import OutputFileManager, BLOCK_SIZE

BROADCAST = "ff:ff:ff:ff:ff:ff"




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
    
    file = OutputFileManager("data")
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