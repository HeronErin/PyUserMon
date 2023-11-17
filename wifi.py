import subprocess, os

def getInterfaces():
    ip = subprocess.run(["ifconfig", "-s"], stdout=subprocess.PIPE)
    lines = ip.stdout.decode("utf-8").split("\n")[1:]
    return [line.split(" ")[0] for line in lines if line]

def startMonitorMode(interface):
    if not interface+"mon" in getInterfaces():
        proc=subprocess.run(["sudo", "airmon-ng", "start", interface], stdout =subprocess.DEVNULL)
        assert proc.returncode == 0
def stopMonitorMode(interface):
    proc=subprocess.run(["sudo", "airmon-ng", "stop", interface+"mon"], stdout =subprocess.DEVNULL)
    assert proc.returncode == 0



# wlan.ta
# wlan.da

