import time

import subprocess
from netaddr import *

from core.models import trigger

from plugins.inga.models import inga

class _ingaIPDiscover(trigger._trigger):
    scanName = str()
    scanQuantity = int()
    cidr = str()

    def check(self):
        ips = IPNetwork(self.cidr)
        if self.scanQuantity == 0:
            scanQuantity = len(ips)
        else:
            scanQuantity = self.scanQuantity

        scanResults = inga._inga().query(query={ "scanName" : self.scanName })["results"]
        for ip in ips:
            ipFound = False
            for scanResult in scanResults:
                if str(ip) == scanResult["ip"]:
                    ipFound = True
            if not ipFound:
                inga._inga().new(self.scanName,str(ip),False)

        scanResults = inga._inga().getAsClass(query={ "scanName" : self.scanName },limit=scanQuantity,sort=[( "lastScan", 1 )])
        discovered = []
        for scanResult in scanResults:
            process = subprocess.Popen(["nmap","-sn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            change = False
            if "Host is up (" in stdout.decode():
                if scanResult.up != True:
                    scanResult.updateRecord(scanResult.ip,True)
                    discovered.append({ "ip" : scanResult.ip, "up" : True })
                    change = True
            else:
                process = subprocess.Popen(["nmap","--top-ports","100","-Pn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                if "Host is up (" in stdout.decode():
                    if scanResult.up != True:
                        scanResult.updateRecord(scanResult.ip,True)
                        discovered.append({ "ip" : scanResult.ip, "up" : True })
                        change = True
                else:
                    process = subprocess.Popen(["nmap","-sU","--top-ports","10","-Pn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    if "Host is up (" in stdout.decode():
                        if scanResult.up != True:
                            scanResult.updateRecord(scanResult.ip,True)
                            discovered.append({ "ip" : scanResult.ip, "up" : True })
                            change = True
                    else:
                        if scanResult.up != False:
                            scanResult.updateRecord(scanResult.ip,False)
                            discovered.append({ "ip" : scanResult.ip, "up" : False })
                            change = True
            if not change:
                scanResult.lastScan = int(time.time())
                scanResult.update(["lastScan"])
            

        self.result["events"] = discovered