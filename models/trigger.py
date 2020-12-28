import time
import re

import subprocess
from netaddr import *

from core.models import trigger
from core import db

from plugins.inga.models import inga

class _ingaIPDiscover(trigger._trigger):
    scanName = str()
    scanQuantity = int()
    cidr = str()
    stateChange = bool()

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
                    change = True
                if not self.stateChange or change:
                    discovered.append({ "ip" : scanResult.ip, "up" : True, "scanName" : self.scanName })
            else:
                process = subprocess.Popen(["nmap","--top-ports","100","-Pn","--max-rtt-timeout","800ms","--max-retries","0","--open",scanResult.ip], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                openPorts = re.finditer(r'^(\d*)\/(\S*)\s+(open)\s+([^\n]*)$',stdout,re.MULTILINE)
                up = False
                for index, logicMatch in enumerate(openPorts):
                    up = True
                    break
                if up:
                    if scanResult.up != True:
                        scanResult.updateRecord(scanResult.ip,True)
                        change = True
                    if not self.stateChange or change:
                        discovered.append({ "ip" : scanResult.ip, "up" : True, "scanName" : self.scanName })
                else:
                    process = subprocess.Popen(["nmap","-sU","--top-ports","10","-Pn","--max-rtt-timeout","800ms","--max-retries","0","--open",scanResult.ip], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    openPorts = re.finditer(r'^(\d*)\/(\S*)\s+(open)\s+([^\n]*)$',stdout,re.MULTILINE)
                    up = False
                    for index, logicMatch in enumerate(openPorts):
                        up = True
                        break
                    if up:
                        if scanResult.up != True:
                            scanResult.updateRecord(scanResult.ip,True)
                            change = True
                        if not self.stateChange or change:
                            discovered.append({ "ip" : scanResult.ip, "up" : True, "scanName" : self.scanName })
                    else:
                        if scanResult.up != False:
                            scanResult.updateRecord(scanResult.ip,False)
                            change = True
                        if not self.stateChange or change:
                            discovered.append({ "ip" : scanResult.ip, "up" : False, "scanName" : self.scanName })
            if not change:
                scanResult.lastScan = int(time.time())
                scanResult.update(["lastScan"])
            
        self.result["events"] = discovered

class _ingaGetScanUp(trigger._trigger):    
    scanName = str()
    customSearch = dict()
    limit = 0

    def check(self):
        search = { "scanName" : self.scanName, "up" : True }
        if self.customSearch:
            for key,value in self.customSearch.items():
                search[key] = value

        if self.limit > 0:
            self.result["events"] = inga._inga().query(query=search,limit=self.limit)["results"]
        else:
            self.result["events"] = inga._inga().query(query=search)["results"]

    def setAttribute(self,attr,value,sessionData=None):
        if not sessionData or db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
            if attr == "customSearch":
                value = helpers.unicodeEscapeDict(value)
        return super(_ingaGetScanUp, self).setAttribute(attr,value,sessionData=sessionData)