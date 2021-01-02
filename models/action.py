import time
import uuid
import re
from pathlib import Path
import subprocess
import requests
import base64
from netaddr import *
from urllib3.exceptions import InsecureRequestWarning
from core import settings, helpers, audit, db, storage
from core.models import action

from plugins.inga.models import inga
from plugins.remote.includes import helpers as remoteHelpers


class _ingaIPDiscoverAction(action._action):
    scanName = str()
    scanQuantity = int()
    cidr = str()
    stateChange = bool()
    runRemote = bool()
    pingOnly = bool()
    lastScanAtLeast = int()

    def run(self,data,persistentData,actionResult):
        cidr = helpers.evalString(self.cidr,{"data" : data})
        scanName = helpers.evalString(self.scanName,{"data" : data})
        ips = IPNetwork(cidr)
        if self.scanQuantity == 0:
            scanQuantity = len(ips)
        else:
            scanQuantity = self.scanQuantity

        scanResults = inga._inga().query(query={ "scanName" : scanName },fields=["scanName","ip","up","lastScan"])["results"]
        for ip in ips:
            ipFound = False
            for scanResult in scanResults:
                if str(ip) == scanResult["ip"]:
                    ipFound = True
            if not ipFound:
                inga._inga().new(self.acl,scanName,str(ip),False)
        if self.lastScanAtLeast > 0:
            scanResults = inga._inga().getAsClass(query={ "scanName" : scanName, "lastScan" : { "$lt" : ( time.time() - self.lastScanAtLeast ) } },limit=scanQuantity,sort=[( "lastScan", 1 )],fields=["scanName","ip","up","lastScan"])
        else:
            scanResults = inga._inga().getAsClass(query={ "scanName" : scanName },limit=scanQuantity,sort=[( "lastScan", 1 )],fields=["scanName","ip","up","lastScan"])
        discovered = []
        for scanResult in scanResults:
            # Support for running on a remote host
            if self.runRemote and "remote" in persistentData:
                if "client" in persistentData["remote"]:
                    client = persistentData["remote"]["client"]
                    exitCode, stdout, stderr = client.command(" ".join(["nmap","-sn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip]),elevate=True)
                    stdout = "\n".join(stdout)
                    stderr = "\n".join(stderr)
                    if not stdout:
                        actionResult["result"] = False
                        actionResult["rc"] = 500
                        actionResult["msg"] = stderr
                        return actionResult
            else:
                process = subprocess.Popen(["nmap","-sn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                stdout = stdout.decode()
                stderr = stderr.decode()
            change = False
            if "Host is up (" in stdout:
                if scanResult.up != True:
                    scanResult.updateRecord(scanResult.ip,True)
                    change = True
                if not self.stateChange or change:
                    discovered.append({ "ip" : scanResult.ip, "up" : True, "scanName" : scanName })
            elif self.pingOnly == False:
                if self.runRemote and "remote" in persistentData:
                    if "client" in persistentData["remote"]:
                        client = persistentData["remote"]["client"]
                        exitCode, stdout, stderr = client.command(" ".join(["nmap","--top-ports","100","-Pn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip]),elevate=True)
                        stdout = "\n".join(stdout)
                        stderr = "\n".join(stderr)
                        if not stdout:
                            actionResult["result"] = False
                            actionResult["rc"] = 500
                            actionResult["msg"] = stderr
                            return actionResult
                else:
                    process = subprocess.Popen(["nmap","--top-ports","100","-Pn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    stdout = stdout.decode()
                    stderr = stderr.decode()
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
                        discovered.append({ "ip" : scanResult.ip, "up" : True, "scanName" : scanName })
                else:
                    if self.runRemote and "remote" in persistentData:
                        if "client" in persistentData["remote"]:
                            client = persistentData["remote"]["client"]
                            exitCode, stdout, stderr = client.command(" ".join(["nmap","-sU","--top-ports","10","-Pn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip]),elevate=True)
                            stdout = "\n".join(stdout)
                            stderr = "\n".join(stderr)
                            if not stdout:
                                actionResult["result"] = False
                                actionResult["rc"] = 500
                                actionResult["msg"] = stderr
                                return actionResult
                    else:
                        process = subprocess.Popen(["nmap","-sU","--top-ports","10","-Pn","--max-rtt-timeout","800ms","--max-retries","0",scanResult.ip], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        stdout, stderr = process.communicate()
                        stdout = stdout.decode()
                        stderr = stderr.decode()

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
                            discovered.append({ "ip" : scanResult.ip, "up" : True, "scanName" : scanName })
                    else:
                        if scanResult.up != False:
                            scanResult.updateRecord(scanResult.ip,False)
                            change = True
                        if not self.stateChange or change:
                            discovered.append({ "ip" : scanResult.ip, "up" : False, "scanName" : scanName })
            if not change:
                scanResult.lastScan = int(time.time())
                scanResult.update(["lastScan"])
            
        if len(discovered) > 0:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["discovered"] = discovered
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
        return actionResult


class _ingaPortScan(action._action):
    ports = str()
    ip = str()
    scanName = str()
    timeout = int()
    stateChange = bool()
    runRemote = bool()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        if ip:
            ports = helpers.evalString(self.ports,{"data" : data})
            scanName = helpers.evalString(self.scanName,{"data" : data})

            options = ["nmap"]
            if ports.startswith("--"):
                options.append(ports.split(" ")[0])
                options.append(ports.split(" ")[1])
            else:
                options.append("-p")
                options.append(ports)
            options.append(ip)

            scan = inga._inga().getAsClass(query={ "scanName": scanName, "ip": ip })
            if len(scan) > 0:
                scan = scan[0]
            else:
                scanID = inga._inga().new(self.acl,scanName,ip,True).inserted_id
                scan = inga._inga().getAsClass(id=scanID)[0]

            if scan:
                timeout = 30
                if self.timeout > 0:
                    timeout = self.timeout

                # Support for running on a remote host
                if self.runRemote and "remote" in persistentData:
                    if "client" in persistentData["remote"]:
                        client = persistentData["remote"]["client"]
                        exitCode, stdout, stderr = client.command(" ".join(options),elevate=True)
                        stdout = "\n".join(stdout)
                        stderr = "\n".join(stderr)
                        if not stdout:
                            actionResult["result"] = False
                            actionResult["rc"] = 500
                            actionResult["msg"] = stderr
                            return actionResult
                else:
                    process = subprocess.Popen(options, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    try:
                        stdout, stderr = process.communicate(timeout=timeout)
                        stdout = stdout.decode()
                        stderr = stderr.decode()
                    except subprocess.TimeoutExpired:
                        actionResult["result"] = False
                        actionResult["rc"] = -999
                        return actionResult


                openPorts = re.finditer(r'^(\d*)\/(\S*)\s*(\S*)\s*([^\n]*)$',stdout,re.MULTILINE)
                updates = { "new" : [], "update" : [], "removed" : [] }
                foundPorts = []
                #udp = [ x["port"] for x in scan.ports["udp"] ]
                for index, logicMatch in enumerate(openPorts):
                    portNumber = int(logicMatch.group(1).strip())
                    portType = logicMatch.group(2).strip()
                    portState = logicMatch.group(3).strip()
                    portService = logicMatch.group(4).strip()

                    currentPort = [ x for x in scan.ports["tcp"] if x["port"] == portNumber ]
                    if currentPort:
                        currentPort = currentPort[0]
                        portDict = { "port" : portNumber, "type" : portType, "state" : portState, "service" : portService, "data" : currentPort["data"] }
                    else:
                        portDict = { "port" : portNumber, "type" : portType, "state" : portState, "service" : portService, "data" : { } }

                    if portNumber not in foundPorts:
                        foundPorts.append(portNumber)

                        if not currentPort:
                            updates["new"].append(portDict)
                        else:
                            if currentPort != portDict:
                                updates["update"].append(portDict)
                            elif not self.stateChange:
                                updates["update"].append(portDict)
                            
                poplist = []
                try:
                    for port in  [ x["port"] for x in scan.ports["tcp"] ]:
                        if port not in foundPorts:
                            poplist.append(port)
                    for port in poplist:
                        currentPort = [ x for x in scan.ports["tcp"] if x["port"] == port ]
                        if currentPort:
                            currentPort = currentPort[0]
                            updates["removed"].append(currentPort)
                except KeyError:
                    pass

                scan.ports["scanDetails"]["lastPortScan"] = time.time()
                scan.update(["ports"])

                if len(updates["new"]) > 0 or len(updates["update"]) > 0:
                    audit._audit().add("inga","history",{ "lastUpdate" : scan.lastUpdateTime, "endDate" : int(time.time()), "ip" : scan.ip, "up" : scan.up, "ports" : scan.ports })

                actionResult["result"] = True
                actionResult["rc"] = 0
                actionResult["data"]["portScan"] = updates

                bulkOps = scan._dbCollection.initialize_ordered_bulk_op()
                if len(updates["update"]) > 0:
                    actionResult["rc"] = 302
                    for port in updates["update"]:   
                        bulkOps.find({ "scanName" : scanName, "ip" : ip, "ports.tcp.port" : port["port"] }).update_one({ "$set" : { "ports.tcp.$.state" : port["state"], "ports.tcp.$.service" : port["service"] } })           

                if len(updates["new"]) > 0:
                    actionResult["rc"] = 201
                    for port in updates["new"]:
                        bulkOps.find({ "scanName" : scanName, "ip" : ip }).update_one({ "$push" : { "ports.tcp" : port } })   

                for port in updates["removed"]:
                    bulkOps.find({ "scanName" : scanName, "ip" : ip, "ports.tcp.port" : port["port"] }).update_one({ "$pull" : { "ports.tcp" : { "port" : port["port"] } } })   
                
                if len(updates["new"]) > 0 or len(updates["update"]) > 0 or len(updates["removed"]) > 0:
                    bulkOps.execute()

                if actionResult["rc"] == 0 and len(foundPorts) > 0: 
                    actionResult["rc"] = 304

                return actionResult
        actionResult["result"] = False
        actionResult["rc"] = 1
        return actionResult

class _ingaWebScreenShot(action._action):
    ip = str()
    port = str()
    url = str()
    timeout = int()
    updateScan = dict()
    outputDir = "/tmp"
    scanName = str()
    runRemote = bool()

    def takeScreenshot(self,functionInputDict):
        from selenium import webdriver
        import uuid
        import os
        from pathlib import Path
        import base64

        url = functionInputDict["url"]
        timeout = functionInputDict["timeout"]
        outputDir = functionInputDict["outputDir"]

        profile = webdriver.FirefoxProfile()
        profile.accept_untrusted_certs = True
        fireFoxOptions = webdriver.FirefoxOptions()
        fireFoxOptions.set_headless()
        wdriver = webdriver.Firefox(firefox_options=fireFoxOptions,firefox_profile=profile,executable_path="/usr/bin/geckodriver",firefox_binary="/usr/bin/firefox")
        wdriver.set_window_size(1920, 1080)
        wdriver.set_page_load_timeout(timeout)
        try:
            wdriver.get(url)
            
            filename  = "{0}.png".format(str(uuid.uuid4()))
            wdriver.save_screenshot(str(Path("{0}/{1}".format(outputDir,filename))))
            with open(str(Path("{0}/{1}".format(outputDir,filename))), mode='rb') as file: 
                fileData = file.read()
            os.remove(str(Path("{0}/{1}".format(outputDir,filename))))
        finally:
            wdriver.quit()
        return { "fileData" : base64.b64encode(fileData).decode() }

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        port = helpers.evalString(self.port,{"data" : data})
        scanName = helpers.evalString(self.scanName,{"data" : data})
        url = helpers.evalString(self.url,{"data" : data})
        outputDir = helpers.evalString(self.outputDir,{"data" : data})
        timeout = 5
        if self.timeout != 0:
            timeout = self.timeout

        response = remoteHelpers.runRemoteFunction(self.runRemote,persistentData,self.takeScreenshot,{"url" : url, "timeout" : timeout, "outputDir" : outputDir})
        if "error" not in response:
            newStorageItem = storage._storage().new(self.acl,response["fileData"])
            inga._inga()._dbCollection.update_one({ "scanName": scanName, "ip": ip, "ports.tcp.port" : port },{ "$set" : { "ports.tcp.$.data.webScreenShot" : { "storageID" : str(newStorageItem.inserted_id) } } })
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["storageID"] = str(newStorageItem.inserted_id)
        else:
            actionResult["result"] = False
            actionResult["rc"] = 500
            actionResult["msg"] = response["error"]
            actionResult["stderr"] = response["stderr"]
            actionResult["stdout"] = response["stdout"]
        return actionResult

class _ingaWebServerDetect(action._action):
    ip = str()
    port = str()
    timeout = int()
    excludeHeaders = list()
    scanName = str()
    runRemote = bool()

    # BETA testing of remote action helper
    def webserverConnect(self,functionInputDict):
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        protocol = functionInputDict["protocol"]
        ip = functionInputDict["ip"]
        port = functionInputDict["port"]
        timeout = functionInputDict["timeout"]
        response = requests.head("{0}://{1}:{2}".format(protocol,ip,port),verify=False,allow_redirects=False,timeout=timeout)
        return { "headers" : response.headers, "status_code" : response.status_code }

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        port = helpers.evalString(self.port,{"data" : data})
        scanName = helpers.evalString(self.scanName,{"data" : data})

        result = []
        protocols = ["http", "https"]
        for protocol in protocols:
            timeout = 5
            if self.timeout != 0:
                timeout = self.timeout
                
            response = remoteHelpers.runRemoteFunction(self.runRemote,persistentData,self.webserverConnect,{"protocol" : protocol, "ip" : ip, "port" : port, "timeout" : timeout})
            if "error" not in response:
                headers = helpers.lower_dict(response["headers"])
                for excludeHeader in self.excludeHeaders:
                    if excludeHeader in headers:
                        del headers[excludeHeader]
                # Update scan if updateScan mapping was provided
                if len(scanName) > 0:
                    inga._inga()._dbCollection.update_one({ "scanName": scanName, "ip": ip, "ports.tcp.port" : port },{ "$set" : { "ports.tcp.$.data.webServerDetect" : { "protocol" : protocol, "headers" : headers  } } })
                result.append({ "protocol" : protocol, "headers" : headers })

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["serverDetails"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
        return actionResult           


class _ingaGetScanUpAction(action._action):    
    scanName = str()
    customSearch = dict()
    limit = 0

    def run(self,data,persistentData,actionResult):
        scanName = helpers.evalString(self.scanName,{"data" : data})
        customSearch = helpers.evalDict(self.customSearch,{"data" : data})
        search = { "scanName" : scanName, "up" : True }
        if customSearch:
            for key,value in customSearch.items():
                search[key] = value
        actionResult["result"] = True
        actionResult["rc"] = 0
        if self.limit > 0:
            actionResult["events"] = inga._inga().query(query=search,limit=self.limit,sort=[( "ports.scanDetails.lastPortScan", 1 )])["results"]
        else:
            actionResult["events"] = inga._inga().query(query=search,sort=[( "ports.scanDetails.lastPortScan", 1 )])["results"]
        return actionResult

    def setAttribute(self,attr,value,sessionData=None):
        if not sessionData or db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
            if attr == "customSearch":
                value = helpers.unicodeEscapeDict(value)
        return super(_ingaGetScanUpAction, self).setAttribute(attr,value,sessionData=sessionData)