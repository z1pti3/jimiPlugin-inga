import time
import uuid
import re
from pathlib import Path
from selenium import webdriver
import subprocess
import requests
from netaddr import *
from urllib3.exceptions import InsecureRequestWarning
from core import settings, helpers, audit, db
from core.models import action
from plugins.inga.models import inga

class _ingaIPDiscoverAction(action._action):
    scanName = str()
    scanQuantity = int()
    cidr = str()
    stateChange = bool()
    runRemote = bool()
    pingOnly = bool()
    lastScanAtLeast = int()

    def run(self,data,persistentData,actionResult):
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
                inga._inga().new(self.acl,self.scanName,str(ip),False)
        if self.lastScanAtLeast > 0:
            scanResults = inga._inga().getAsClass(query={ "scanName" : self.scanName, "lastScan" : { "$lt" : ( time.time() - self.lastScanAtLeast ) } },limit=scanQuantity,sort=[( "lastScan", 1 )])
        else:
            scanResults = inga._inga().getAsClass(query={ "scanName" : self.scanName },limit=scanQuantity,sort=[( "lastScan", 1 )])
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
                    discovered.append({ "ip" : scanResult.ip, "up" : True, "scanName" : self.scanName })
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
                        discovered.append({ "ip" : scanResult.ip, "up" : True, "scanName" : self.scanName })
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
                change = False
                new = False
                updates = { "new" : [], "removed" : [] }
                foundPorts = []
                for index, logicMatch in enumerate(openPorts):
                    portNumber = logicMatch.group(1).strip()
                    portType = logicMatch.group(2).strip()
                    portState = logicMatch.group(3).strip()
                    portService = logicMatch.group(4).strip()

                    if portNumber not in foundPorts:
                        foundPorts.append(portNumber)

                        if portType not in scan.ports:
                            scan.ports[portType] = {}
                        if portNumber not in scan.ports[portType]:
                            scan.ports[portType][portNumber] = { "port" : portNumber, "type" : portType, "state" : portState, "service" : portService }
                            updates["new"].append(scan.ports[portType][portNumber])
                            new = True
                        elif scan.ports[portType][portNumber]["state"] != portState or scan.ports[portType][portNumber]["service"] != portService:
                            if scan.ports[portType][portNumber]["state"] != portState:
                                scan.ports[portType][portNumber]["state"] = portState
                                change = True
                            if scan.ports[portType][portNumber]["service"] != portService:
                                scan.ports[portType][portNumber]["service"] = portService
                                change = True
                            updates["new"].append(scan.ports[portType][portNumber])
                        elif not self.stateChange:
                            updates["new"].append(scan.ports[portType][portNumber])

                poplist = []
                try:
                    for port in scan.ports["tcp"]:
                        if port not in foundPorts:
                            poplist.append(port)
                    for port in poplist:
                        updates["removed"].append(scan.ports["tcp"][port])
                        del scan.ports["tcp"][port] 
                        change = True
                except KeyError:
                    pass

                if "scanDetails" not in scan.ports:
                    scan.ports["scanDetails"] = { "lastPortScan" : 0 }
                scan.ports["scanDetails"]["lastPortScan"] = time.time()
                scan.update(["ports"])

                if new or change:
                    audit._audit().add("inga","history",{ "lastUpdate" : scan.lastUpdateTime, "endDate" : int(time.time()), "ip" : scan.ip, "up" : scan.up, "ports" : scan.ports })

                actionResult["result"] = True
                actionResult["data"]["portScan"] = updates
                if new:
                    actionResult["rc"] = 201
                elif change:
                    actionResult["rc"] = 302
                else:
                    if len(foundPorts) > 0:
                        actionResult["rc"] = 304
                    else:
                        actionResult["rc"] = 0
                return actionResult
        actionResult["result"] = False
        actionResult["rc"] = 1
        return actionResult

class _ingaWebScreenShot(action._action):
    url = str()
    timeout = int()
    updateScan = dict()

    def run(self,data,persistentData,actionResult):
        url = helpers.evalString(self.url,{"data" : data})

        profile = webdriver.FirefoxProfile()
        profile.accept_untrusted_certs = True
        fireFoxOptions = webdriver.FirefoxOptions()
        fireFoxOptions.set_headless()
        wdriver = webdriver.Firefox(firefox_options=fireFoxOptions,firefox_profile=profile,executable_path="/usr/bin/geckodriver",firefox_binary="/usr/bin/firefox")
        wdriver.set_window_size(1920, 1080)
        timeout = 5
        if self.timeout != 0:
            timeout = self.timeout
        wdriver.set_page_load_timeout(timeout)
        try:
            wdriver.get(url)
            filename  = "{0}.png".format(str(uuid.uuid4()))
            wdriver.save_screenshot(str(Path("plugins/inga/output/{0}".format(filename))))

            # Update scan if updateScan mapping was provided
            updateScan = helpers.evalDict(self.updateScan,{ "data" : data })
            if len(updateScan) > 0:
                inga._inga().api_update(query={ "scanName": updateScan["scanName"], "ip": updateScan["ip"] },update={ "$set" : { "ports.{0}.{1}.webScreenShot".format(updateScan["protocol"],updateScan["port"]) : { "filename" : filename } } })

            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["data"] = { "filename" : filename }
        except:
            actionResult["result"] = False
            actionResult["rc"] = 100
        finally:
            wdriver.quit()
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

        protocols = ["http", "https"]
        for protocol in protocols:
            try:
                timeout = 5
                if self.timeout != 0:
                    timeout = self.timeout
                    
                response = self.runRemoteFunction(persistentData,self.webserverConnect,{"protocol" : protocol, "ip" : ip, "port" : port, "timeout" : timeout})
                if "error" not in response:
                    headers = helpers.lower_dict(response["headers"])
                    for excludeHeader in self.excludeHeaders:
                        if excludeHeader in headers:
                            del headers[excludeHeader]
                    if protocol == "http":
                        if response["status_code"] == 301:
                            if "location" in headers:
                                if "https" in headers["location"]:
                                    actionResult["data"]["protocol"] = "https"
                                    actionResult["data"]["headers"] = headers
                                    actionResult["result"] = False
                                    actionResult["rc"] = 301
                                    return actionResult
                    # Update scan if updateScan mapping was provided
                    if len(scanName) > 0:
                        updateResult = inga._inga().api_update(query={ "scanName": scanName, "ip": ip, "ports.tcp.{1}.webServerDetect.headers".format(port) : { "$ne" : headers } },update={ "$set" : { "ports.tcp.{1}.webServerDetect".format(port) : { "protocol" : protocol, "headers" : headers  } } })
                        if updateResult["count"] > 0:
                            actionResult["data"]["protocol"] = protocol
                            actionResult["data"]["headers"] = headers
                            actionResult["result"] = True
                            actionResult["rc"] = 205
                            return actionResult

                    actionResult["data"]["protocol"] = protocol
                    actionResult["data"]["headers"] = headers
                    actionResult["result"] = True
                    actionResult["rc"] = 304
                    return actionResult
            except:
                pass

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
            actionResult["events"] = inga._inga().query(query=search,limit=self.limit)["results"]
        else:
            actionResult["events"] = inga._inga().query(query=search)["results"]
        return actionResult

    def setAttribute(self,attr,value,sessionData=None):
        if not sessionData or db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
            if attr == "customSearch":
                value = helpers.unicodeEscapeDict(value)
        return super(_ingaGetScanUpAction, self).setAttribute(attr,value,sessionData=sessionData)