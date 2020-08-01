import time
import uuid
import re
from pathlib import Path
from selenium import webdriver
import subprocess
import requests
from urllib3.exceptions import InsecureRequestWarning

from core import settings, helpers
from core.models import action
from plugins.inga.models import inga


class _ingaPortScan(action._action):
    ports = str()
    ip = str()
    scanName = str()
    timeout = int()
    stateChange = bool()

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

                process = subprocess.Popen(options, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    timeout = 30
                    if self.timeout > 0:
                        timeout = self.timeout
                    stdout, stderr = process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    actionResult["result"] = False
                    actionResult["rc"] = -999
                    return actionResult


                openPorts = re.finditer(r'^(\d*)\/(\S*)\s*(\S*)\s*([^\n]*)$',stdout.decode(),re.MULTILINE)
                change = False
                new = False
                updates = []
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
                            updates.append(scan.ports[portType][portNumber])
                            new = True
                        elif scan.ports[portType][portNumber]["state"] != portState or scan.ports[portType][portNumber]["service"] != portService:
                            if scan.ports[portType][portNumber]["state"] != portState:
                                scan.ports[portType][portNumber]["state"] = portState
                                change = True
                            if scan.ports[portType][portNumber]["service"] != portService:
                                scan.ports[portType][portNumber]["service"] = portService
                                change = True
                            updates.append(scan.ports[portType][portNumber])
                        elif not self.stateChange:
                            updates.append(scan.ports[portType][portNumber])

                poplist = []
                if len(foundPorts) > 0:
                    for port in scan.ports["tcp"]:
                        if port not in foundPorts:
                            poplist.append(port)
                    for port in poplist:
                        updates.append(scan.ports["tcp"][port])
                        del scan.ports["tcp"][port] 
                        change = True

                if new or change:
                    scan.update(["ports"])

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
    updateScan = dict()
    excludeHeaders = list()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        port = helpers.evalString(self.port,{"data" : data})

        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        protocols = ["http", "https"]
        for protocol in protocols:
            try:
                timeout = 5
                if self.timeout != 0:
                    timeout = self.timeout
                response = requests.head("{0}://{1}:{2}".format(protocol,ip,port),verify=False,allow_redirects=False,timeout=timeout)
                headers = helpers.lower_dict(response.headers)
                for excludeHeader in self.excludeHeaders:
                    if excludeHeader in headers:
                        del headers[excludeHeader]
                if protocol == "http":
                    if response.status_code == 301:
                        if "location" in headers:
                            if "https" in headers["location"]:
                                actionResult["data"]["protocol"] = "https"
                                actionResult["data"]["headers"] = headers
                                actionResult["result"] = False
                                actionResult["rc"] = 301
                                return actionResult
                # Update scan if updateScan mapping was provided
                updateScan = helpers.evalDict(self.updateScan,{ "data" : data })
                if len(updateScan) > 0:
                    updateResult = inga._inga().api_update(query={ "scanName": updateScan["scanName"], "ip": updateScan["ip"], "ports.{0}.{1}.webServerDetect.headers".format(updateScan["protocol"],updateScan["port"]) : { "$ne" : headers } },update={ "$set" : { "ports.{0}.{1}.webServerDetect".format(updateScan["protocol"],updateScan["port"]) : { "protocol" : protocol, "headers" : headers  } } })
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
           