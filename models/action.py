import time
import uuid
import re
from pathlib import Path
from selenium import webdriver
import subprocess

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

            options = ["nmap","--max-rtt-timeout","800ms","max-retries","0"]
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
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["data"] = { "filename" : filename }
        except:
            actionResult["result"] = False
            actionResult["rc"] = 100
        finally:
            wdriver.quit()
        return actionResult