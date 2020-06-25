import time
import uuid
from pathlib import Path
from selenium import webdriver
import subprocess

from core import settings, helpers
from core.models import action


class _ingaPortScan(action._action):
    ports = str()
    ip = str()

    def run(self,data,persistentData,actionResult):
        ip = helpers.evalString(self.ip,{"data" : data})
        if ip:
            ports = helpers.evalString(self.ports,{"data" : data})

            options = ["nmap","--max-rtt-timeout","800ms","max-retries","0"]
            if ports.startswith("--"):
                options.append(ports.split(" ")[0])
                options.append(ports.split(" ")[1])
            else:
                options.append("-P")
                options.append(ports)
            options.append(ip)

            process = subprocess.Popen(options, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            print(stdout.decode())
            actionResult["result"] = True
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
        wdriver = webdriver.PhantomJS(service_args=['--ignore-ssl-errors=true', '--ssl-protocol=any'])
        wdriver.set_window_size(1920, 1080)
        wdriver.get(url)
        filename  = "{0}.png".format(str(uuid.uuid4()))
        timeout = 5
        if self.timeout != 0:
            timeout = self.timeout
        time.sleep(timeout)
        wdriver.save_screenshot(Path("output/{0}".format(filename)))
        wdriver.quit
        actionResult["result"] = True
        actionResult["rc"] = 0
        actionResult["data"] = { "filename" : filename }
        return actionResult