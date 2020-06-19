import time
import uuid
from pathlib import Path
from selenium import webdriver

from core import settings, helpers
from core.models import action

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