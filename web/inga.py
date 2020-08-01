from flask import Blueprint, render_template
from flask import current_app as app

from core import api
from plugins.inga.models import inga

pluginPages = Blueprint('ingaPages', __name__, template_folder="templates")

@pluginPages.route("/inga/")
def mainPage():
    scans = inga._inga()._dbCollection.distinct("scanName")
    results = []
    for scan in scans:
        totalCount = inga._inga().count(api.g.sessionData,query={ "scanName" : scan })["results"][0]["count"]
        upCount = inga._inga().count(api.g.sessionData,query={ "scanName" : scan, "up" : True })["results"][0]["count"]
        if totalCount > 0:
            results.append({ "scanName" : scan, "up" : upCount, "total" : totalCount })
    return render_template("scans.html", scans=results)

@pluginPages.route("/inga/<scanName>/")
def getScan(scanName):
    results = inga._inga().query(api.g.sessionData,query={ "scanName" : scanName, "up" : True })["results"]
    return render_template("scan.html", scanResults=results)
