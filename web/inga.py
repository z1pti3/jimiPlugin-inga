import urllib.parse
from pathlib import Path
from flask import request, send_from_directory
from markupsafe import Markup

from flask import Blueprint, render_template
from flask import current_app as app

from core import api, db, storage
from plugins.inga.models import inga

from os.path import dirname, abspath, join
from json import load

import random
# pluginPages = Blueprint('ingaPages', __name__, template_folder="templates")

pluginPages = Blueprint('ingaPages', __name__, template_folder="ingatemplates",static_folder="ingastatic",static_url_path="ingastatic")


def getPortMapping(jsonData,checkVal):
    for k,v in jsonData.items():
        if checkVal in v:
            return k
    return None

def genRandomColours(length):
    chartColoursList = []
    for _ in range(length):
        r = random.randint(0,255)
        g = random.randint(0,255)
        b = random.randint(0,255)
        color = f"rgba({r}, {g}, {b}, 0.6)"
        chartColoursList.append(color)
    return chartColoursList

@pluginPages.app_template_filter('urlencode')
def urlencode_filter(s):
    if type(s) == 'Markup':
        s = s.unescape()
    s = s.encode('utf8')
    s = urllib.parse.quote_plus(s)
    return Markup(s)

@pluginPages.route('/inga/includes/<file>')
def custom_static(file):
    return send_from_directory(str(Path("plugins/inga/web/includes")), file)

@pluginPages.route("/inga/")
def mainPage():

    # unsecurePorts,fileTransferPorts,rdp,webserverPorts,databasePorts,networkProtoPorts,otherPort = 0,0,0,0,0,0,0

    scans           = inga._inga()._dbCollection.distinct("scanName")
    results         = []
    sankeyChartData = [ ]
    portsPieChart   = { }

    jsonMappingFile = abspath(join(dirname( __file__ ), '..', 'web')) + "/includes/sankeyMapping.json" #dirname(abspath(__file__)) + "/sankeyMapping.json" #abspath(join(dirname( __file__ ), '..'))#, 'includes')) # 
    with open(jsonMappingFile) as json_file:
        jsonMap_data = load(json_file)


    for scan in scans:
        #reset keys for each scan
        sankeyDict  = { "unsecurePorts": 0, "fileTransferPorts": 0, "rdp": 0, "webserverPorts": 0, "databasePorts": 0, "networkProtoPorts": 0, "otherPort": 0  }

        
        scanData    = inga._inga().query(api.g.sessionData,query={ "scanName" : scan, "up" : True })["results"]
        totalCount  = inga._inga().count(api.g.sessionData,query={ "scanName" : scan })["results"][0]["count"]
        upCount     = inga._inga().count(api.g.sessionData,query={ "scanName" : scan, "up" : True })["results"][0]["count"]

        

        for upHost in scanData:
            if "cidr" in upHost and upHost["cidr"] != "":
                    # print(upHost)
                    tcpPorts = upHost["ports"]["tcp"]
                    udpPorts = upHost["ports"]["udp"]

                    try:
                        for portValue in tcpPorts:
                            if portValue["port"] not in portsPieChart:
                                portsPieChart[portValue["port"]] = 0
                            if portValue["state"] == "open":
                                portsPieChart[portValue["port"]]+=1
                    except KeyError:
                        pass  


                    #merge both lists together
                    combinedPorts = tcpPorts + udpPorts
                    for port in combinedPorts:
                        if port["state"] == "open":
                            portNum =  port["port"]
                            matched =   getPortMapping(jsonMap_data,str(portNum))
                            # print(matched)
                            if matched != None:
                                sankeyDict[matched] += 1
                            else:
                                sankeyDict["otherPort"] += 1

        for k,v in sankeyDict.items():
            if v > 0:
                scanName    = scanData[0]["scanName"]
                sankeyChartData.append([ scanName, k, v ])


        if totalCount > 0:
            results.append({ "scanName" : scan, "up" : upCount, "total" : totalCount })

    pieChartColours = genRandomColours(len(portsPieChart))

    # print(pieChartColours)
    # print(portsPieChart)
    # print(sankeyChartData)
    return render_template("ingaHomepage.html", scans=results,sankeyPortData=sankeyChartData,pieChart=portsPieChart,pieChartColours=pieChartColours)

@pluginPages.route("/inga/scan/")
def getScan():
    scanName            = urllib.parse.unquote_plus(request.args.get("scanName"))
    results             = inga._inga().query(api.g.sessionData,query={ "scanName" : scanName, "up" : True },fields=["scanName","ip","up","lastScan","ports"])["results"]
    barChartData        = { }
    scanData            = []
    networkChartPorts   = []
    # 
    # New
    for scan in results:
        c               = 0
        portValues      = [ ]

        try:
            tcpPorts        = scan["ports"]["tcp"]
            udpPorts        = scan["ports"]["udp"]
            combinedPorts   = tcpPorts + udpPorts      

            for portValue in combinedPorts:
                if portValue["state"] == "open":
                    c += 1
                    portValues.append( { "port":  portValue["port"], "service": portValue["service"], "state": portValue["state"] })
                    networkChartPorts.append([scan["ip"],str(portValue["port"])])
            if c > 0:
                try:
                    barChartData[scan["ip"]] = c
                except KeyError:
                    pass            
        except KeyError:
            pass
        
        scanData.append( { "scanName": scan["scanName"], "ip": scan["ip"], "up": scan["up"], "lastScan": scan["lastScan"], "portData": portValues } )

    barChartColours = genRandomColours(len(barChartData))

    test    = inga._inga().query(api.g.sessionData,query={ "scanName" : scanName, "up" : True },fields=["ports","ip","domains"])["results"]
    test2   = []
    ids     = []
    print(scanName)
    for scan in test:
        # print(scan)
        try:
            for portValue in scan["ports"]["tcp"]:
                try:
                    ids.append(db.ObjectId(portValue["data"]["webScreenShot"]["storageID"]))
                    test2.append({ "url" : "{0}://{1}:{2}".format(portValue["data"]["webServerDetect"]["protocol"],scan["ip"],portValue["port"]), "fileData" : portValue["data"]["webScreenShot"]["storageID"] })
                except KeyError:
                    pass
            for domainValue in scan["domains"]:
                for protocol in ["http","https"]:
                    try:
                        ids.append(db.ObjectId(domainValue["data"]["webScreenShot"][protocol]["storageID"]))
                        test2.append({ "url" : "{0}://{1}".format(protocol,domainValue["domain"]), "fileData" : domainValue["data"]["webScreenShot"][protocol]["storageID"] })
                    except KeyError:
                        pass
        except KeyError:
            pass
    print("IDS",ids)
    print(test2)
    results = storage._storage().query(api.g.sessionData,query={ "_id" : { "$in" : ids } })["results"]
    for item in test2:
        for storageResult in results:
            if item["fileData"] == str(storageResult["_id"]):
                item["fileData"] = storageResult["fileData"]


    return render_template("ingaScan.html", barChartData=barChartData,barChartColours=barChartColours,scanData=scanData, networkChartPorts=networkChartPorts)    
    # return render_template("scan.html", scanResults=results)

@pluginPages.route("/inga/scan/images/")
def getScanImages():
    scanName = urllib.parse.unquote_plus(request.args.get("scanName"))
    results = inga._inga().query(api.g.sessionData,query={ "scanName" : scanName, "up" : True },fields=["ports","ip","domains"])["results"]
    result = []
    ids = []
    for scan in results:
        try:
            for portValue in scan["ports"]["tcp"]:
                try:
                    ids.append(db.ObjectId(portValue["data"]["webScreenShot"]["storageID"]))
                    result.append({ "url" : "{0}://{1}:{2}".format(portValue["data"]["webServerDetect"]["protocol"],scan["ip"],portValue["port"]), "fileData" : portValue["data"]["webScreenShot"]["storageID"] })
                except KeyError:
                    pass
            for domainValue in scan["domains"]:
                for protocol in ["http","https"]:
                    try:
                        ids.append(db.ObjectId(domainValue["data"]["webScreenShot"][protocol]["storageID"]))
                        result.append({ "url" : "{0}://{1}".format(protocol,domainValue["domain"]), "fileData" : domainValue["data"]["webScreenShot"][protocol]["storageID"] })
                    except KeyError:
                        pass
        except KeyError:
            pass
    results = storage._storage().query(api.g.sessionData,query={ "_id" : { "$in" : ids } })["results"]
    for item in result:
        for storageResult in results:
            if item["fileData"] == str(storageResult["_id"]):
                item["fileData"] = storageResult["fileData"]
    return render_template("scanImages.html", result=result)
