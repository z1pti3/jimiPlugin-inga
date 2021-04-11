import urllib.parse
from pathlib import Path
from flask import request, send_from_directory
from markupsafe import Markup

from flask import Blueprint, render_template
from flask import current_app as app

from core import api, db, storage
from plugins.inga.models import inga

from os.path import dirname, abspath, join
import time
import json

import jimi
from web import ui

import random
pluginPages = Blueprint('ingaPages', __name__, template_folder="templates")

# pluginPages = Blueprint('ingaPages', __name__, template_folder="ingatemplates",static_folder="ingastatic",static_url_path="ingastatic")


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

@pluginPages.route('/includes/<file>')
def custom_static(file):
    return send_from_directory(str(Path("plugins/inga/web/includes")), file)

@pluginPages.route("/")
def mainPage():
    return render_template("inga.html",CSRF=jimi.api.g.sessionData["CSRF"])

@pluginPages.route("/barScansResults/",methods=["POST"])
def barScansResults():
    bar = ui.bar()
    with open(Path("plugins/inga/web/includes/sankeyMapping.json")) as json_file:
        serviceMap = json.load(json_file)
    bar.addLabel("Other")
    for service in serviceMap.keys():
        bar.addLabel(service)
    scansResults = inga._inga().getAsClass(api.g.sessionData,query={ "up" : True },fields=["scanName","ip","up","lastScan","ports"])
    data = {}
    for scansResult in scansResults:
        if scansResult.scanName not in data:
            data[scansResult.scanName] = { "Other" : 0 }
            for service in serviceMap.keys():
                data[scansResult.scanName][service] = 0
        for port in scansResult.ports["tcp"]:
            matched = getPortMapping(serviceMap,str(port["port"]))
            if matched != None:
                data[scansResult.scanName][matched] += 1
            else:
                data[scansResult.scanName]["Other"] += 1
    for scan in data:
        dataList = []
        for k,v in data[scan].items():
            dataList.append(v)
        bar.addDataset(scan,dataList)

    data = json.loads(jimi.api.request.data)
    return bar.generate(data), 200

@pluginPages.route("/tableScans/<action>/",methods=["GET"])
def tableScans(action):
    scans = inga._inga().groupby(sessionData=api.g.sessionData,field="scanName")
    total = len(scans)
    columns = [ "Scan Name", "Total Hosts" ]
    table = ui.table(columns,total,total)
    if action == "build":
        return table.getColumns() ,200
    elif action == "poll":
        # Custom table data so it can be vertical
        data = []
        for source in scans:
            data.append(["<a href=\"{0}{1}/\">{2}</a>".format("scan/",source["_id"],ui.safe(source["_id"])),ui.safe(source["_count"])])
        table.data = data
        return { "draw" : int(jimi.api.request.args.get('draw')), "recordsTable" : total, "recordsFiltered" : total, "recordsTotal" : total, "data" : data } ,200

@pluginPages.route("/tableScansDomains/<action>/",methods=["GET"])
def tableScansDomains(action):
    scans = inga._inga().getAsClass(sessionData=api.g.sessionData,query={})
    columns = [ "Domain Name", "IP", "Scan Name" ]
    table = ui.table(columns,0,0)
    if action == "build":
        return table.getColumns() ,200
    elif action == "poll":
        data = []
        for scan in scans:
            for domain in scan.domains:
                data.append([ui.safe(domain["domain"]),ui.safe(domain["ip"]),ui.safe(scan.scanName)])
        total = len(data)
        start = int(jimi.api.request.args.get('start'))
        if start + 200 > len(data):
            data = data[start:]
        else:
            data = data[start:start+200]
        return { "draw" : int(jimi.api.request.args.get('draw')), "recordsTable" : len(data), "recordsFiltered" : total, "recordsTotal" : total, "data" : data } ,200

@pluginPages.route("/networkScansResults/",methods=["GET"])
def networkScansResults():
    scansResults = inga._inga().getAsClass(api.g.sessionData,query={ "up" : True },fields=["scanName","ip","up","lastScan","ports"])

    nodesDict = {}
    edgesDict = {}
    for scansResult in scansResults:
        if scansResult.scanName not in nodesDict:
            nodesDict[scansResult.scanName] = { "id" : scansResult.scanName, "label" : scansResult.scanName, "shape" : "dot", "value" : 1, "color" : { "background" : "#C72F1E", "border" : "#C72F1E" , "highlight" : { "background" : "#000", "border" : "#FFF" } } }
        if scansResult.ip not in nodesDict:
            nodesDict[scansResult.ip] = { "id" : scansResult.ip, "label" : scansResult.ip, "shape" : "image", "image" : "/static/img/computer.svg", "value" : 1, "color" : { "background" : "#C72F1E", "border" : "#C72F1E" , "highlight" : { "background" : "#000", "border" : "#FFF" } } }
        else:
            nodesDict[scansResult.ip]["value"] += 1
        key = "{0}-{1}".format(scansResult.scanName,scansResult.ip)
        if key not in edgesDict:
            edgesDict[key] = { "id" : key, "from" : scansResult.scanName, "to" : scansResult.ip }
            
    nodes = [ x for x in nodesDict.values() ]
    edges = [ x for x in edgesDict.values() ]
    options = {
        "interaction": {
            "tooltipDelay": 200,
            "hideEdgesOnDrag": True,
            "hideEdgesOnZoom": True,
        },
        "layout": {
            "improvedLayout": False
        },
        "physics": {
            "enabled": True,
            "timestep": 1,
            "stabilization": False,
            "barnesHut" : {
                "springConstant" : 0.001
            }
        },
        "nodes": {
            "shape": "dot",
            "color": {
                "background": "#4090c9",
                "highlight": {
                    "background": "#000",
                    "border": "#FFF"
                }
            },
            "font": {
                "size": 10,
                "face": "Tahoma",
                "color": "#bfbfbf"
            }
        },
        "edges": {
            "width": 1,
            "selectionWidth": 1,
            "color": {
                "color": "#ffffff2f", 
                "highlight": "#FFF",
            },
            "smooth": {
                "type": "continuous",
            }
        }
    }
    return { "nodes" : nodes, "edges" : edges, "options" : options }, 200

@pluginPages.route("/scan/<scanName>/")
def getScan(scanName):
    scansResults = inga._inga().query(api.g.sessionData,query={ "scanName" : scanName, "up" : True },fields=["scanName","ip","up","lastScan","ports"])["results"]
    return render_template("ingaScan.html",CSRF=jimi.api.g.sessionData["CSRF"],scanResults=ui.dictTable(scansResults))

@pluginPages.route("scan/<scanName>/barScanResults/",methods=["POST"])
def barScanResults(scanName):
    bar = ui.bar()
    with open(Path("plugins/inga/web/includes/sankeyMapping.json")) as json_file:
        serviceMap = json.load(json_file)
    bar.addLabel("Other")
    for service in serviceMap.keys():
        bar.addLabel(service)
    scansResults = inga._inga().getAsClass(api.g.sessionData,query={ "scanName" : scanName, "up" : True },fields=["scanName","ip","up","lastScan","ports"])
    data = {}
    for scansResult in scansResults:
        if scansResult.scanName not in data:
            data[scansResult.scanName] = { "Other" : 0 }
            for service in serviceMap.keys():
                data[scansResult.scanName][service] = 0
        for port in scansResult.ports["tcp"]:
            matched = getPortMapping(serviceMap,str(port["port"]))
            if matched != None:
                data[scansResult.scanName][matched] += 1
            else:
                data[scansResult.scanName]["Other"] += 1
    for scan in data:
        dataList = []
        for k,v in data[scan].items():
            dataList.append(v)
        bar.addDataset(scan,dataList)

    data = json.loads(jimi.api.request.data)
    return bar.generate(data), 200

@pluginPages.route("scan/<scanName>/timelineScansResults/",methods=["GET"])
def timelineScansResults(scanName):
    scanResults = inga._inga().getAsClass(api.g.sessionData,query={ "scanName" : scanName, "up" : True },fields=["scanName","ip","up","lastScan","ports"])
    timeline = []
    for scanResult in scanResults:
        formatted_date = time.strftime('%Y-%m-%d %H:%M:%S',  time.localtime(scanResult.lastScan))
        timeline.append({ "id" : len(timeline), "content" : scanResult.ip, "start" : formatted_date })

    return { "timeline" : timeline }, 200

# @pluginPages.route("/scan/<scanName>/")
# def getScan(scanName):
#     results             = inga._inga().query(api.g.sessionData,query={ "scanName" : scanName, "up" : True },fields=["scanName","ip","up","lastScan","ports"])["results"]
#     barChartData        = { }
#     scanData            = []
#     networkChartPorts   = []
#     # 
#     # New
#     for scan in results:
#         c               = 0
#         portValues      = [ ]

#         try:
#             tcpPorts        = scan["ports"]["tcp"]
#             udpPorts        = scan["ports"]["udp"]
#             combinedPorts   = tcpPorts + udpPorts      

#             for portValue in combinedPorts:
#                 if portValue["state"] == "open":
#                     c += 1
#                     portValues.append( { "port":  portValue["port"], "service": portValue["service"], "state": portValue["state"] })
#                     networkChartPorts.append([scan["ip"],str(portValue["port"])])
#             if c > 0:
#                 try:
#                     barChartData[scan["ip"]] = c
#                 except KeyError:
#                     pass            
#         except KeyError:
#             pass
        
#         scanData.append( { "scanName": scan["scanName"], "ip": scan["ip"], "up": scan["up"], "lastScan": scan["lastScan"], "portData": portValues } )

#     barChartColours = genRandomColours(len(barChartData))

#     test    = inga._inga().query(api.g.sessionData,query={ "scanName" : scanName, "up" : True },fields=["ports","ip","domains"])["results"]
#     test2   = []
#     ids     = []
#     print(scanName)
#     for scan in test:
#         # print(scan)
#         try:
#             for portValue in scan["ports"]["tcp"]:
#                 try:
#                     ids.append(db.ObjectId(portValue["data"]["webScreenShot"]["storageID"]))
#                     test2.append({ "url" : "{0}://{1}:{2}".format(portValue["data"]["webServerDetect"]["protocol"],scan["ip"],portValue["port"]), "fileData" : portValue["data"]["webScreenShot"]["storageID"] })
#                 except KeyError:
#                     pass
#             for domainValue in scan["domains"]:
#                 for protocol in ["http","https"]:
#                     try:
#                         ids.append(db.ObjectId(domainValue["data"]["webScreenShot"][protocol]["storageID"]))
#                         test2.append({ "url" : "{0}://{1}".format(protocol,domainValue["domain"]), "fileData" : domainValue["data"]["webScreenShot"][protocol]["storageID"] })
#                     except KeyError:
#                         pass
#         except KeyError:
#             pass
#     print("IDS",ids)
#     print(test2)
#     results = storage._storage().query(api.g.sessionData,query={ "_id" : { "$in" : ids } })["results"]
#     for item in test2:
#         for storageResult in results:
#             if item["fileData"] == str(storageResult["_id"]):
#                 item["fileData"] = storageResult["fileData"]


#     return render_template("ingaScan.html", barChartData=barChartData,barChartColours=barChartColours,scanData=scanData, networkChartPorts=networkChartPorts)    
#     # return render_template("scan.html", scanResults=results)

@pluginPages.route("/scan/<scanName>/images/")
def getScanImages(scanName):
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
