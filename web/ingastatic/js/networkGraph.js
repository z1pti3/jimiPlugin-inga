function network(data,HTMLElementID) {
    var network = null;
    var mapping = {};
    var nodes = [];
    var edges = [];
    var edgeMapping = {};
    var finalNodes = []
    for (d in data) {
        d = data[d];
        var b = null;
        var a = null;
        var color = "#4090c9";

        if (d[0] == $('#fromAsset').val() || d[1] == $('#fromAsset').val() ) {
            color = "#a61919";
        }

        if (!mapping.hasOwnProperty(d[0])) {
            id = nodes.length;
            nodes.push({ id: id, label: d[0], value: 1, color : color });
            mapping[d[0]] = { id :  id };
        } else {
            nodes[mapping[d[0]]["id"]]["value"] +=1;
        }
        a = mapping[d[0]]

        if (!mapping.hasOwnProperty(d[1])) {
            id = nodes.length;
            nodes.push({ id: id, label: d[1], value: 1, color : color });
            mapping[d[1]] = { id :  id };
        } else {
            nodes[mapping[d[1]]["id"]]["value"] +=1;
        }
        b = mapping[d[1]]


        if (a["id"] != b["id"]) {
            var key = a["id"]+"->"+b["id"];
            var key2 = b["id"]+"->"+a["id"];
            if ((!edgeMapping.hasOwnProperty(key)) && (!edgeMapping.hasOwnProperty(key2))) {
                edgeMapping[key] = 1;
                edgeMapping[key2] = 1;
                edges.push({ 
                    from: a["id"], 
                    to: b["id"]
                });
            }
        }
    }
    
    var container = document.getElementById(HTMLElementID);
    var data = {
        nodes: nodes,
        edges: edges
    };
    var options = {
        nodes: {
            shape: "dot",
            scaling: {
            min: 1,
            max: 10,
            },
            font: {
            size: 12,
            face: "Tahoma",
            color: "#bfbfbf"
            },
        },
        edges: {
            width: 0.15,
            color: { inherit: "from" },
            smooth: {
                type: "continuous",
            },
        }
    };
    network = new vis.Network(container, data, options);
}
