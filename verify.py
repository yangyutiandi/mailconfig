import re

pattern = re.compile(
    r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
    r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
)

proto_type = ["smtp", "imap", "imap4", "pop", "pop3"]

def guess(port, default = "plain"):
    if port == 993 or port == 995 or port == 465:
        return 'ssl'
    if port == 143 or port == 110 or port == 587 or port == 25:
        return 'starttls'
    return default

def config_flat(item, info_dict):
    info = {}
    for key in item:
        if key != "config":
            info[key] = item[key]
    info.update(info_dict)
    config = item["config"]
    configlist = []
    if "incomingServers" in config:
        configlist+= config["incomingServers"]
    if "outgoingServers" in config:
        configlist += config["outgoingServers"]
    for i in range(len(configlist)):
        configlist[i]["config_info"] = info
    return  configlist

def flat_autoconfig(data):
    url_pool = ["autoconfig-url", "well-known-url"]
    http_method = ["http_get", "https_get"]
    relist = []
    for url in url_pool:
        for method in http_method:
            if "config" in data[url][method]:
                relist += config_flat(data[url][method], {"orign" : url+":"+method })

    if "config" in data["ISPDB"]:
        relist += config_flat(data["ISPDB"], {"orign" : "ISPDB"})
    back_off = data["Back-off"]
    domain_pool = ["register domain", "parent domain"]
    for each in domain_pool:
        if each in back_off:    #have this domain item
            cur = back_off[each]
            if "config" in cur["https_get"]:
                relist += config_flat(cur["https_get"], {"orign": each +":https_get" , each: cur[each] })
            if "config" in cur["ISPDB"]:
                relist += config_flat(cur["ISPDB"], {"orign": each + ":ISPDB", each: cur[each]})
    # print(relist, len(relist))
    return  relist

def flat_autodiscover(data):
    url_pool = ["autodis-origin", "autodis-prefix"]
    http_method = ["http_get", "https_get", "http_post", "https_post"]
    relist = []
    for url in url_pool:
        for method in http_method:
            if "config" in data[url][method]:
                relist += config_flat(data[url][method], {"orign" : url+":"+method })
    if "config" in data["autodis-redirect"]:
        relist += config_flat(data["autodis-redirect"], {"orign": "autodis-redirect"})
    if "config" in data["autodis-srv"]:
        relist += config_flat(data["autodis-srv"], {"orign": "autodis-srv"})
    # print(relist, len(relist))
    return relist

def check_type(type):
    if type in proto_type:
        return True
    return False

def check_port(pstr):
    if pstr is None:
        return False
    if not pstr.isdigit():  #not a num
        return False
    pint = int(pstr)
    if 1 <= pint <=65535:
        return True
    return False

def check_domain(hostname): # a valid hostname
    if not hostname:
        return False
    # TODO: this is a regex string check, more check?
    return True if pattern.match(hostname) else False


def autoconfig_socket(item):
    sockettype = item["socketType"].lower()
    if sockettype == 'ssl':
        return 'ssl'
    if sockettype == 'starttls':
        return 'starttls'
    if sockettype == 'plain':
        return 'plain'
    return None

def autodiscover_socket(item):
    ssl = item['ssl']
    encryption = item['encryption']
    port = int(item["port"])    #port have verified

    if encryption:
        if encryption == 'none':
            return 'plain'
        elif encryption == 'ssl':
            return 'ssl'
        elif encryption == 'tls':
            return 'starttls'
        elif encryption == 'auto':
            #TODO: process auto
            return guess(port)
        else:   #not a valid param
            return None
    elif ssl :
        if ssl == 'on':
            # thunderbird and outlook
            return guess(port, "ssl")
        elif ssl == 'off':
            return 'plain'
        else:   #not a valid param
            return None
    else:   #not a valid param
         return None

def invalid_add(tree, item, info=""):
    if "invaild" not in tree:
        tree["invaild"] = []
    item["config_info"]["error_info"] = info
    tree["invaild"].append(item)

def valid_add(tree, list, info):
    # list = [type, hostname, port, socket_type_info]
    now = tree
    for i in range(len(list)-1):
        if list[i] not in now:
            now[list[i]] = {}
        now = now[list[i]]
    socket_type = list[-1]
    if socket_type not in now:
        now[socket_type] = []
    now[socket_type].append(info)

# need to check none
def autoconfig_param_check(configs, tree):
    for item in configs:
        if not check_type(item["type"].lower()):
            invalid_add(tree, item, f'proto_type = {item["type"]}, type error')
            continue
        if not check_port(item["port"]) or not check_domain(item["hostname"]):
            invalid_add(tree, item, f'{item["hostname"]}:{item["port"]}, hostname and port error')
            continue
        socket_type = autoconfig_socket(item)
        if socket_type is None: #invalid socket type
            invalid_add(tree, item, f'socketType = {item["socketType"]}, socketType error')
            continue
        info = item["config_info"].copy()
        if item["authentication"] is not None:
            info["authentication"] = item["authentication"]
        valid_add(tree, [item["type"].lower(), item["hostname"], item["port"], socket_type], info)

def autodiscover_process(configs):  #erery item in autodiscover have some other info
    param_pool = ["spa", "ttl", "domainrequired"]
    for i in range(len(configs)):
        for param in param_pool:
            if configs[i][param] is not None:
                configs[i]["config_info"][param] = configs[i][param]

def autodiscover_param_check(configs, tree):    #type in autodiscover does not need to be check, see code in autodiscover.py
    for item in configs:
        if not check_port(item["port"]) or not check_domain(item["server"]):
            invalid_add(tree, item, f'{item["server"]}:{item["port"]}, hostname and port error')
            continue
        socket_type = autodiscover_socket(item)
        if socket_type is None:  # invalid socket type
            invalid_add(tree, item, f'encryption = {item["encryption"]} and ssl = {item["ssl"]}, socketType error')
            continue
        info = item["config_info"].copy()
        valid_add(tree,  [item["type"].lower(), item["server"], item["port"], socket_type], info)

def srv_param_check(configs, tree):
    for item in configs:
        if not (1<= item["port"] <= 65535) or not check_domain(item["hostname"]):
            invalid_add(tree, item, f'{item["server"]}:{item["port"]}, hostname and port error')
            continue
        valid_add(tree, [item["type"].lower(), item["hostname"], str(item["port"]), item["socketType"]], item["config_info"])

def autoconfig_check(data, tree):
    res = flat_autoconfig(data)
    autoconfig_param_check(res, tree)

def autodiscover_check(data, tree):
    res = flat_autodiscover(data)
    autodiscover_process(res)
    autodiscover_param_check(res, tree)

def srv_check(data, tree):
    res = []
    for key, item in data.items():
        if item:
            info = {"orign" : "srv:" + key, "is_dnssec" : item["is_dnssec"]}
            for config in item["srv_record"]:
                socketType = "starttls"
                type = key
                if key[-1] == "s":
                    type = type[:-1]
                    socketType = "ssl"
                cur = {"type" : type, "hostname" : config["hostname"], "port" : config["port"], "socketType" : socketType, "config_info": info}
                res.append(cur)
    srv_param_check(res, tree)

def buildin_check(data, tree):
    res = []
    for key, item in data.items():
        configlist = []
        for config in item:
            if "incomingServers" in config:
                configlist += config["incomingServers"]
            if "outgoingServers" in config:
                configlist += config["outgoingServers"]
            for i in range(len(configlist)):
                configlist[i]["config_info"] = {"orign" : "build_in:" + key}
        res += configlist
    autoconfig_param_check(res, tree)


def param_check(data):
    tree = {}
    if "autoconfig" in data:
        autoconfig_check(data["autoconfig"], tree)
    if "autodiscover" in data:
        autodiscover_check(data["autodiscover"], tree)
    if "srv" in data:
        srv_check(data["srv"], tree)
    if "buildin" in data:
        buildin_check(data["buildin"], tree)
    return tree

if __name__=="__main__":
    import json

    f = open("data.json", 'r')
    item = f.read()
    f.close()
    datadict = json.loads(item)
    x = param_check(datadict)
    json_string = json.dumps(x, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)