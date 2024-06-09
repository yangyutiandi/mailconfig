import os
import json
import re

def getkeylist(keys, item):
    re = []
    for key in keys:
        if key in item:
            re += item[key]
    return re

def buildin(domain):
    data = {}
    filepath = "./buildinlists"
    files = os.listdir(filepath)
    if "key.json" not in files:
        data["error"]= "file key.json not found"
        return data
    try:
        kfile = open(f"{filepath}/key.json",'r')
        json_str = kfile.read()
        kfile.close()
        keyinfo = json.loads(json_str)
    except Exception as e:
        data["error"] = str(e)
        return data

    data["warning"] = []
    for key, matchs in keyinfo.items():
        if key+".txt" not in files:
            data["warning"].append(f"file {key}.txt not found" )
            continue
        f = open(f"{filepath}/{key}.txt",'r')
        jlist = f.read()
        f.close()
        jlist = jlist.split('\n')
        relist = []
        for item in jlist:
            try:
                item = json.loads(item)
            except:
                continue
            if "domain" not in item or key not in item:
                continue
            match = False
            if matchs:
                matchs = getkeylist(matchs, item)
                for restring in matchs:
                    reinfo = re.match(restring, domain)
                    if reinfo and reinfo.group() == domain:  #the regex must fully match the domain
                        match = True
                        break
            if not match and "domain" in item:
                if domain == item["domain"]:
                    match = True
            if match:
                relist.append(item[key])
        data[key] = relist
    return data


if __name__ == "__main__":

    x = buildin("onet.pl")
    json_string = json.dumps(x, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)