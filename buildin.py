import os
import json
import re
from srv import resolve_mx

def getkeylist(keys, item):
    re = []
    for key in keys:
        if key in item:
            re += item[key]
    return re

def buildin(domain):
    mxdomain = None
    mxlist = resolve_mx(domain)
    if mxlist:  # no mx record
        mxdomain = mxlist[0]["hostname"]
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
        jlist = f.read().split('\n')[0:-1]
        f.close()
        relist = []
        for item in jlist:
            item = json.loads(item)
            if "domain" not in item or key not in item:
                continue
            match = False
            if matchs:
                if "domre" in matchs:
                    matcher = getkeylist(matchs["domre"], item)
                    for restring in matcher:
                        reinfo = re.match(restring, domain)
                        if reinfo and reinfo.group() == domain:  #the regex must fully match the domain
                            match = True
                            break
                if mxdomain and not match and "mxre" in matchs:
                    matcher = getkeylist(matchs["mxre"], item)
                    for restring in matcher:
                        reinfo = re.match(restring, mxdomain)
                        if reinfo and reinfo.group() == mxdomain:  # the regex must fully match the domain
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

    x = buildin("gmail.com")
    json_string = json.dumps(x, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)