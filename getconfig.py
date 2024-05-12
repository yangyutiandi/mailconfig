import json
import argparse
from autoconfig import autoconfig
from autodiscover import autodiscover
from srv import srv

SCAN_AUTOCONFIG = 1
SCAN_AUTODISCOVER = 2
SCAN_SRV = 4

SCAN_ALL = SCAN_AUTOCONFIG| SCAN_AUTODISCOVER | SCAN_SRV

def doscan(mailaddress, domain, flag):
    data = {}
    if(flag & SCAN_AUTOCONFIG):
        print("scanning autoconfig")
        data["autoconfig"] = autoconfig(domain, mailaddress)
    if (flag & SCAN_AUTODISCOVER):
        print("scanning autodiscover")
        data["autodiscover"] = autodiscover(domain, mailaddress)
    if (flag & SCAN_SRV):
        print("scanning srv")
        data["srv"] = srv(domain)
    print("done")
    json_string = json.dumps(data, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)

def main():

    parser = argparse.ArgumentParser(description='a tool to get all possible config of an email address')

    parser.add_argument('mailaddress', type=str, help='a mail address is required')

    parser.add_argument('-c', '--autoconfig', action='store_true', help='look up from all autoconfig url')
    parser.add_argument('-d', '--autodiscover', action='store_true', help='look up from all autodiscover url')
    parser.add_argument('-s', '--srv', action='store_true', help='look up from DNS SRV')

    args = parser.parse_args()

    list = args.mailaddress.split("@")
    if len(list) !=2 :
        print(args.mailaddress + " is not a valid email address")
        return
    domain = list[1]
    # print(list[0], domain)

    flag = 0
    if args.autoconfig:
        flag |= SCAN_AUTOCONFIG
    if args.autodiscover:
        flag |= SCAN_AUTODISCOVER
    if args.srv:
        flag |= SCAN_SRV

    if flag == 0 :       #default scan all
        flag = SCAN_ALL

    # print(flag)
    doscan(args.mailaddress, domain, flag)


if __name__ == "__main__":
    main()