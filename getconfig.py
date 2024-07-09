import json
import argparse
from autoconfig import autoconfig
from autodiscover import autodiscover
from srv import srv
from buildin import buildin
from verify import param_check
from testconnect import testconnect

SCAN_AUTOCONFIG = 1
SCAN_AUTODISCOVER = 2
SCAN_SRV = 4
SCAN_BUILDIN = 8

SCAN_ALL = SCAN_AUTOCONFIG| SCAN_AUTODISCOVER | SCAN_SRV | SCAN_BUILDIN

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
    if (flag & SCAN_BUILDIN):
        print("looking up the buildin list")
        data["buildin"] = buildin(domain)
    print("done")
    return data
    # json_string = json.dumps(data, indent=4, default=lambda obj: obj.__dict__)


def main():

    parser = argparse.ArgumentParser(description='a tool to get all possible config of an email address')

    parser.add_argument('mailaddress', type=str, help='a mail address is required')

    parser.add_argument('-c', '--autoconfig', action='store_true', help='look up from all autoconfig url')
    parser.add_argument('-d', '--autodiscover', action='store_true', help='look up from all autodiscover url')
    parser.add_argument('-s', '--srv', action='store_true', help='look up from DNS SRV')
    parser.add_argument('-b', '--buildin', action='store_true', help='look up from mail client buildin provider list')

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
    if args.buildin:
        flag |= SCAN_BUILDIN

    if flag == 0 :       #default scan all
        flag = SCAN_ALL

    # print(flag)
    result = doscan(args.mailaddress, domain, flag)
    json_string = json.dumps(result, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)
    tree = param_check(result)
    json_string = json.dumps(tree, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)
    tree1 = param_check(result, True)
    json_string = json.dumps(tree1, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)
    testconnect(tree)
    json_string = json.dumps(tree, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)


if __name__ == "__main__":
    main()