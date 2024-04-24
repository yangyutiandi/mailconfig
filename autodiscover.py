
import xml.etree.ElementTree as ET
import logging
from srv import resolve_srv
from httpmethod import http_get, https_get, http_post, https_post, get_redirect_post

LOGGER = logging.getLogger(__name__)


def autodiscover_srv(domain):
    try:
        res = resolve_srv(f"_autodiscover._tcp.{domain}")
        if not res or not res['srv_record']:        #none list
            return None
        try:
            if res['srv_record']:
                hostname = res['srv_record'][0]['hostname']
            else:
                return None
        except Exception as e:
            return None
        autodiscover_url = f"https://{hostname}/autodiscover/autodiscover.xml"
        return autodiscover_url
    except Exception:
        # LOGGER.warning("Failed to resolve autodiscover SRV record")
        return None


def parse_autodiscover(content):
    '''
    parse a xml into autodiscover struct,
    if error happened, return a "extract_error"
    '''
    # details: https://msopenspecs.azureedge.net/files/MS-OXDSCLI/[MS-OXDSCLI].pdf
    # Notes: namespace for different xml!
    def is_element_present(element, tag, namespace):
        return element.find(tag, namespace) is not None
    def get_element_text(element, tag, namespace, default=None):
        if is_element_present(element, tag, namespace):
            return element.find(tag, namespace).text
        else:
            return default
    
    data = {}
    try:
        tree = ET.parse(content)
    except ET.ParseError as e:
        # print("XML parse fail.")
        data['extract_error'] = "XML parse fail."
        return data
    
    namespace = {
        "ns1": "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006",
        "ns2": "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"
    }
    root_element = tree.getroot()
    # Parse for error response.
    response_for_error = root_element.find("ns1:Response", namespace)
    if response_for_error:
        error_part = response_for_error.find("ns1:Error", namespace)
        if error_part:
            data['extract_error'] = error_part.find("ns1:Message", namespace).text
            return data
        else :
            data['extract_error'] = "xmns: http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006, message have an error"
            return data
    response = root_element.find("ns2:Response", namespace)
    account = response.find("ns2:Account", namespace)
    action = account.find("ns2:Action", namespace)
    protocols = account.findall("ns2:Protocol", namespace)
    
    incoming_server_data = []
    outgoing_server_data = []
    web_access_data = []
    if action.text == "redirectAddr":
        data["redirectAddr"] = account.find("ns2:RedirectAddr", namespace).text
    elif action.text == "redirectUrl":
        data["redirectUrl"] = account.find("ns2:RedirectUrl", namespace).text
    elif action.text == "settings":
        for protocol in protocols:
            if protocol.find("ns2:Type", namespace).text == "IMAP" or protocol.find("ns2:Type", namespace).text == "POP3":
                server_data = {
                    "type": protocol.find("ns2:Type", namespace).text,
                    "server": protocol.find("ns2:Server", namespace).text,
                    "port": protocol.find("ns2:Port", namespace).text,
                    "ssl": get_element_text(protocol, "ns2:SSL", namespace, "on"),
                    "encryption": get_element_text(protocol, "ns2:Encryption", namespace),
                    "spa": get_element_text(protocol, "ns2:SPA", namespace, "on"),
                    "ttl": get_element_text(protocol, "ns2:TTL", namespace, "1"),
                    "domainrequired": get_element_text(protocol, "ns2:DomainRequired", namespace, "on")
                }
                incoming_server_data.append(server_data)
            if protocol.find("ns2:Type", namespace).text == "SMTP":
                server_data = {
                    "type": protocol.find("ns2:Type", namespace).text,
                    "server": protocol.find("ns2:Server", namespace).text,
                    "port": protocol.find("ns2:Port", namespace).text,
                    "ssl": get_element_text(protocol, "ns2:SSL", namespace, "on"),
                    "encryption": get_element_text(protocol, "ns2:Encryption", namespace),
                    "spa": get_element_text(protocol, "ns2:SPA", namespace, "on"),
                    "ttl": get_element_text(protocol, "ns2:TTL", namespace, "1"),
                    "domainrequired": get_element_text(protocol, "ns2:DomainRequired", namespace, "on")
                }
                outgoing_server_data.append(server_data)
            if protocol.find("ns2:Type", namespace).text == "WEB":
                if protocol.find("ns2:External", namespace):
                    server_data["External"] = {}
                    if protocol.find("ns2:External", namespace).find("ns2:OWAUrl", namespace):
                        server_data["External"]["OWAUrl"]["AuthenticationMethod"] = protocol.find("ns2:External", namespace).find("ns2:OWAUrl", namespace).get("AuthenticationMethod")
                        server_data["External"]["OWAUrl"]["URL"] = protocol.find("ns2:External", namespace).find("ns2:OWAUrl", namespace).text
                        web_access_data.append(server_data)
        data = {"incomingServers": incoming_server_data, "outgoingServers": outgoing_server_data, "webmails": web_access_data}
    return data

# redirect url found in the xml, we must use https post method, and cover the result get before
def config_from_redirect(url, mailaddress, max_redirects=10):
    '''
    除了 httpmethod返回结构之外，还有rediriect信息
    redirect_path : xml重定向路径列表 url + mailaddress
    redirect_xml : 信息，success为成功返回结果，其他字符串为有错误
    可以将此结构直接覆盖原数据，error，config等都会更新，若没有得到config，也可以使用原config
    通过redirect_xml判断redirect过程中遇到了什么错误
    '''
    # print(max_redirects)
    redirect_path = []
    for i in range(max_redirects):
        redirect_path.append((url, mailaddress))
        cur = https_post(url, mailaddress)
        # print(cur)
        if "xml"  not in cur:  #fail in this step
            cur.update({"redirect_path": redirect_path , "redirect_xml" : "redirect meet a error, see in error"})
            return cur
        cur["config"] = parse_autodiscover(cur["xml"])
        if "extract_error" in cur["config"]:
            return {"redirect_path": redirect_path , "redirect_xml" : "error in xml : "+ cur["config"]["extract_error"]}
        if "redirectUrl" in cur["config"]:
            url = cur["config"]["redirectUrl"]
        elif "redirectAddr" in cur["config"]:
            mailaddress = cur["config"]["redirectAddr"]
        else:
            cur.update({"redirect_path": redirect_path , "redirect_xml" : "success"})
            return cur
        if (url,mailaddress) in redirect_path:    #meet a circle
            return {"redirect_path": redirect_path, "redirect_xml": "self redirect to : " + url + "with param" + mailaddress}
    return {"redirect_path": redirect_path, "redirect_xml": "Max redirects reached"}


# allow_redirects=False 是否支持重定向，以及max_redirects=10设置最大重定向次数
def autodiscover(domain, mailaddress):
    # Ref: https://learn.microsoft.com/en-us/previous-versions/office/office-2010/cc511507(v=office.14)?redirectedfrom=MSDN
    # Ref: https://learn.microsoft.com/en-us/previous-versions/office/developer/exchange-server-interoperability-guidance/hh352638(v=exchg.140)

    data = {}
    # Step 1 & 2
    # 4 urls and 2 methods
    url1 = f"http://{domain}/autodiscover/autodiscover.xml"
    url2 = f"http://autodiscover.{domain}/autodiscover/autodiscover.xml"
    url_pool =[(url1, "autodis-origin"), (url2, "autodis-prefix")]
    for url, alias in url_pool:
        data[alias] = {}
        # request from HTTP
        cur = http_get(url)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url, cur["config"]["redirectAddr"]))
        data[alias]["http_get"] = cur

        cur = http_post(url, mailaddress)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url, cur["config"]["redirectAddr"]))
        data[alias]["http_post"] = cur

        # upgrade to https
        url = url.replace("http://", "https://")
        cur = https_get(url)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url, cur["config"]["redirectAddr"]))
        data[alias]["https_get"] = cur

        cur = https_post(url,mailaddress)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url, cur["config"]["redirectAddr"]))
        data[alias]["https_post"] = cur
    
    # Step 3
    url3 = f"http://autodiscover.{domain}/autodiscover/autodiscover.xml"  # Must redirect to https and also prompt the user.
    cur = get_redirect_post(url3, mailaddress)
    if cur  and"xml" in cur:
        cur["config"] = parse_autodiscover(cur["xml"])
        if "redirectUrl" in cur["config"]:
            cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
        elif "redirectAddr" in cur["config"]:
            cur.update(config_from_redirect(url3, cur["config"]["redirectAddr"]))
    data['autodis-redirect'] = cur

    # Step 4, autodiscover-v2
    # url4 = f"https://autodiscover.{domain}/autodiscover/autodiscover.json?Email=admin@{domain}&Protocol=AutodiscoverV1" # Autodiscover v2, ref to https://docs.grommunio.com/kb/autodiscover.html and https://www.msxfaq.de/exchange/autodiscover/autodiscover_v2.htm
    # data["autodis-v2"]= {}
    # try:
    #     res = requests.get(url4, timeout=10, allow_redirects=True, headers={"User-Agent": user_agent}, verify=certifi.where())
    #     content_type = res.headers.get('content-type', '').lower().split(';')[0]
    #     if content_type == "application/json":
    #         data['autodis-v2'].update(res.json())
    #     else:
    #         data['autodis-v2'].update({'request_error': 'Content-Type is not json'})
    # except requests.exceptions.SSLError:
    #     data["autodis-v2"].update({'request_error': 'SSL error'})
    # except requests.exceptions.ConnectionError:
    #     data["autodis-v2"].update({'request_error': 'Connection error'})
    # except Exception as e:
    #     data["autodis-v2"].update({'request_error': 'Other error'})
        
    
    # Step 5
    data['autodis-srv'] = {}
    url_from_srv = autodiscover_srv(domain)
    # print(url_from_srv)
    if url_from_srv:
        cur = https_post(url_from_srv, mailaddress)
        if "xml" in cur:
            cur["config"] = parse_autodiscover(cur["xml"])
            if "redirectUrl" in cur["config"]:
                cur.update(config_from_redirect(cur["config"]["redirectUrl"], mailaddress))
            elif "redirectAddr" in cur["config"]:
                cur.update(config_from_redirect(url_from_srv, cur["config"]["redirectAddr"]))
        data['autodis-srv'] = cur
    else:
        data['autodis-srv']['error'] =  'No SRV record'
    return data



if __name__=="__main__":
    import json

    x = autodiscover("ametiq.com", "admni@ametiq.com")  #need to redirect in xml
    # x = autodiscover("soverin.net", "admni@soverin.net") # have srv
    # x = autodiscover("cluemail.com", "admni@cluemail.com")  # need to redirct in http header
    # x = autodiscover("belean.pl", "admin@belean.pl")   # certificate false
    # x = autodiscover("bigpond.net.au", "admin@bigpond.net.au")   # autodiscover all fail
    # x = autodiscover("huxcomm.net", "admin@huxcomm.net")  # no srv

    # x = config_from_redirect("https://autoconfig-ssl.mail.hostpoint.ch/autodiscover/autodiscover.xml", "ametiq.com", 5)
    json_string = json.dumps(x, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)