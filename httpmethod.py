'''
use http/https get or post to get a xml string
interface: http_get, https_get, http_post, https_post, get_redirect_post
param a url, (a domain of mailserver)

return a dict,
error: some error happened, this error is a http(s) error
xml: a string in xml format
redirect: all redirect paths in http header, from person lookup url to final url get the xml

https_method return,
verified : is certificate can be verified

in get_redirect_post return
error: redirect not to a https url
'''

import io
import requests
import certifi

DEFAULT_TIMEOUT = 5
def process_respond(response):
    re = {}
    # re["error"] = ""
    content_type = response.headers.get("content-type", '').lower().split(';')[0]
    if response.status_code >= 200 and response.status_code < 300:
        if content_type == "text/xml" or content_type == "application/xml":
            # track the redirection.
            if response.history:
                redict = {}
                for redirect in response.history:
                    redict[redirect.url] = redirect.status_code
                redict[response.url] = response.status_code
                re["redirect"] = redict
            # print(response.text)
            xml_file = io.StringIO(response.text)
            # data[alias]['config_from_http'] = parse_autoconfig(xml_file)
            re["xml"] = xml_file
            # config_from_http = parse_autoconfig(xml_file)
            # if config_from_http:
            #     re["config"] = config_from_http
        else:
            # print(response.text)
            re["error"] = "Content-Type is not xml"
    else:
        re["error"] = f"status code: {response.status_code}, {response.reason}"
    return re

def http_get(url):
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36 (Autoconfig Test)"
    # user_agent = "Mozilla/5.0"
    # request from HTTP
    re = {}
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': user_agent})
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.TooManyRedirects):
            re["error"] = "Too many redirects."
        elif isinstance(e, requests.exceptions.ConnectionError):
            re["error"] = "Connection Error"
        elif isinstance(e, requests.exceptions.Timeout):
            re["error"] = "Timeout"
        else:
            re["error"] = str(e)
    except Exception as e:
        re["error"] = str(e)
    else:
        re.update(process_respond(response))
    return re

def https_get(url):
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36 (Autoconfig Test)"
    # user_agent = "Mozilla/5.0"
    #  request from HTTPS
    re = {}
    try:
        response = requests.get(url, verify=certifi.where(), timeout=DEFAULT_TIMEOUT, headers={'User-Agent': user_agent})
        re["verified"] = True
    except requests.exceptions.SSLError:
        try:
            re["verified"] = False
            response = requests.get(url, verify=False, timeout=DEFAULT_TIMEOUT, headers={'User-Agent': user_agent})
        except requests.exceptions.SSLError:
            re["error"] = "SSL Connection Error"
            return re
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.TooManyRedirects):
            re["error"] = "Too many redirects."
        elif isinstance(e, requests.exceptions.ConnectionError):
            re["error"] = "Connection Error"
        elif isinstance(e, requests.exceptions.Timeout):
            re["error"] = "Timeout"
        else:
            re["error"] = str(e)
        return re
    except Exception as e:
        re["error"] = str(e)
        return re
    re.update(process_respond(response))
    return re

# post need to set data, need domain
def http_post(url, mailaddress):
    body = f"""<?xml version='1.0' encoding='utf-8'?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request><EMailAddress>{mailaddress}</EMailAddress>
        <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request></Autodiscover>
    """
    re = {}
    try:
        response = requests.post(url, data=body, timeout=DEFAULT_TIMEOUT, headers={"Content-Type": "text/xml; charset=utf-8"})
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.TooManyRedirects):
            re["error"] = "Too many redirects."
        elif isinstance(e, requests.exceptions.ConnectionError):
            re["error"] = "Connection Error"
        elif isinstance(e, requests.exceptions.Timeout):
            re["error"] = "Timeout"
        else:
            re["error"] = str(e)
    except Exception as e:
        re["error"] = str(e)
    else:
        re.update(process_respond(response))
    return re

def https_post(url, mailaddress):
    body = f"""<?xml version='1.0' encoding='utf-8'?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request><EMailAddress>{mailaddress}</EMailAddress>
        <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request></Autodiscover>
    """
    re = {}
    try:
        response = requests.post(url, data=body, timeout=DEFAULT_TIMEOUT, headers={"Content-Type": "text/xml; charset=utf-8"}, verify=certifi.where())
        re["verified"] = True
    except requests.exceptions.SSLError:
        try:
            re["verified"] = False
            response = requests.post(url, data=body, timeout=DEFAULT_TIMEOUT, headers={"Content-Type": "text/xml; charset=utf-8"}, verify=False)
        except requests.exceptions.SSLError:
            re["error"] = "SSL Connection Error"
            return re
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.TooManyRedirects):
            re["error"] = "Too many redirects."
        elif isinstance(e, requests.exceptions.ConnectionError):
            re["error"] = "Connection Error"
        elif isinstance(e, requests.exceptions.Timeout):
            re["error"] = "Timeout"
        else:
            re["error"] = str(e)
        return re
    except Exception as e:
        re["error"] = str(e)
        return re

    re.update(process_respond(response))
    return re

def get_redirect_post(url, mailaddress):
    """
    this function will redict a http get method to a https post method to get a xml string
    """
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36 (Autoconfig Test)"
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={"User-Agent": user_agent})
        if response.history:
            redict = {}
            for redirect in response.history:
                redict[redirect.url] = redirect.status_code
            redict[response.url] = response.status_code
            re = {}
            re.update({"redirect": redict})
            if response.url.startswith("https://"):
                # Maybe "request_error" in fetch_config().
                re.update(https_post(response.url, mailaddress))
            else:
                re.update({'error': f"Not a https url : {url}"})
            return re
        else:
            # there is no redict
            return {}
    except Exception as e:
        # this error is no need to care about,means no redict
        return {}


if __name__ == "__main__":
    domain = "pobox.com"
    url1 = f"https://{domain}/autodiscover/autodiscover.xml"
    url2 = f"https://autodiscover.{domain}/autodiscover/autodiscover.xml"
    print(https_get(url1))
    print(https_post(url1, domain))
    print(https_get(url2))
    print(https_post(url2, domain))
