import dns.resolver
import logging

my_resolver = dns.resolver.Resolver(configure=False)
my_resolver.nameservers = ['8.8.8.8', '1.1.1.1']
DNS_RESOLVERS = ['8.8.8.8']
DNS_TIMEOUT = 30
LOGGER = logging.getLogger(__name__)

def query_dns(query_name, query_type):
    # Send a dns query
    try:
        results = my_resolver.resolve(query_name, query_type)
        return list(results)
    except:
        return []

def check_dnssec(domain_name, record_type, domain=None):
    """Test to see if a DNSSEC record is valid and correct.

    Checks a domain for DNSSEC whether the domain has a record of type that is protected
    by DNSSEC or NXDOMAIN or NoAnswer that is protected by DNSSEC.

    TODO: Probably does not follow redirects (CNAMEs).  Should work on
    that in the future.
    """
    try:
        query = dns.message.make_query(domain_name, record_type, want_dnssec=True)
        for nameserver in DNS_RESOLVERS:
            response = dns.query.tcp(query, nameserver, timeout=DNS_TIMEOUT)
            if response is not None:
                if response.flags & dns.flags.AD:
                    return True
                else:
                    return False
    except Exception as error:
        print("[DNSSEC Fail]", domain, error)
        return None


def resolve_mx(query_name):
    data = []
    answers = query_dns(query_name, 'MX')
    if len(answers) == 0:
        return data
    for rdata in answers:
        entry = {
            "hostname": ".".join(
                [
                    x.decode('utf-8')
                    for x in rdata.exchange.labels
                    if x.decode('utf-8') != ""
                ]
            ),
            "priority": rdata.preference,
        }
        data.append(entry)
    data = sorted(data, key=lambda x: int(x["priority"]))
    return data

def resolve_srv(query_name):
    answers = query_dns(query_name, 'SRV')
    data = {}
    cur = []
    if len(answers) == 0:
        return data
    for rdata in answers:
        entry = {
            "hostname": ".".join(
                [
                    x.decode('utf-8')
                    for x in rdata.target.labels
                    if x.decode('utf-8') != ""
                ]
            ),
            "port": rdata.port,
            "priority": rdata.priority,
            "weight": rdata.weight,
        }
        cur.append(entry)
    data['srv_record'] = sorted(cur, key=lambda k: (k['priority'], -k['weight'])) #dns 优先级
    data['is_dnssec'] = check_dnssec(query_name, 'SRV')
    return data

def srv(domain):
    # Function replaced by ./srv-scan/scan.go
    '''
    Constructs a SRV record for the given domain, and returns a dictionary of the results.
    '''
    data = {}
    #data["autoconfig"] = resolve_srv(f"_autoconfig._tcp.{domain}")
    data["imaps"] = resolve_srv(f"_imaps._tcp.{domain}")
    data["imap"] = resolve_srv(f"_imap._tcp.{domain}")
    data["pop3s"] = resolve_srv(f"_pop3s._tcp.{domain}")
    data["pop3"] = resolve_srv(f"_pop3._tcp.{domain}")
    data["submissions"] = resolve_srv(f"_submissions.tcp.{domain}")
    data["submission"] = resolve_srv(f"_submission.tcp.{domain}")
    return data


if __name__ == "__main__":
    import json
    x = srv('pobox.com')
    json_string = json.dumps(x, indent=4, default=lambda obj: obj.__dict__)
    print(json_string)