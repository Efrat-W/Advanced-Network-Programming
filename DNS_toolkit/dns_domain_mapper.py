from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR, DNSRRSOA
from os import path
from dnsmap import list2
#from time import sleep

DEFAULT_DNS = "8.8.8.8"
TYPE_A = 1 # A (1) for IPv4
TYPE_SOA = 6 

def extract_prefixes():
    file_path = path.dirname(path.abspath(__file__))
    wordlist_path = path.join(file_path, "wordlist_TLAs.txt")

    with open(wordlist_path, 'r') as wordlist:
        for prefix in wordlist:
            yield prefix.strip()
    
    # dnsmap.h list, manually exported into dnsmap.py
    for prefix in list2:
        yield prefix


def getIP(domain, dns=DEFAULT_DNS, q_type=TYPE_A):
    res_addr = []

    # create DNS query packet
    new_domain = domain
    res = sr1(
            IP(dst=dns)/
            UDP(dport=53)/
            DNS(rd=1, qd=DNSQR(qname=new_domain, qtype=q_type)),
            verbose=0,
            timeout=5
            )
    
    if (q_type == 6 or q_type == "SOA") and res.haslayer(DNSRRSOA):
        #print(res.show())
        if res[DNS].ancount:
            dns_name = (res[DNSRRSOA].mname).decode()[:-1]
            #print(f"DNS server of {domain}, extracted from SOA: {dns_name}")
            return getIP(dns_name, dns, q_type=TYPE_A) # get IP addr of the DNS server

    elif res and res[DNS].ancount and res.haslayer(DNSRR):
        #print(res.show())
        for i in range(res[DNS].ancount):
            dnsrr = res[DNSRR][i]
            if dnsrr.type == q_type: # for IPv4
                res_addr.append(dnsrr.rdata)
    
    
    return res_addr


def printDNSmap(hashed_domains):
    for domain, ip_list in hashed_domains:
        print(domain)
        for i, ip in enumerate(ip_list):
            print(f"IP address #{i+1}: {ip}")
        print('\n')



def dnsmap(domain, q_type=TYPE_A, dns=DEFAULT_DNS):
    # get a domain-specific DNS server via SOA rr
    dns_server = getIP(domain, q_type=TYPE_SOA)
    
    if not len(dns_server):
        print("SOmething went wrong :/")
        return

    dns = dns_server[0]
    hash_ip = {}

    for pref in extract_prefixes():
        new_domain = pref + '.' + domain

        res_addr = getIP(new_domain, dns)

        if res_addr:
            hash_ip[new_domain] = hash_ip.get(new_domain, [])
            
            for ip in res_addr:
                hash_ip[new_domain] += [ip]

            yield (new_domain, res_addr)

    return hash_ip



printDNSmap(dnsmap("jct.ac.il", q_type="SOA"))