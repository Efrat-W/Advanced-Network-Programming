from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR, DNSRRSOA, sniff, TCP, raw
from os import path
import socket
from sys import argv

'''
DNS toolkit, Advanced Networking final assignment
by ef-w
'''

#~~~~~~~~~~~~~~~~~~~    1 CAA dig script   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DEFAULT_DNS = "8.8.8.8"

def printCAA(records: list[str]) -> None:
    print("CAA records:")
    for rec in records:
        print(rec)

def dig(domain: str, q_type="CAA", dns :str=DEFAULT_DNS) -> list[str]:
    # create DNS query packet
    res = sr1(
            IP(dst=dns)/
            UDP(dport=53)/
            DNS(rd=1, qd=DNSQR(qname=domain, qtype=q_type)),
            verbose=0
            )

    cutoff = len('\x00\x05issue')
    addr_res = []
    dnsrr_count = res[DNS].ancount
    for i in range(dnsrr_count):
        data = res[DNSRR][i].rdata
        data = data.decode()[cutoff:]
        data = data.split(';')  # in case of irrelevant added info
        addr_res.append(data[0])
    
    return addr_res


#~~~~~~~~~~~~~~~~~~~    2 DNS map script   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#from dnsmap import list2

TYPE_A = 1 # A (1) for IPv4
TYPE_SOA = 6 

def extract_prefixes():
    file_path = path.dirname(path.abspath(__file__))
    wordlist_path = path.join(file_path, "wordlist_TLAs.txt")

    with open(wordlist_path, 'r') as wordlist:
        for prefix in wordlist:
            yield prefix.strip()
    
    """# dnsmap.h list, manually exported into dnsmap.py
    for prefix in list2:
        yield prefix"""


def getIP(domain: str, dns: str=DEFAULT_DNS, q_type=TYPE_A) -> list[str]:
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
        
        if res[DNS].ancount:
            dns_name = (res[DNSRRSOA].mname).decode()[:-1]
            return getIP(dns_name, dns, q_type=TYPE_A) # get IP addr of the DNS server

    elif res and res[DNS].ancount and res.haslayer(DNSRR):
        for i in range(res[DNS].ancount):
            dnsrr = res[DNSRR][i]
            if dnsrr.type == q_type: # for IPv4
                res_addr.append(dnsrr.rdata)
    
    
    return res_addr


def printDNSmap(hashed_domains: dict[str, list[str]]) -> None:
    print("\nDNS Network Mapper")
    for domain, ip_list in hashed_domains:
        print(domain)
        for i, ip in enumerate(ip_list):
            print(f"IP address #{i+1}: {ip}")
        print('\n')



def dnsmap(domain: str, q_type=TYPE_A, dns: str=DEFAULT_DNS):
    # get a domain-specific DNS server via SOA rr
    dns_server = getIP(domain, q_type=TYPE_SOA)
    
    if not len(dns_server):
        print("SOmething went wrong :/")
        return

    dns = dns_server[0]

    for pref in extract_prefixes():
        new_domain = pref + '.' + domain

        res_addr = getIP(new_domain, dns)

        if res_addr:
            yield (new_domain, res_addr)

#~~~~~~~~~~~~~~~~~~~    3 WHOIS   script   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def whoisQueryReq(domain: str) -> None:
    print("Processing, might take a few seconds...")
    
    iana = "whois.iana.org"
    PORT = 43 # TCP port on which WHOIS listens
    TLD = '.' + domain.split('.')[-1].lower()
    whois_server = ''
    name_servers = []


    def TLDfilter(p):
        return TCP in p and TLD in str(p[TCP].payload).lower()
    
    def DomainFilter(p):
        return TCP in p and domain in str(p[TCP].payload).lower()
    

    # Phase 1: Find TLD specific whois server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((iana, PORT))
        sock.send((TLD + "\r\n").encode())

        # receive response packets
        packets = sniff(timeout=10, filter="tcp port 43", lfilter=TLDfilter)
        #print(f"num of packets sniffed: {len(packets):^4} IANA")
        for p in packets:
            payload = bytes(p[TCP].payload).decode('UTF8','replace')
            raw_data = payload.split('\n')
            for data in raw_data:
                if "whois:" in data:
                    whois_server = data.split(':')[1].strip()
                    break
                elif "nserver:" in data:
                    name_servers.append(data.split(':')[1].strip())

        if not whois_server:
            if not len(name_servers):
                assert "No server was found, whatsoever."
            whois_server = name_servers[0]


    except Exception as e:
        print(f"An error occured: {e}")

    finally:
        sock.close()

    # if there was no result in phase 1
    if not whois_server:
        whois_server = domain

    # Phase 2: Return all data from the whois requested domain
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((whois_server, PORT))
        sock.send((domain + "\r\n").encode())

        # receive response packets
        packets = sniff(timeout=10, filter="tcp port 43", lfilter=DomainFilter)

        for p in packets:
            payload = bytes(p[TCP].payload).decode('UTF8','replace')
            print(payload)

    except Exception as e:
        print(f"An error occured: {e}")

    finally:
        sock.close()

#~~~~~~~~~~~~~~~~~~~    Main script   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def main(args) -> None:
    if len(args) < 2:
        print("No domain name given. Feel free to try again.")
        return
    
    req_domain = args[1]

    op = 0
    # optinal for running a specific operation
    # 1 for CAA, 2 for DNS enum, 3 for WHOIS
    try:
        if len(args) > 2:
            op = int(args[2])
    except:
        pass
    
    # 1.    CAA of requested domain
    if not op or op == 1:
        records = dig(req_domain)
        printCAA(records)

    # 2.    DNS enumeration
    if not op or op == 2:
        printDNSmap(dnsmap(domain=req_domain, q_type="SOA"))

    # 3.    WHOIS query
    if not op or op == 3:
        whoisQueryReq(domain=req_domain)

if __name__ == '__main__':
    main(argv)