from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR, DNSRRSOA, sniff, TCP, raw
from os import path
import socket
from sys import argv

'''
DNS toolkit, Advanced Networking (final assignment)
by ef-W
'''

#~~~~~~~~~~~~~~~~~~~    1 CAA dig script   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DEFAULT_DNS = "8.8.8.8"

def printCAA(records: list[str]) -> None:
    """
    Prints the CAA records obtained from DNS query.
    :param records (list[str]): List of records to print.
    """

    print("CAA records:")
    for rec in records:
        print('\t' + rec)


def dig(domain: str, q_type="CAA", dns :str=DEFAULT_DNS) -> list[str]:
    """
    Performs a DNS query to obtain CAA records for the specified domain.

    :param domain (str): requested domain for DNS query.
    :param q_type (str or int): query type. Default "CAA".
    :param dns (str): DNS server to query. Default 8.8.8.8.

    :returns list[str]: List of the CAA records.
    """
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

def extract_prefixes(prefixes_file: str):
    """
    Generator function to yield prefixes from text file

    :param prefixes_file (str): prefix list text file.
    """
    file_path = path.dirname(path.abspath(__file__))
    wordlist_path = path.join(file_path, prefixes_file)

    with open(wordlist_path, 'r') as wordlist:
        for prefix in wordlist:
            yield prefix.strip()


def getIP(domain: str, dns: str=DEFAULT_DNS, q_type=TYPE_A) -> list[str]:
    """
    Performs a DNS query to obtain CAA records for the specified domain.

    :param domain (str): requested domain for DNS query.
    :param q_type (str or int): query type. Default 1.
    :param dns (str): DNS server to query. Default 8.8.8.8.

    :returns list[str]: List of the IP addresses.
    """

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
    
    # extract IP address accordingly
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


def printDNSmap(domain_IPs_pair) -> None:
    """
    Prints the DNS enumeration map.
    
    :param domain_IPs_pair: generator yielded pairs of domain and its IP addrs.
    """
    domain_count, ip_count = 0, 0
    unique_ip = set()
    for domain, ip_list in domain_IPs_pair:
        domain_count += 1
        ip_count += len(ip_list)

        print(domain)
        for i, ip in enumerate(ip_list):
            unique_ip.add(ip)
            print(f"IP address #{i+1}: {ip}")
        print('\n')
    
    print(f"""TOTAL:
    {domain_count} (sub)domains
    {ip_count} IP addresses ({len(unique_ip)} distinct addresses)""")



def dnsmap(domain: str, q_type=TYPE_A, dns: str=DEFAULT_DNS):
    """
    Performs DNS enumeration for the specified domain.

    :param domain: requested domain for DNS query.
    :param q_type: query type. Default 1.
    :param dns: DNS server to query. Default 8.8.8.8.
    """
    print("\nDNS Network Mapper")

    # get a domain-specific DNS server via SOA rr
    dns_server = getIP(domain, q_type=TYPE_SOA)
    if not len(dns_server):
        print("No servers found, closing")
        return

    dns = dns_server[0]

    for pref in extract_prefixes("wordlist_TLAs.txt"):
        new_domain = pref + '.' + domain

        res_addr = getIP(new_domain, dns)

        if res_addr:
            yield (new_domain, res_addr)

#~~~~~~~~~~~~~~~~~~~    3 WHOIS   script   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def whoisQueryReq(domain: str) -> None:
    """
    Performs WHOIS for the specified domain & print the obtained info.

    :param domain (str): requested domain for DNS query.
    """
    print("<Processing, might take a few seconds...>")
    
    iana = "whois.iana.org"
    PORT = 43 # TCP port on which WHOIS listens
    TLD = '.' + domain.split('.')[-1].lower()
    whois_server = '' # not necessarily whois, but the main server we'll use
    name_servers = [] # in case there's no whois server result

    # scapy lfilters
    def TLDfilter(p):
        return TLD in str(p[TCP].payload).lower()
    

    # Phase 1: Find TLD specific whois server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((iana, PORT))
        sock.send((TLD + "\r\n").encode())
        
        # receive response packets
        packets = sniff(timeout=10, filter=f"tcp port {PORT}", lfilter=TLDfilter)
        for p in packets:
            payload = bytes(p[TCP].payload).decode('UTF8','replace')
            raw_data = payload.split('\n')
            for data in raw_data:
                if "whois:" in data:
                    whois_server = data.split(':')[1].strip()
                    break
                elif "nserver:" in data:
                    name_servers.append(data.split(':')[1].strip())

        # use a nserver if no whois server was obtained, or original domain
        if not whois_server:
            if len(name_servers):
                whois_server = name_servers[0]
            else:
                whois_server = domain

        #print(f"whois server: {whois_server}")

    except Exception as e:
        print(f"An error occured fetching the whois server: {e}")

    finally:
        sock.close()


    # Phase 2: Return all data from the whois requested domain
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((whois_server, PORT))
        sock.send((domain + "\r\n").encode())

        # receive response packets
        packets = sniff(timeout=10, filter=f"tcp port {PORT} and host {whois_server}")

        for p in packets:
            payload = bytes(p[TCP].payload).decode('UTF8','replace')
            print(payload)

    except Exception as e:
        print(f"An error occured fetching the data: {e}")

    finally:
        sock.close()

#~~~~~~~~~~~~~~~~~~~    Main script   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def main(args) -> None:
    if len(args) < 2:
        print("No domain name given. Feel free to try again.")
        return

    
    try: 
        req_domain = args[1].lower()
    except: 
        print("First argument cannot be parsed correctly. Make sure it's a valid domain name.")
        return
    
    op = 0 # optinal for running a specific operation
    # 1 for CAA, 2 for DNS enum, 3 for WHOIS
    try:
        if len(args) > 2:
            op = int(args[2])
    except Exception as e:
        print("Optional second argument should be an integer.")
        return
    
    # 1.    CAA of requested domain
    if not op or op == 1:
        records = dig(req_domain)
        printCAA(records)
        print('\n')

    # 2.    DNS enumeration
    if not op or op == 2:
        printDNSmap(dnsmap(domain=req_domain, q_type="SOA"))
        print('\n')

    # 3.    WHOIS query
    if not op or op == 3:
        whoisQueryReq(domain=req_domain)

if __name__ == '__main__':
    main(argv)