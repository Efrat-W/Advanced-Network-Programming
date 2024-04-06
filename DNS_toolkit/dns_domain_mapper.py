from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR
from os import path
from dnsmap import list2
#from time import sleep

DEFAULT_DNS = "8.8.8.8"

TYPE_A = 1 # A (1) for IPv4

def extract_prefixes():
    file_path = path.dirname(path.abspath(__file__))
    wordlist_path = path.join(file_path, "wordlist_TLAs.txt")

    with open(wordlist_path, 'r') as wordlist:
        for prefix in wordlist:
            yield prefix.strip()
    
    # dnsmap.h list, manually exported into dnsmap.py
    for prefix in list2:
        yield prefix



def dnsmap(domain, q_type=TYPE_A, dns=DEFAULT_DNS):
    for pref in extract_prefixes():
        # create DNS query packet
        new_domain = pref + '.' + domain
        res = sr1(
                IP(dst=dns)/
                UDP(dport=53)/
                DNS(rd=1, qd=DNSQR(qname=new_domain, qtype=q_type)),
                verbose=0,
                timeout=5
                )
        
        if res and res[DNS].ancount:
            #print(res.show())
            print(new_domain)
            for i in range(res[DNS].ancount):
                dnsrr = res[DNSRR][i]
                if dnsrr.type == TYPE_A: # for IPv4
                    print(f"IP address #{i+1}: {dnsrr.rdata}")
                    
            

dnsmap("jct.ac.il")