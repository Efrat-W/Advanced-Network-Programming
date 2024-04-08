import caa_record_digger as CAA, dns_domain_mapper as DNSmap, whois as WHOIS
from sys import argv

'''
DNS toolkit, Advanced Networking final assignment
by ef-w
'''

def main(args):
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
        records = CAA.dig(req_domain)
        CAA.printCAA(records)

    # 2.    DNS enumeration
    if not op or op == 2:
        DNSmap.printDNSmap(DNSmap.dnsmap(domain=req_domain, q_type="SOA"))

    # 3.    WHOIS query
    if not op or op == 3:
        WHOIS.whoisQueryReq(domain=req_domain)

if __name__ == '__main__':
    main(argv)