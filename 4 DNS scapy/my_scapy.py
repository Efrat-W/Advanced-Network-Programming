from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR

def nslookup_DEMO(domain, query_type='A'):
    if query_type == 'PTR':
        domain = '.'.join(reversed(domain.split('.'))) + '.in-addr.arpa'
    response = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype=query_type)), verbose=0)
    for i in range(response[DNS].ancount):
        if response[DNSRR][i].type == 1:
            print(f'IP: {response[DNSRR][i].rdata}')
        elif response[DNSRR][i].type == 5:
            print(f'Canonical Name: {response[DNSRR][i].rdata}')
        elif response[DNSRR][i].type == 12:
            print(f'PTR: {response[DNSRR][i].rdata}')

# auxiliary function to recognize type of request by input
def is_IP(req):
    if not req:
        return False
    for i in req.split('.'):
        if not i.isdigit():
            return False
    return True


def nslookup(domain, q_type="A"):
    if q_type == "PTR":
        domain = ".".join(domain.split('.')[::-1]) + ".in-addr.arpa"
    res = sr1(
            IP(dst="8.8.8.8")/
            UDP(dport=53)/
            DNS(rd=1, qd=DNSQR(qname=domain, qtype=q_type)),
            verbose=0
            )
    #print(res.show())
    #return res[DNSRR][0].rdata
    addr_res = []
    dnsrr_count = res[DNS].ancount
    for i in range(dnsrr_count):
        data = res[DNSRR][i].rdata
        if q_type=='PTR':
            addr_res.append(data.decode()[:-1])
        else:
            addr_res.append(data)
    return addr_res


def main():
    print("""Enter either a domain name to get the corresponding IP address,
or an IP address to get the corresponding domain name:""")
    while True:
        req = input(">>> ")
        res = nslookup(req, "PTR") if is_IP(req) else nslookup(req)
        print(f"There were {len(res)} results:")
        for i in range(len(res)):
            print(f"{i+1}.\t {res[i]}")
        print()

if __name__ == '__main__':
    main()