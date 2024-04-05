from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR

DEFAULT_DNS = "8.8.8.8"
# auxiliary function to recognize type of request by input
def is_IP(req):
    if not req:
        return False
    for i in req.split('.'):
        if not i.isdigit():
            return False
    return True


def dig(domain, q_type="CAA", dns=DEFAULT_DNS):
    # create DNS query packet
    res = sr1(
            IP(dst=dns)/
            UDP(dport=53)/
            DNS(rd=1, qd=DNSQR(qname=domain, qtype=q_type)),
            verbose=0
            )
    
    print(res.show())

    cutoff = len('\x00\x05issue')
    addr_res = []
    dnsrr_count = res[DNS].ancount
    for i in range(dnsrr_count):
        data = res[DNSRR][i].rdata
        if q_type=='CAA':
            data = data.decode()[cutoff:]
            data = data.split(';')  # in case of irrelevant added info
            addr_res.append(data[0])
    return addr_res

records = dig("leetcode.com")
print("CAA records:")
for rec in records:
    print(rec)