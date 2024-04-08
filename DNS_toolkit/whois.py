from scapy.all import sniff, TCP, raw
import socket

def whoisQueryReq(domain: str):
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
            #p.show()
            payload = bytes(p[TCP].payload).decode('UTF8','replace')
            raw_data = payload.split('\n')
            #print(payload)
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

        #print(whois_server)

    except Exception as e:
        print(f"An error occured: {e}")

    finally:
        #print("closing sock 1")
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
        #print(f"num of packets sniffed: {len(packets)} PHASE-2")

        for p in packets:
            payload = bytes(p[TCP].payload).decode('UTF8','replace')
            print(payload)

    except Exception as e:
        print(f"An error occured: {e}")

    finally:
        #print("closing sock 2")
        sock.close()


#whoisQueryReq("leetcode.com")
