from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR, DNSRRSOA, sniff, TCP, raw
from os import path
import socket
from sys import argv

'''
DNS toolkit, Advanced Networking final assignment
by ef-w
'''

### list of combinations from dnsmap.h manually extracted
list2 = {
"0",
"00",
"01",
"02",
"03",
"04",
"05",
"06",
"07",
"08",
"09",
"1",
"2",
"3",
"4",
"5",
"6",
"7",
"8",
"9",
"a",
"aa",
"ab",
"ac",
"access",
"accounting",
"accounts",
"ad",
"admin",
"administrator",
"ae",
"af",
"ag",
"ah",
"ai",
"aix",
"aj",
"ak",
"al",
"am",
"an",
"ao",
"ap",
"apollo",
"aq",
"ar",
"archivos",
"as",
"at",
"au",
"aula",
"aulas",
"av",
"aw",
"ax",
"ay",
"ayuda",
"az",
"b",
"ba",
"backup",
"backups",
"bart",
"bb",
"bc",
"bd",
"be",
"beta",
"bf",
"bg",
"bh",
"bi",
"biblioteca",
"billing",
"bj",
"bk",
"bl",
"blackboard",
"blog",
"blogs",
"bm",
"bn",
"bo",
"bp",
"bq",
"br",
"bs",
"bsd",
"bt",
"bu",
"bv",
"bw",
"bx",
"by",
"bz",
"c",
"ca",
"carro",
"cart",
"cas",
"catalog",
"catalogo",
"catalogue",
"cb",
"cc",
"cd",
"ce",
"cf",
"cg",
"ch",
"chat",
"chimera",
"chronos", # time server?
"ci",
"citrix",
"cj",
"ck",
"cl",
"classroom",
"clientes",
"clients",
"cm",
"cn",
"co",
"connect",
"controller",
"correoweb",
"cp",
"cpanel",
"cq",
"cr",
"cs",
"csg",
"ct",
"cu",
"customers",
"cv",
"cw",
"cx",
"cy",
"cz",
"d",
"da",
"data",
"db",
"dbs",
"dc", # domain controller?
"dd",
"de",
"demo",
"demon",
"demostration",
"descargas",
"developers",
"development",
"df",
"dg",
"dh",
"di",
"diana",
"directory",
"dj",
"dk",
"dl",
"dm",
"dmz",
"dn",
"do",
"domain",
"domaincontroller",
"domain-controller",
"download",
"downloads",
"dp",
"dq",
"dr",
"ds",
"dt",
"du",
"dv",
"dw",
"dx",
"dy",
"dz",
"e",
"ea",
"eaccess",
"eb",
"ec",
"ed",
"ee",
"ef",
"eg",
"eh",
"ei",
"ej",
"ejemplo",
"ejemplos",
"ek",
"el",
"em",
"email",
"en",
"enrutador",
"eo",
"ep",
"eq",
"er",
"es",
"et",
"eu",
"ev",
"eventos",
"events",
"ew",
"ex",
"example",
"examples",
"exchange",
"extranet",
"ey",
"ez",
"f",
"fa",
"fb",
"fc",
"fd",
"fe",
"ff",
"fg",
"fh",
"fi",
"files",
"finance",
"firewall",
"fj",
"fk",
"fl",
"fm",
"fn",
"fo",
"foro",
"foros",
"forum",
"forums",
"fp",
"fq",
"fr",
"freebsd",
"fs",
"ft",
"ftp",
"ftpd",
"fu",
"fv",
"fw",
"fx",
"fy",
"fz",
"g",
"ga",
"galeria",
"gallery",
"gateway",
"gb",
"gc",
"gd",
"ge",
"gf",
"gg",
"gh",
"gi",
"gilford",
"gj",
"gk",
"gl",
"gm",
"gn",
"go",
"gp",
"gq",
"gr",
"groups",
"groupwise",
"gs",
"gt",
"gu",
"guest",
"guia",
"guide",
"gv",
"gw",
"gx",
"gy",
"gz",
"h",
"ha",
"hb",
"hc",
"hd",
"he",
"help",
"helpdesk",
"hera",
"heracles",
"hercules",
"hf",
"hg",
"hh",
"hi",
"hj",
"hk",
"hl",
"hm",
"hn",
"ho",
"home",
"homer",
"hotspot",
"hp",
"hq",
"hr",
"hs",
"ht",
"hu",
"hv",
"hw",
"hx",
"hy",
"hypernova",
"hz",
"i",
"ia",
"ib",
"ic",
"id",
"ie",
"if",
"ig",
"ih",
"ii",
"ij",
"ik",
"il",
"im",
"images",
"imail",
"imap",
"imap3",
"imap3d",
"imapd",
"imaps",
"imgs",
"imogen",
"in",
"inmuebles",
"internal",
"interno",
"intranet",
"io",
"ip",
"ip6",
"ipsec",
"ipv6",
"iq",
"ir",
"irc",
"ircd",
"is",
"isa", #ISA proxy?
"it",
"iu",
"iv",
"iw",
"ix",
"iy",
"iz",
"j",
"ja",
"jabber",
"jb",
"jc",
"jd",
"je",
"jf",
"jg",
"jh",
"ji",
"jj",
"jk",
"jl",
"jm",
"jn",
"jo",
"jp",
"jq",
"jr",
"js",
"jt",
"ju",
"jupiter",
"jv",
"jw",
"jx",
"jy",
"jz",
"k",
"ka",
"kb",
"kc",
"kd",
"ke",
"kf",
"kg",
"kh",
"ki",
"kj",
"kk",
"kl",
"km",
"kn",
"ko",
"kp",
"kq",
"kr",
"ks",
"kt",
"ku",
"kv",
"kw",
"kx",
"ky",
"kz",
"l",
"la",
"lab",
"laboratories",
"laboratorio",
"laboratory",
"labs",
"lb",
"lc",
"ld",
"le",
"lf",
"lg",
"lh",
"li",
"library",
"linux",
"lisa",
"lj",
"lk",
"ll",
"lm",
"ln",
"lo",
"localhost",
"log",
"login",
"logon",
"logs",
"lp",
"lq",
"lr",
"ls",
"lt",
"lu",
"lv",
"lw",
"lx",
"ly",
"lz",
"m",
"ma",
"mail",
"mailgate",
"manager",
"marketing",
"mb",
"mc",
"md",
"me",
"media",
"member",
"members",
"mercury", # MX server?
"meta",
"meta01",
"meta02",
"meta03",
"meta1",
"meta2",
"meta3",
"mf",
"mg",
"mh",
"mi",
"miembros",
"minerva",
"mj",
"mk",
"ml",
"mm",
"mn",
"mo",
"mob",
"mobile",
"moodle",
"movil",
"mp",
"mq",
"mr",
"ms",
"mssql",
"mt",
"mu",
"mv",
"mw",
"mx",
"mx0",
"mx01",
"mx02",
"mx03",
"mx1",
"mx2",
"mx3",
"my",
"mysql",
"mz",
"n",
"na",
"nb",
"nc",
"nd",
"ne",
"nelson",
"neon",
"net",
"netmail",
"news",
"nf",
"ng",
"nh",
"ni",
"nj",
"nk",
"nl",
"nm",
"nn",
"no",
"novell",
"np",
"nq",
"nr",
"ns",
"ns0",
"ns01",
"ns02",
"ns03",
"ns1",
"ns2",
"ns3",
"nt",
"ntp",
"nu",
"nv",
"nw",
"nx",
"ny",
"nz",
"o",
"oa",
"ob",
"oc",
"od",
"oe",
"of",
"og",
"oh",
"oi",
"oj",
"ok",
"ol",
"om",
"on",
"online",
"oo",
"op",
"oq",
"or",
"ora",
"oracle",
"os",
"osx",
"ot",
"ou",
"ov",
"ow",
"owa",
"ox",
"oy",
"oz",
"p",
"pa",
"partners",
"pb",
"pc",
"pcanywhere",
"pd",
"pe",
"pegasus",
"pendrell",
"personal",
"pf",
"pg",
"ph",
"photo",
"photos",
"pi",
"pj",
"pk",
"pl",
"pm",
"pn",
"po",
"pop",
"pop3",
"portal",
"postgresql",
"postman",
"postmaster",
"pp", # preprod?
"ppp",
"pq",
"pr",
"preprod",
"pre-prod",
"private",
"prod",
"proxy",
"prueba",
"pruebas",
"ps",
"pt",
"pu",
"pub",
"public",
"pv",
"pw",
"px",
"py",
"pz",
"q",
"qa",
"qb",
"qc",
"qd",
"qe",
"qf",
"qg",
"qh",
"qi",
"qj",
"qk",
"ql",
"qm",
"qn",
"qo",
"qp",
"qq",
"qr",
"qs",
"qt",
"qu",
"qv",
"qw",
"qx",
"qy",
"qz",
"r",
"ra",
"ras",
"rb",
"rc",
"rd",
"re",
"remote",
"reports",
"research",
"restricted",
"rf",
"rg",
"rh",
"ri",
"rj",
"rk",
"rl",
"rm",
"rn",
"ro",
"robinhood",
"router",
"rp",
"rq",
"rr",
"rs",
"rt",
"rtr",
"ru",
"rv",
"rw",
"rx",
"ry",
"rz",
"s",
"sa",
"sales",
"sample",
"samples",
"sandbox",
"sb",
"sc",
"sd",
"se",
"search",
"secure",
"seguro",
"server",
"services",
"servicios",
"servidor",
"sf",
"sg",
"sh",
"sharepoint",
"shop",
"shopping",
"si",
"sj",
"sk",
"sl",
"sm",
"sms",
"smtp",
"sn",
"so",
"socios",
"solaris",
"soporte",
"sp", # sharepoint?
"sq",
"sql",
"squirrel",
"squirrelmail",
"sr",
"ss",
"ssh",
"st",
"staff",
"staging",
"stats",
"su",
"sun",
"support",
"sv",
"sw",
"sx",
"sy",
"sz",
"t",
"ta",
"tb",
"tc",
"td",
"te",
"test",
"tf",
"tftp",
"tg",
"th",
"ti",
"tienda",
"tj",
"tk",
"tl",
"tm",
"tn",
"to",
"tp",
"tq",
"tr",
"ts",
"tt",
"tu",
"tunnel",
"tv",
"tw",
"tx",
"ty",
"tz",
"u",
"ua",
"uat",
"ub",
"uc",
"ud",
"ue",
"uf",
"ug",
"uh",
"ui",
"uj",
"uk",
"ul",
"um",
"un",
"unix",
"uo",
"up",
"upload",
"uploads",
"uq",
"ur",
"us",
"ut",
"uu",
"uv",
"uw",
"ux",
"uy",
"uz",
"v",
"va",
"vb",
"vc",
"vd",
"ve",
"ventas",
"vf",
"vg",
"vh",
"vi",
"virtual",
"vista",
"vj",
"vk",
"vl",
"vm",
"vn",
"vnc",
"vo",
"vp",
"vpn",
"vpn1",
"vpn2",
"vpn3",
"vq",
"vr",
"vs",
"vt",
"vu",
"vv",
"vw",
"vx",
"vy",
"vz",
"w",
"wa",
"wap",
"wb",
"wc",
"wd",
"we",
"web",
"web0",
"web01",
"web02",
"web03",
"web1",
"web2",
"web3",
"webadmin",
"webct",
"weblog",
"webmail",
"webmaster",
"webmin",
"wf",
"wg",
"wh",
"wi",
"win",
"windows",
"wj",
"wk",
"wl",
"wm",
"wn",
"wo",
"wp",
"wq",
"wr",
"ws",
"wt",
"wu",
"wv",
"ww",
"ww0",
"ww01",
"ww02",
"ww03",
"ww1",
"ww2",
"ww3",
"www",
"www0",
"www01",
"www02",
"www03",
"www1",
"www2",
"www3",
"wx",
"wy",
"wz",
"x",
"xa",
"xanthus",
"xb",
"xc",
"xd",
"xe",
"xf",
"xg",
"xh",
"xi",
"xj",
"xk",
"xl",
"xm",
"xn",
"xo",
"xp",
"xq",
"xr",
"xs",
"xt",
"xu",
"xv",
"xw",
"xx",
"xy",
"xz",
"y",
"ya",
"yb",
"yc",
"yd",
"ye",
"yf",
"yg",
"yh",
"yi",
"yj",
"yk",
"yl",
"ym",
"yn",
"yo",
"yp",
"yq",
"yr",
"ys",
"yt",
"yu",
"yv",
"yw",
"yx",
"yy",
"yz",
"z",
"za",
"zb",
"zc",
"zd",
"ze",
"zeus",
"zf",
"zg",
"zh",
"zi",
"zj",
"zk",
"zl",
"zm",
"zn",
"zo",
"zp",
"zq",
"zr",
"zs",
"zt",
"zu",
"zv",
"zw",
"zx",
"zy",
"zz"}

#~~~~~~~~~~~~~~~~~~~    1 CAA dig script   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DEFAULT_DNS = "8.8.8.8"

def printCAA(records: list[str]) -> None:
    """Prints the CAA records obtained from DNS query."""

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
    
    # dnsmap.h list copied and placed at the bottom of the script
    for prefix in list2:
        yield prefix


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


def printDNSmap(hashed_domains) -> None:
    """
    Prints the DNS enumeration map.
    
    :param hashed_domains: generator yielded pairs of domain and its IP addrs.
    """
    #print("\nDNS Network Mapper")
    for domain, ip_list in hashed_domains:
        print(domain)
        for i, ip in enumerate(ip_list):
            print(f"IP address #{i+1}: {ip}")
        print('\n')



def dnsmap(domain: str, q_type=TYPE_A, dns: str=DEFAULT_DNS):
    """
    Performs DNS enumeration for the specified domain.

    :param domain (str): requested domain for DNS query.
    :param q_type (str or int): query type. Default 1.
    :param dns (str): DNS server to query. Default 8.8.8.8.
    """
    print("Processing...")

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
    print("Processing, might take a few seconds...")
    
    iana = "whois.iana.org"
    PORT = 43 # TCP port on which WHOIS listens
    TLD = '.' + domain.split('.')[-1].lower()
    whois_server = '' # not necessarily, but the main server we'll use
    name_servers = [] # in case there's no whois server result

    # scapy lfilters
    def TLDfilter(p):
        return TCP in p and TLD in str(p[TCP].payload).lower()
    

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

        # use a nserver if no whois server was obtained
        if not whois_server:
            if len(name_servers):
                whois_server = name_servers[0]
            else:
                whois_server = domain

    except Exception as e:
        print(f"An error occured: {e}")

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