import socket, requests
import concurrent.futures
from urllib.parse import urlparse
import subprocess
import re
import platform
from utils.banner import info, warning, danger, success

COMMON_PORTS_WITH_SERVICES_EXTENDED = [
    (1,    "tcpmux",        "TCP Port Service Multiplexer"),
    (7,    "echo",          "Echo Protocol (diagnostic)"),
    (20,   "FTP-data",      "FTP data transfer"),
    (21,   "FTP",           "File Transfer Protocol (control)"),
    (22,   "SSH",           "Secure Shell"),
    (23,   "Telnet",        "Telnet (insecure remote shell)"),
    (25,   "SMTP",          "Simple Mail Transfer Protocol"),
    (37,   "time",          "Time Protocol"),
    (53,   "DNS",           "Domain Name System"),
    (67,   "DHCP-server",   "DHCP server (UDP)"),
    (68,   "DHCP-client",   "DHCP client (UDP)"),
    (69,   "TFTP",          "Trivial File Transfer Protocol (UDP)"),
    (80,   "HTTP",          "HyperText Transfer Protocol"),
    (81,   "HTTP-alt",      "Alternate HTTP (common for dev)"),
    (88,   "Kerberos",      "Kerberos authentication"),
    (110,  "POP3",          "Post Office Protocol v3"),
    (111,  "rpcbind",       "rpcbind / portmapper (RPC)"),
    (123,  "NTP",           "Network Time Protocol (UDP)"),
    (135,  "MS-RPC",        "Microsoft RPC/epmap"),
    (137,  "NetBIOS-NS",    "NetBIOS name service (UDP)"),
    (138,  "NetBIOS-DGM",   "NetBIOS datagram service (UDP)"),
    (139,  "NetBIOS-SSN",   "NetBIOS session service (SMB over NetBIOS)"),
    (143,  "IMAP",          "Internet Message Access Protocol"),
    (161,  "SNMP",          "Simple Network Management Protocol (UDP)"),
    (162,  "SNMP-trap",     "SNMP Trap (UDP)"),
    (179,  "BGP",           "Border Gateway Protocol"),
    (389,  "LDAP",          "Lightweight Directory Access Protocol"),
    (443,  "HTTPS",         "HTTP Secure (TLS)"),
    (445,  "SMB",           "Server Message Block (Windows file-sharing)"),
    (465,  "SMTPS",         "SMTPS / SMTP over SSL (legacy)"),
    (514,  "Syslog",        "Syslog (UDP/TCP)"),
    (546,  "DHCPv6-client", "DHCPv6 client (UDP)"),
    (563,  "NNTP-over-SSL", "NNTP over SSL (Usenet secure)"),
    (587,  "SMTP-submission","SMTP message submission (MTA client -> MTA)"),
    (631,  "IPP",           "Internet Printing Protocol"),
    (636,  "LDAPS",         "LDAP over TLS/SSL"),
    (873,  "rsync",         "rsync file sync"),
    (989,  "FTPS-data",     "FTPS data (implicit TLS)"),
    (990,  "FTPS",          "FTPS control (implicit TLS)"),
    (993,  "IMAPS",         "IMAP over SSL"),
    (995,  "POP3S",         "POP3 over SSL"),
    (1080, "SOCKS",         "SOCKS proxy"),
    (1194, "OpenVPN",       "OpenVPN (commonly UDP)"),
    (1433, "MSSQL",         "Microsoft SQL Server (TCP)"),
    (1434, "MSSQL-UDP",     "MSSQL Browser (UDP)"),
    (1521, "Oracle",        "Oracle DB listener"),
    (1701, "L2TP",          "Layer 2 Tunneling Protocol"),
    (2049, "NFS",           "Network File System"),
    (2082, "cPanel",        "cPanel (WHM/cPanel default ports)"),
    (2083, "cPanel-SSL",    "cPanel over SSL"),
    (2181, "Zookeeper",     "Apache Zookeeper"),
    (2375, "Docker-API",    "Docker remote API (insecure, TCP)"),
    (2376, "Docker-API-TLS","Docker remote API (TLS)"),
    (27017,"MongoDB",       "MongoDB (default)"),
    (28017,"MongoDB-HTTP",  "MongoDB HTTP status interface (legacy)"),
    (3306, "MySQL",         "MySQL database"),
    (3389, "RDP",           "Remote Desktop Protocol (Windows)"),
    (3690, "Subversion",    "SVN (svnserve)"),
    (4000, "SimpleBus",     "Commonly used by custom apps"),
    (4444, "metasploit",    "Often used by metasploit listener (lab)"),
    (5000, "Flask/Dev",     "Common dev servers (Flask, Gunicorn)"),
    (5060, "SIP",           "SIP (VoIP, UDP/TCP)"),
    (5061, "SIPS",          "SIP over TLS"),
    (5432, "PostgreSQL",    "PostgreSQL database"),
    (5601, "Kibana",        "Kibana web UI (ELK stack)"),
    (5900, "VNC",           "Virtual Network Computing (remote desktop)"),
    (6000, "X11",           "X Window System (X11)"),
    (6379, "Redis",         "Redis key-value store"),
    (6667, "IRC",           "Internet Relay Chat"),
    (6881, "BitTorrent",    "BitTorrent (DHT/peer)"),
    (7000, "Cassandra",     "Cassandra internode / default UI ports"),
    (8080, "HTTP-Alt",      "Alternative HTTP (proxy/dev)"),
    (8200, "Vault",         "HashiCorp Vault"),
    (8443, "HTTPS-Alt",     "Alternative HTTPS / admin consoles"),
    (9000, "php-fpm",       "php-fpm or dev UIs (often)"),
    (9200, "Elasticsearch", "Elasticsearch HTTP API"),
    (11211,"Memcached",     "Memcached caching service"),
    (27018,"MongoDB-alt",   "MongoDB alternate port"),
]

def get_os_by_ttl(domain):
    print(f"{info()} Melakukan ping untuk analisis TTL...")
    try:
        system_os = platform.system().lower()
        if system_os == "windows":
            command = ["ping", "-n", "1", domain]
        else:
            command = ["ping", "-c", "1", domain]

        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        
        ttl_match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
        
        if not ttl_match:
            return "Tidak dapat menentukan TTL."

        ttl = int(ttl_match.group(1))

        if 60 <= ttl <= 64:
            return "Kemungkinan besar Linux / Unix"
        elif 120 <= ttl <= 128:
            return "Kemungkinan besar Windows"
        else:
            return f"Tidak pasti (TTL={ttl})"

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "Gagal melakukan ping ke target."
    except Exception as e:
        return f"Error saat ping: {e}"
    
def check_case_sensitivity(target_url):
    print(f"{info()} Memeriksa case-sensitivity path...")
    
    common_paths = ["/robots.txt", "/favicon.ico", "/sitemap.xml"]
    parsed_url = urlparse(target_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    path_to_test = None
    original_response_status = 0

    for path in common_paths:
        try:
            res = requests.head(base_url + path, timeout=3, allow_redirects=True)
            if res.status_code == 200:
                path_to_test = path
                original_response_status = res.status_code
                break
        except requests.RequestException:
            continue

    if not path_to_test:
        return "Tidak dapat menemukan file umum untuk diuji (e.g., robots.txt)."

    try:
        swapped_case_path = "".join(c.lower() if c.isupper() else c.upper() for c in path_to_test)
        
        url_swapped = base_url + swapped_case_path
        res_swapped = requests.head(url_swapped, timeout=3, allow_redirects=True)

        if original_response_status == 200 and res_swapped.status_code == 200:
            return f"Kemungkinan besar Windows (case-insensitive, diuji pada '{path_to_test}')"
        elif original_response_status == 200 and res_swapped.status_code != 200:
            return f"Kemungkinan besar Linux / Unix (case-sensitive, diuji pada '{path_to_test}')"
        else:
            return "Tidak dapat menentukan (respons awal tidak 200)."

    except requests.RequestException:
        return "Gagal saat memeriksa case-sensitivity."

def get_headers(target_url, level):
    print(f"{info()} Mengambil header HTTP...")
    try:
        response = requests.head(target_url, timeout=5, allow_redirects=True)
        
        print(f"{success()} Header Ditemukan:")
        important_headers = ['Server', 'X-Powered-By', 'Content-Type', 'Set-Cookie']
        if level == "EASY":
            for header in important_headers:
                if header in response.headers:
                    print(f"    - {header}: {response.headers[header]}")
        if level == "HARD":
            for key, value in response.headers.items():
                print(f"    - {key}: {value}")

    except requests.RequestException as e:
        print(f"{warning()} Gagal mengambil header: {e}")

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def check_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            return port
    return None

def scan_ports(ip_address):
    open_ports = []
    ports_to_scan = [p[0] for p in COMMON_PORTS_WITH_SERVICES_EXTENDED] # Ambil hanya nomor port untuk dipindai
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(check_port, ip_address, port): port for port in ports_to_scan}
        
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result is not None:
                open_ports.append(result)
                
    return sorted(open_ports)

def run_identifier(target_url, level):
    try:
        domain = urlparse(target_url).netloc
    except Exception:
        print(f"{warning()} URL tidak valid.")
        return
    
    print(f"{info()} Memulai identifikasi untuk: {domain}")
    ip_address = get_ip_address(domain)
    if not ip_address:
        print(f"{warning()} Gagal mendapatkan alamat IP untuk {domain}")
        return
    print(f"{success()} Alamat IP: {ip_address}")

    print(f"\n{info()} Memulai OS Fingerprinting...")
    ttl_result = get_os_by_ttl(domain)
    print(f"{success()} Hasil Analisis TTL: {ttl_result}")
    
    case_result = check_case_sensitivity(target_url)
    print(f"{success()} Hasil Case-Sensitivity: {case_result}")

    print("")

    get_headers(target_url, level)

    print("")

    print(f"{info()} Memindai port-port umum...")
    open_ports = scan_ports(ip_address)
    if open_ports:
        print(f"{success()} Port Terbuka Ditemukan:")
        port_map = {p[0]: f"({p[1]}) - {p[2]}" for p in COMMON_PORTS_WITH_SERVICES_EXTENDED}
        for port in open_ports:
            service_name = port_map.get(port, "Unknown")
            print(f"    - Port {port} {service_name}")
    else:
        print(f"{danger()} Tidak ada port umum yang ditemukan terbuka.")