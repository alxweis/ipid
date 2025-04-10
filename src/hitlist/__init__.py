import os

DIR_PATH = os.path.dirname(os.path.abspath(__file__))

ICMP_IP_SCANNER = os.path.join(DIR_PATH, "ip_scan/icmp/scan.sh")
TCP_IP_SCANNER = os.path.join(DIR_PATH, "ip_scan/tcp/scan.sh")
UDP_IP_SCANNER = os.path.join(DIR_PATH, "ip_scan/udp/scan.sh")

HTTP_OS_SCANNER = os.path.join(DIR_PATH, "os_scan/http.sh")
DNS_OS_SCANNER = os.path.join(DIR_PATH, "os_scan/dns.sh")
