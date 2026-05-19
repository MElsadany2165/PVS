# services.py - port/service mappings and scan presets
#
# I pulled most of these from IANA's service name registry + nmap's
# nmap-services file. Not exhaustive but covers the stuff you'll
# actually encounter in real scans.

# port -> service name (the ones people actually care about)
WELL_KNOWN_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",  # SMB over TCP
    465: "smtps",
    514: "syslog",
    515: "printer",
    587: "submission",    # mail submission
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1434: "mssql-m",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9090: "web-admin",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Scan presets - based on nmap's top ports analysis
# (frequency-based, not just sequential)
PORT_PRESETS = {
    # quick and dirty - good for a fast check
    "top20": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    ],

    # covers most things you'd find on a typical network
    "top100": [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110,
        111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444,
        445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873,
        990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
        1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
        3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432,
        5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
        8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153,
        49154, 49155, 49156, 49157,
    ],

    # common services including databases, caches, etc.
    "common": [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137,
        138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587,
        636, 993, 995, 1080, 1433, 1434, 1521, 1723, 2049, 3306, 3389,
        5060, 5432, 5900, 5901, 6379, 8000, 8080, 8443, 8888, 9090, 9200,
        9300, 11211, 27017, 27018, 28017,
    ],

    # Enterprise-grade preset (Active Directory, databases, DevOps tools, virtualization)
    "enterprise": [
        20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 111, 123, 135, 137,
        138, 139, 143, 161, 162, 389, 443, 445, 465, 514, 515, 548, 587,
        636, 873, 993, 995, 1080, 1433, 1434, 1521, 1723, 1883, 2049, 2181,
        2375, 2376, 3000, 3306, 3389, 5000, 5060, 5432, 5672, 5900, 5901,
        5985, 5986, 6379, 6443, 8000, 8080, 8081, 8082, 8140, 8200, 8443,
        8500, 8883, 8888, 9000, 9090, 9092, 9100, 9200, 9300, 9443, 9999,
        10250, 11211, 15672, 27017, 27018, 50000
    ],
}
