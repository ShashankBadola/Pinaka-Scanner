import nmap
import sys
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m' 
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'
banner = r"""{}{}
  ____   __   _  _     __     _  _     __
 ( __ \ |  | | \| |   /  \   | |/ /   /  \
  ) __/ |  | | \  |  / __ \  |   \   /  _ \
 (__)   |__| |_|\_| (__)(__) |_|\_\ (__)(__)

======PINAKA SCANNER by Shashank Badola=======
""".format(bcolors.OKGREEN,bcolors.BOLD,bcolors.WARNING,bcolors.OKBLUE,bcolors.ENDC)

print(banner)

f=open("input.txt", 'r')
IP_address = f.readlines()
IP_address = [x.strip() for x in IP_address]
print(IP_address)
pn=input("Enter the port number:")
i=0
while i<len(IP_address):
    print(IP_address[i])
    x= nmap.PortScanner()
    x.scan(hosts=IP_address[i], ports=pn, arguments='-Pn', sudo=False)
    x.command_line()
    x.scaninfo()
    x.all_hosts()
    x[IP_address[i]].hostname()
    x[IP_address[i]].state()
    x[IP_address[i]].all_protocols()
    if('tcp' in x[IP_address[i]]):
        list(x[IP_address[i]]['tcp'].keys())
    x[IP_address[i]].all_tcp()
    x[IP_address[i]].all_udp()
    x[IP_address[i]].all_ip()
    for host in x.all_hosts():
        print('---------------------------------------------')
        print('Host: %s (%s)' % (host, x[host].hostname()))
        print('State: %s' % x[host].state())
        for proto in x[host].all_protocols():
            print('----------------------')
            print('Protocol : %s' % proto)
            lport = list(x[host][proto].keys())
            lport.sort()
            for port in lport:
                print('port: %s\tstate : %s' % (port, x[host][proto][port]['state']))
                print('---------------------------------------------------')
    print(x.csv())
    i=i+1
input("Press any key to Exit")
