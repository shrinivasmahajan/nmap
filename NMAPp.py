from nmap import *
import argparse

parser=argparse.ArgumentParser(description='This is chutiyappaa')
parser.add_argument('--host',action='store',dest='host',required=True)
parser.add_argument('--port',action='store',dest='port',required=True)
args=parser.parse_args()
ip=args.host
p=args.port

nm=nmap.PortScanner()
#ip=raw_input("Enter the ip address (xx.xx.xx.xx or xx.xx.xx.xx-yy): ")
#p=raw_input("Enter port range(x or x-y): ")
nm.scan(ip,p)

#print nm.all_hosts()
#print nm['11.11.3.205']['tcp'].keys()
#print nm['11.11.3.205']['tcp'][27]['name']

for host in nm.all_hosts():
	state=nm[host].state()	
	print '\nscanned: ',host,'\tState: ',state
	for proto in nm[host].all_protocols():
		ports=nm[host][proto].keys()		
		
		for port in ports:		
			state=nm[host][proto][port]['state']
			name= nm[host][proto][port]['name']			
			print "Port: %s\t State: %s\t Name: %s" %(port,state,name) 
			
		
