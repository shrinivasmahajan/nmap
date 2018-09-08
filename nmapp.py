#Chalo shuru karte hai bina backchodi ke...
#sudo pat-get install nmap
#sudo pip tnstall python-nmap

import nmap
nm=nmap.PortScanner()
nm.scan('127.0.0.1','1-10')	#scan('ip','port range')
nm.command_line()		#for command searching
nm.all_hosts()			#jitne scan kiye aur unmese kitne up hai
nm['11.11.3.205'].state()	#nm['ip which u scanned'].state() up/down
nm['11.11.3.205'].all_protocols()	#how many ports are there ex tcp,udp,etc
nm['11.11.3.205']['MAC']	#access only one key
nm['11.11.3.205']['MAC'].keys()
nm['11.11.3.205']['MAC'].values()
nm['11.11.3.205'].has_tcp(80)
nm['11.11.3.205']['tcp'][80]



