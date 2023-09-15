import psutil
import dpkt
import os
import time
import sys
import datetime
import socket
import subprocess
import requests
import json
#made by daddy dolphin
dump_directory = str(sys.argv[1])
IP_Report_Directory = str(sys.argv[2])
interface = str(sys.argv[3])
packet_threshold = int(sys.argv[4])



textart = """
                                  __
                               _.-~  )
                    _..--~~~~,'   ,-/     _
                 .-'. . . .'   ,-','    ,' )
               ,'. . . _   ,--~,-'__..-'  ,'
             ,'. . .  (@)' ---~~~~      ,'
            /. . . . '~~             ,-'
           /. . . . .             ,-'
          ; . . . .  - .        ,'
         : . . . .       _     /
        . . . . .          `-.:
       . . . ./  - .          )
      .  . . |  _____..---.._/ _____
~---~~~~----~~~~             ~~
"""
os.system("clear")
print(f"\033[94m{textart}")

def maincheck():
	while True:
		# Caluculating Packets Per Second, and Megabits per second ( Rounded to the nearest whole number ) 
		packets_1 = int(psutil.net_io_counters().packets_recv)
		Bytes_1 = round(int(psutil.net_io_counters().bytes_recv) / 125000)
		time.sleep(1)
		packets_2 = int(psutil.net_io_counters().packets_recv)
		Bytes_2 = round(int(psutil.net_io_counters().bytes_recv) / 125000)
		mbps = Bytes_2 - Bytes_1
		pps = packets_2 - packets_1
		cpu = psutil.cpu_percent()
		print(f"\033[31mmbps: \033[37m{Bytes_2 - Bytes_1}\n\033[31mPackets Per Second: \033[37m{packets_2 - packets_1}\n\033[31mCPU Usage: \033[37m {psutil.cpu_percent()}%")
		for i in range(3):
			sys.stdout.write('\x1b[1A')
			sys.stdout.write('\x1b[2K') # Just to clear where it lists mbps, pps, and cpu percentage. 
		if (packets_2 - packets_1) > packet_threshold:
			dump(mbps, pps, cpu) # Auto TCPDUMP

def dump(mbps, pps, cpu):
	print(f"\nAttack Detected: {pps} Packets Per Second | {mbps} Megabits Per Second\n")
	date = datetime.datetime.now().strftime("%Y%m%d-%H%M-%S")
	subprocess.getoutput(f"tcpdump -i {interface} -n -s0 -c 2000 -w {dump_directory}/dump.{date}.pcap") # You can change the 2000 to whatever is prefered for number of packets in a capture. 
	print(f"Attack Captured: {dump_directory}/dump.{date}.pcap\n")
	Analyze(mbps, pps, cpu, date)

def Analyze(mbps, pps, cpu, date):
	Unique_IPS = 0
	Source_Ports = []
	Source_IPs = []
	Destination_Ports = []
	tcp_flags = []
	Protocol = []
	Destination_IP = []
	Repeating_Source_IPs = []
	Pcapfile = open(f"{dump_directory}/dump.{date}.pcap", "rb")  # Opening .pcap file as Raw Binary  {dump_directory}/dump.{date}.pcap
	pcap = dpkt.pcap.Reader(Pcapfile) # Reading pcap file with DPKT 
	for ts, buf in pcap:
		eth=dpkt.ethernet.Ethernet(buf)
		if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
		   continue
		ip=eth.data
		tcp = ip.data
		if ip.p==dpkt.ip.IP_PROTO_TCP:
			tcp = ip.data
			Source_Ports.append(str(tcp.sport))
			Destination_Ports.append(str(tcp.dport))
			Protocol.append("TCP")
			if ((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)): # and (tcp.flags & dpkt.tcp.TH_ACK)):
   				tcp_flags.append("TCP SYN,ACK")
			elif tcp.flags & dpkt.tcp.TH_SYN: # The rest of this cluster fuck of shit is somewhat self explanatory
			   tcp_flags.append("TCP SYN")
			elif ((tcp.flags & dpkt.tcp.TH_RST) and (tcp.flags & dpkt.tcp.TH_ACK)):
				tcp_flags.append("TCP RST,ACK")
			elif ((tcp.flags & dpkt.tcp.TH_PUSH) and (tcp.flags & dpkt.tcp.TH_ACK)):
				tcp_flags.append("TCP PSH,ACK")
			elif ((tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_URG)):
				tcp_flags.append("TCP URG,ACK")
			elif tcp.flags & dpkt.tcp.TH_ACK:
			   tcp_flags.append("TCP ACK")
			elif tcp.flags & dpkt.tcp.TH_RST:
			   tcp_flags.append("TCP RST")
			elif tcp.flags & dpkt.tcp.TH_PUSH:
				tcp_flags.append("TCP PSH")
			elif tcp.flags & dpkt.tcp.TH_FIN:
				tcp_flags.append("TCP FIN")
			elif tcp.flags & dpkt.tcp.TH_URG:
				tcp_flags.append("TCP URG")
			elif tcp.flags & dpkt.tcp.TH_CWR:
				tcp_flags.append("TCP CWR")
			elif tcp.flags & dpkt.tcp.TH_ECE:
				tcp_flags.append("TCP ECE")
		elif ip.p==dpkt.ip.IP_PROTO_UDP:
			Protocol.append("UDP")
			UDP = ip.data
			try:

				Source_Ports.append(str(UDP.sport))
				Destination_Ports.append(str(UDP.dport))
			except:
				pass
		elif ip.p==dpkt.ip.IP_PROTO_ICMP:
			Protocol.append("ICMP")
		else:
			Protocol.append("IPv4 Fragment")
		Destination_IP.append(str(socket.inet_ntoa(ip.dst)))
		if socket.inet_ntoa(ip.src) not in Source_IPs:
			Source_IPs.append(socket.inet_ntoa(ip.src))
			Unique_IPS +=1
		else:
			Repeating_Source_IPs.append(socket.inet_ntoa(ip.src))
	if "TCP" in max(Protocol, key = Protocol.count): # Seing Which Protocol Appeared The Most In Our List
		Attack_type = "TCP"
	elif "UDP" in max(Protocol, key = Protocol.count):
		Attack_type = "UDP"
	elif "ICMP" in max(Protocol, key = Protocol.count):
		Attack_type = "ICMP"
	elif "IPv4 Fragment" in max(Protocol, key = Protocol.count):
		Attack_type = "IPv4 Fragment"
	else:
		Attack_type = "Unknown"
	srcport = str(max(Source_Ports, key = Source_Ports.count))
	dstport = str(max(Destination_Ports, key = Destination_Ports.count))
	global Attack_flags
	if "TCP" in Attack_type:
		Attack_flags = str(max(tcp_flags, key = tcp_flags.count))
	else:
		Attack_flags = "NA"
	if (srcport == "443") & (Attack_type == "TCP") & (Attack_flags == "TCP SYN,ACK"):
	 vector = "Killall"
	elif (srcport == "80") & (Attack_type == "TCP") & (Attack_flags == "TCP SYN,ACK"):
	  vector = "Killall"
	elif (srcport == "37810") & (Attack_type == "UDP"):
	  vector = "DVR"
	elif (srcport == "10001") & (Attack_type == "UDP"):
	  vector = "Ubiquiti"
	elif (srcport == "11211") & (Attack_type == "UDP"):
	  vector = "MemcacheD"
	elif (srcport == "1194") & (Attack_type == "UDP"):
	  vector = "OpenVPN Reflection"
	elif (srcport == "137") & (Attack_type == "UDP"):
	  vector = "NetBIOS"
	elif (srcport == "161") & (Attack_type == "UDP"):
	  vector = "SNMP"
	elif (srcport == "1900") & (Attack_type == "UDP"):
	  vector = "SSDP"
	elif (srcport == "30120") & (Attack_type == "UDP"):
	  vector = "FiveM"
	elif (srcport == "30718") & (Attack_type == "UDP"):
	  vector = "Lantronix IOT"
	elif (srcport == "32414") & (Attack_type == "UDP"):
	  vector = "Plex Media Server"
	elif (srcport == "3283") & (Attack_type == "UDP"):
	  vector = "ARD"
	elif (srcport == "33848") & (Attack_type == "UDP"):
	  vector = "Jenkins Hudson Amplification"
	elif (srcport == "3389") & (Attack_type == "UDP"):
	  vector == "RDP"
	elif (srcport == "3478") & (Attack_type == "UDP"):
	  vector = "STUN"
	elif (srcport == "3702") & (Attack_type == "UDP"):
	  vector = "WSD"
	elif (srcport == "5351") & (Attack_type == "UDP"):
	  vector = "NATPMP"
	elif (srcport == "53") & (Attack_type == "UDP"):
	  vector = "DNS"
	elif (srcport == "5353") & (Attack_type == "UDP"):
	  vector = "MDNS"
	elif (srcport == "123") & (Attack_type == "UDP"):
	  vector = "NTP"
	elif (srcport == "5683") & (Attack_type == "UDP"):
	  vector = "COAP"
	elif (srcport == "389") & (Attack_type == "UDP"):
  	  vector = "CLDAP"
	elif (srcport == "8080") & (Attack_type == "TCP"):
	  vector = "Speedtest"
	elif (srcport == "22") & (Attack_type == "TCP"):
	  vector = "RAIL"
	elif (srcport == "109") & (Attack_type == "TCP"):
		vector = "BGP Flood"
	elif (srcport == "27015") & (Attack_type == "UDP"):
		vector = "Tsource Engine Query Flood"
	else:
	  vector = "Unknown"
	if "TCP" in Attack_type:
		Attack_type = str(max(tcp_flags, key = tcp_flags.count))
	Destination_IP = str(max(Destination_IP, key = Destination_IP.count))
	Max_Source_IP = str(max(Repeating_Source_IPs, key = Repeating_Source_IPs.count))
	IP_List = open(f"{IP_Report_Directory}/{date}.txt", "w")
	for IPs in Source_IPs:
		IP_List.write(f"{IPs} \n")
	IP_List.close()
	secondcheck(Attack_type, vector, Destination_IP, Unique_IPS, Max_Source_IP, dstport, Source_IPs)

def secondcheck(Attack_type, vector, Destination_IP, Unique_IPS, Max_Source_IP, dstport, Source_IPs):
	Timer = 0
	mbps = 0
	mbpspeak = []
	asns = []
	orgs = []
	while True:
		Timer +=1
		packets_1 = int(psutil.net_io_counters().packets_recv)
		Bytes_1 = round(int(psutil.net_io_counters().bytes_recv) / 125000)
		time.sleep(1)
		packets_2 = int(psutil.net_io_counters().packets_recv)
		Bytes_2 = round(int(psutil.net_io_counters().bytes_recv) / 125000)
		print(f"\033[31mmbps: \033[37m{Bytes_2 - Bytes_1}\n\033[31mPackets Per Second: \033[37m{packets_2 - packets_1}\n\033[31mCPU Usage: \033[37m {psutil.cpu_percent()}%\n\033[31mAttack Type: \033[37m{Attack_type}\n\033[31mAttack Vector: \033[37m{vector}\n\033[31mDestination IP: \033[37m{Destination_IP}:{dstport}\n\033[31mMost Frequent Source IP: \033[37m{Max_Source_IP}\n\033[31mUnique IPs: \033[37m{Unique_IPS}\n")
		mbps += Bytes_2 - Bytes_1
		mbpspeak.append(Bytes_2 - Bytes_1)
		for i in range(9):
			sys.stdout.write('\x1b[1A')
			sys.stdout.write('\x1b[2K')

		if packet_threshold > (packets_2 - packets_1):

			response = requests.post('https://app.ipapi.co/bulk/', data={'q':", ".join(Source_IPs).replace("'",""), 'output': 'json'})
			info = json.loads(response.text)
			info = info["data"]
			for i in info:
				asn = i["asn"]
				org = i["org"]
				if asn in asns:
					pass
				else:
					asns.append(asn)
					orgs.append(org)

			asns.append("NA")
			orgs.append("NA")
			print(f"\nThe Last Attack lasted {Timer} Seconds, The Attack Type Was {Attack_type} / {vector} on {Destination_IP}:{dstport}, The Attack Peaked Around {max(mbpspeak)}Mbit/s, Averaged Around {round((mbps) / Timer)} Mbit/s, And Came From About {len(asns)} Different Networks; The Most Frequent One Being {max(asns, key = asns.count)}/{max(orgs, key = orgs.count)}\n")
			maincheck()

try:
	maincheck()
except KeyboardInterrupt:
	os.system("clear")
	sys.exit()


