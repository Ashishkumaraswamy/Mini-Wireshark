from threading import Thread
from scapy.all import *
import time
from os import system

def display_title():
    system("cls")
    print("\t\t-----------------------------------")
    print("\t\t\t  MINI WIRESHARK")
    print("\t\t-----------------------------------")

def welcome_screen():
    display_title()
    print("\n\n\n\t\t\tWelcome to Wireshark\n")
    print("\n\t\t\t   1 - Start new\n\t\t\t   2 - Load\n\t\t\t   3 - Exit")
    choice=int(input("\n\n\t\t\tEnter your choice? "))
    if choice==1:
        interface()
    elif choice==2:
        load()
    else:
        exit()

def interface():
    display_title()
    print("\n\nSelect the newtork inteface to be used to sniff packets:\n")
    show_interfaces()
    netindex=input("\n\nEnter the index of the newtork interface to snip packets:  ")
    iface=chosen_interface(netindex)
    if iface==-1:
        system("cls")
        print("\n\n\n\t\t\t**Enter a valid IFACE index from the list shown**\t")
        time.sleep(2)
        welcome_screen()
    else:
        snip_page(None,iface)

def options(pkts=None,iface=None):
    print("\n\n\t\t\t\t\tOptions:\n\n 1 -> Capture packets again\t2 -> Examine a captured packet\t   3 -> Save session\t  4 -> Exit session\n\n")
    choice=int(input("Enter your choice? "))
    if choice==1:
        snip_page(None,iface)
    elif choice==2:
        examine(pkts)
    elif choice==3:
        save(pkts)
    else:
        welcome_screen()

def valid_filter(filter):
    flag=True
    filter_list=['tcp','ip','arp','icmp','udp']
    f=filter.split(" ")
    if len(f)>1 and len(f)%2==0:
        flag=False
        return flag 
    for i in range(len(f)):
        if i%2 != 0:
            if f[i] == 'or' or f[i] == 'and':
                flag=True
            else:
                flag=False
        elif f[i] not in filter_list:
            flag=False
    return flag

def snip_page(current_filter=None,iface=None):
    system("cls")
    display_title()
    if current_filter==None:
        current_filter=str(input("\nEnter the filter name:  "))
        current_filter=current_filter.lower()
        if valid_filter(current_filter):
            snip_page(current_filter,iface)
        else:
            system("cls")
            display_title()
            print("\n\n\t\t*Enter a proper filter option*\t")
            time.sleep(2)
            snip_page(None,iface)
    else:
        print("\t\t\nCurrent Filter   :   ",current_filter,"\n")
        pkts=sniff_packets(iface,current_filter)
        print_packets(pkts)
        options(pkts,iface)

def print_packets(pkts):
    print("\t\t\tPACKETS\n")
    print("S.No\t   Source\t\t  Destination\t\t Type\tLength\n")
    s=20
    for i in range(len(pkts)):
        tl=top_layer(pkts[i]).upper()
        if tl!='ARP':
            print(i+1,"\t",pkts[i][IP].src," "*(s-len(pkts[i][IP].src)),"\t",pkts[i][IP].dst," "*(s-len(pkts[i][IP].dst)),"\t",tl,"\t",len(pkts[i]))
        else:
            print(i+1,"\t",pkts[i].src," "*(s-len(pkts[i].src)),"\t",pkts[i].dst," "*(s-len(pkts[i].dst)),"\t",tl,"\t",len(pkts[i]))

def sniff_packets(iface,filter):
    pkts=sniff(iface=iface,count=10,filter=filter,timeout=8)
    if(len(pkts)==0):
        print("\n\n\tNo packets captured !!")
        time.sleep(3)
        snip_page(None,iface)
    return pkts

def top_layer(packet):
    while packet.payload and packet.payload.name!='Raw':
        packet=packet.payload
        layer=packet.name
    return layer
    
def examine(pkts):
    display_title()
    print("\n\n")
    print_packets(pkts)
    n=int(input("\n\nEnter the packet number to examine: "))
    system("cls")
    display_title()
    print("\n\n")
    for i in range(0,4):
        if i==0:
            print("Frame :",len(pkts[n-1])," bytes on wire (",len(pkts[n-1])*8," bits), ",len(pkts[n-1])," bytes captured (",len(pkts[n-1])*8,"bits)\n")
        if i==1:
            print("Ethernet Layer 2, Src:",pkts[n-1].src," Dst:",pkts[n-1].dst)
            print("  >Destination:       ",pkts[n-1].dst)
            print("  >Source:            ",pkts[n-1].src)
            print("  >Type:              ",pkts[n-1].type,"\n")
        if i==2:
            if pkts[n-1].haslayer(TCP):
                print("Internet Protocol Version 4, Src:",pkts[n-1][IP].src,", Dst:",pkts[n-1][IP].dst)
                print("  >Version:       ",pkts[n-1][IP].version)
                print("  >IHL:           ",pkts[n-1][IP].ihl)
                print("  >Total Length:  ",pkts[n-1][IP].len)
                print("  >Identification:",pkts[n-1][IP].id)
                print("  >TTL:           ",pkts[n-1][IP].ttl)
                print("  >protocol:      ",pkts[n-1][IP].proto,"\n")
            if pkts[n-1].haslayer(ARP):
                op=pkts[n-1][ARP].op
                if op==1:
                    opcode="request"
                else:
                    opcode="response"
                print("Address Resolution Protocol (",opcode,")")
                print("  >Hardware Type:     ",pkts[n-1][ARP].hwtype)
                print("  >Hardware Size:     ",pkts[n-1][ARP].hwlen)
                print("  >Protocol Size:     ",pkts[n-1][ARP].plen)
                print("  >Opcode:            ",opcode," (",pkts[n-1][ARP].id,")")
                print("  >Sender MAC Address:",pkts[n-1][ARP].hwsrc)
                print("  >Sender IP Address: ",pkts[n-1][ARP].psrc)
                print("  >Target MAC Address:",pkts[n-1][ARP].hwdst)
                print("  >Target IP Address: ",pkts[n-1][ARP].pdst)
                break
        if i==3:
            if pkts[n-1].haslayer(TCP):
                print("Transmission Control Protocol, Src Port:",pkts[n-1][TCP].sport," Dst Port:",pkts[n-1][TCP].dport)
                print("  >Source Port:      ",pkts[n-1][TCP].sport)
                print("  >Destination Port: ",pkts[n-1][TCP].dport)
                print("  >Sequence Number:  ",pkts[n-1][TCP].seq)
                print("  >Window:           ",pkts[n-1][TCP].window,"\n")
            elif pkts[n-1].haslayer(UDP):
                print("User Datagram Protocol, Src Port:",pkts[n-1][UDP].sport," Dst Port:",pkts[n-1][UDP].dport)
                print("  >Source Port:      ",pkts[n-1][UDP].sport)
                print("  >Destination Port: ",pkts[n-1][UDP].dport)
                print("  >Length:           ",pkts[n-1][UDP].len)
                print("  >Checksum:         ",pkts[n-1][UDP].chksum,"\n")
            elif pkts[n-1].haslayer(ICMP):
                print("Internet Control Message Protocol")
                print("  >Type:     ",pkts[n-1][ICMP].type)
                print("  >Code:     ",pkts[n-1][ICMP].code)
                print("  >Checksum: ",pkts[n-1][ICMP].seq,"\n")
    print("\n\n")
    print(hexdump(pkts[n-1]))
    print("\n\n")
    options(pkts)

def save(pkts):
    display_title()
    name=str(input("\n\nEnter the file to be save: "))
    path="Saved files/"+name+".pcap"
    wrpcap(path,pkts)
    print("\nFile saved under "+path)
    time.sleep(3)
    examine(pkts)

def load():
    display_title()
    name=str(input("\n\nEnter file name to load: "))
    path="Saved files/"+name+".pcap"
    pkts=rdpcap(path)
    print("\nFile "+path+"  loaded")
    time.sleep(3)
    examine(pkts)

def exit():
    display_title()
    print("\n\t\t\t\t\t\tBy: Ashish & Hafiz")
    msg="GOODBYE..."
    print("\n\n\t\t\t",end='')
    for x in msg:
        print(x+" ",end='')
        time.sleep(0.4)
    print("\n\n\n")

def show_interfaces():
    print(conf.ifaces)

def chosen_interface(netindex):
    try:
        iface=dev_from_index(netindex)
    except:
        iface=-1
    return iface

def main():
    system("cls")
    welcome_screen()

main()