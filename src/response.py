from scapy.layers.inet import *
from scapy.all import sniff
from scapy.all import send
from scapy.all import Raw
from scapy.all import DNS

send(IP(src='10.0.1.1',dst='10.0.3.3')/UDP(sport=53,dport=12345)/DNS())
