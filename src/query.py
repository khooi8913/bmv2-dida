from scapy.layers.inet import *
from scapy.all import sniff
from scapy.all import send
from scapy.all import Raw
from scapy.all import DNS

send(IP(src='10.0.1.2',dst='10.0.1.1')/UDP(sport=12345,dport=53)/DNS())