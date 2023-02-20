import pyshark, socket
from array import *

#Complementar
def imprime_protocolo():
    if pkt.ip.proto == '6':
        f.write('Protocol: TCP\n\n')
    elif pkt.ip.proto == '17':
        f.write('Protocol: UDP\n\n')
    elif pkt.ip.proto == '1':
        f.write('Protocol: ICMP\n\n')
    else:
        f.write('Protocol: Unknown\n\n')
        
cap = pyshark.FileCapture('tests/mh.pcapng')

with open('output/output.txt', 'w') as f:
    ips = []
    for pkt in cap:
        try:
            lists = [pkt.ip.src, pkt.ip.dst]
            if lists not in ips:
                ips.append(lists)
                f.write(f'IPs: {pkt.ip.src} -> {pkt.ip.dst}\n')
                
                try:
                    f.write(f'{socket.gethostbyaddr(pkt.ip.src)} -> ')
                except socket.herror:
                    f.write('Unknown -> ')
                try:
                    f.write(f'{socket.gethostbyaddr(pkt.ip.dst)}\n')
                except socket.herror:
                    f.write('Unknown\n')

                f.write(f'MACs: {pkt.eth.src} -> {pkt.eth.dst}\n')
                try:
                    f.write(f'Ports: {pkt.udp.srcport} -> {pkt.udp.dstport}\n')
                except AttributeError:
                    f.write('Ports: Unknown\n')
                imprime_protocolo()
        except AttributeError:
            pass