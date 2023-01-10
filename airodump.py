import pcap
import sys

sniffer = pcap.pcap(name=sys.argv[1], promisc=True, immediate=True, timeout_ms=3600)

print('BSSID\tSSID')
for ts,pkt in sniffer:
    if pkt[24] == 128:
        name_length = pkt[61]
        ssid_name = pkt[62:62 + name_length]
        result = ssid_name.decode('utf-8')
        print(':'.join('%02X' % i for i in pkt[40:46]), result, sep='\t')
