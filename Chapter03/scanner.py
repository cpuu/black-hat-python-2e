import ipaddress
import os
import socket
import struct
import sys
import threading
import time

# 대상 네트워크의 서브넷
SUBNET = '192.168.1.0/24'
# ICMP 응답 메시지 검증용 시그니처 문자열
MESSAGE = 'PYTHONRULES!'


class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # 사람이 이해하기 쉬운 IP 주소 형태로 표기
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # 프로토콜 이름에 알맞은 고유번호를 연계하여 저장
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)


class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


# 이 함수는 시그니처 문자열이 포함된 UDP 데이터그램을 전송한다
def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            time.sleep(1)
            print('+', end='')
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))


class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP
        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print('hitting promiscuous mode...')
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        hosts_up = set([f'{str(self.host)} *'])
        try:
            while True:
                # 패킷 수신
                print('.', end='')
                raw_buffer = self.socket.recvfrom(65535)[0]
                # 패킷의 처음 20 바이트 부분을 추출하여 IP헤더 생성
                ip_header = IP(raw_buffer[0:20])
                # IP헤더에 명시된 프로토콜 이름이 ICMP인 패킷에 대해서만 처리
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)

                    # TYPE 값과 CODE 값이 3인지 확인
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            # 시그니처 문자열이 포함되어 있는지 확인
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf8'):
                                hosts_up.add(str(ip_header.src_address))
                                print(f'Host Up: {str(ip_header.src_address)}')
        # CTRL-C 처리
        except KeyboardInterrupt:
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

            print('\nUser interrupted.')
            if hosts_up:
                print(f'\n\nSummary: Hosts up on {SUBNET}')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.203'
    s = Scanner(host)
    time.sleep(10)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()
