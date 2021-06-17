import ipaddress
import os
import socket
import struct
import sys


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


def sniff(host):
    # 앞선 예제의 코드 준용
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # 패킷 수신
            raw_buffer = sniffer.recvfrom(65535)[0]
            # 패킷의 처음 20 바이트 부분을 추출하여 IP헤더 생성
            ip_header = IP(raw_buffer[0:20])
            # 탐지된 프로토콜 및 호스트 주소 출력
            print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                             ip_header.src_address, ip_header.dst_address))
            # print(f'Version: {ip_header.ver} Header Length: {ip_header.ihl}  TTL: {ip_header.ttl}')

    except KeyboardInterrupt:
        # 윈도우 시스템의 경우, 무차별 모드 해제
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.203'
    sniff(host)
