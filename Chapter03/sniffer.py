import socket
import os

# 수신할 호스트 IP
HOST = '192.168.1.206'


def main():
    # 원시 소켓 생성. 전체 네트워크에 대하여 바인드 설정
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))
    # 캡쳐한 패킷에 IP헤더 포함
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # 하나의 패킷 출력
    print(sniffer.recvfrom(65565))

    # 윈도우 시스템의 경우, 무차별 모드 해제
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


if __name__ == '__main__':
    main()
