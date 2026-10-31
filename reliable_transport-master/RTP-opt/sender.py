import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

# Cấu hình hằng số theo đặc tả RTP
TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

MAX_HEADER_SIZE = 16
MAX_PAYLOAD_SIZE = 1472 - MAX_HEADER_SIZE  # 1456 bytes


def create_packet(pkt_type, seq_num, payload=b""):
    """Tạo gói tin RTP kèm checksum chuẩn theo lớp PacketHeader/Scapy."""
    length = len(payload)
    pkt_header = PacketHeader(type=pkt_type, seq_num=seq_num, length=length)
    raw_pkt = pkt_header / payload
    pkt_header.checksum = compute_checksum(raw_pkt)
    return bytes(pkt_header / payload)


def parse_ack(data):
    """Bóc tách gói ACK và kiểm tra tính hợp lệ bằng compute_checksum."""
    if len(data) < MAX_HEADER_SIZE:
        return None, False

    header_data = data[:MAX_HEADER_SIZE]
    pkt_header = PacketHeader(header_data)

    expected_checksum = pkt_header.checksum
    pkt_header.checksum = 0

    calculated_checksum = compute_checksum(pkt_header / data[MAX_HEADER_SIZE:])
    if expected_checksum != calculated_checksum:
        return None, False

    return pkt_header, True


def sender(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    addr = (receiver_ip, receiver_port)

    # Đọc toàn bộ dữ liệu từ stdin và cắt nhỏ thành từng payload <= 1456 bytes
    raw_data = sys.stdin.buffer.read()
    chunks = [
        raw_data[i : i + MAX_PAYLOAD_SIZE]
        for i in range(0, len(raw_data), MAX_PAYLOAD_SIZE)
    ]

    # --- BƯỚC 1: HANDSHAKE (START PACKET) ---
    start_pkt = create_packet(TYPE_START, 0, b"")
    while True:
        s.sendto(start_pkt, addr)
        ready = select.select([s], [], [], 0.5)
        if ready[0]:
            try:
                data, _ = s.recvfrom(2048)
                ack_hdr, valid = parse_ack(data)
                if valid and ack_hdr.type == TYPE_ACK and ack_hdr.seq_num == 1:
                    break
            except socket.error:
                pass

    # --- BƯỚC 2: TRUYỀN DỮ LIỆU TỐI ƯU (SELECTIVE ACK) ---
    packets = [
        create_packet(TYPE_DATA, i + 1, chunk) for i, chunk in enumerate(chunks)
    ]
    total_packets = len(packets)

    base = 1
    next_seq_num = 1
    acked = {}  # Đánh dấu trạng thái ACK từng gói: acked[seq_num] = True/False
    timer_start = None

    while base <= total_packets:
        # Gửi tất cả gói tin trong phạm vi window cho phép
        while next_seq_num < base + window_size and next_seq_num <= total_packets:
            s.sendto(packets[next_seq_num - 1], addr)
            acked[next_seq_num] = False
            if timer_start is None:
                timer_start = time.time()  # Bật Timer khi gửi gói tin đầu tiên của window
            next_seq_num += 1

        # Lắng nghe ACK trả về
        ready = select.select([s], [], [], 0.05)
        if ready[0]:
            try:
                data, _ = s.recvfrom(2048)
                ack_hdr, valid = parse_ack(data)
                if valid and ack_hdr.type == TYPE_ACK:
                    ack_seq = ack_hdr.seq_num
                    # Trong RTP-opt, ACK trả về chính xác seq_num của gói dữ liệu
                    if base <= ack_seq < next_seq_num:
                        acked[ack_seq] = True

                    # Tiến cửa sổ sang phải nếu gói ở mép trái (base) đã được ACK
                    while base < next_seq_num and acked.get(base, False):
                        base += 1
                        if base < next_seq_num:
                            timer_start = time.time()  # Reset timer cho base mới
                        else:
                            timer_start = None
            except socket.error:
                pass

        # Timeout 500ms: CHỈ gửi lại những gói CHƯA nhận được ACK trong window hiện tại
        if timer_start and (time.time() - timer_start >= 0.5):
            timer_start = time.time()
            for i in range(base, next_seq_num):
                if not acked.get(i, False):
                    s.sendto(packets[i - 1], addr)

    # --- BƯỚC 3: KẾT THÚC KẾT NỐI (END PACKET) ---
    end_seq = total_packets + 1
    end_pkt = create_packet(TYPE_END, end_seq, b"")
    end_timer = time.time()

    s.sendto(end_pkt, addr)
    while time.time() - end_timer < 0.5:
        ready = select.select([s], [], [], 0.05)
        if ready[0]:
            try:
                data, _ = s.recvfrom(2048)
                ack_hdr, valid = parse_ack(data)
                if valid and ack_hdr.type == TYPE_ACK and ack_hdr.seq_num == end_seq + 1:
                    break
            except socket.error:
                pass

    s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()