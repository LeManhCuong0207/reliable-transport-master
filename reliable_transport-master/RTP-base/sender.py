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
    # Gộp header và payload để tính checksum
    raw_pkt = pkt_header / payload
    pkt_header.checksum = compute_checksum(raw_pkt)
    return bytes(pkt_header / payload)


def parse_ack(data):
    """Bóc tách gói ACK và kiểm tra tính hợp lệ bằng compute_checksum."""
    if len(data) < MAX_HEADER_SIZE:
        return None, False

    header_data = data[:MAX_HEADER_SIZE]
    pkt_header = PacketHeader(header_data)

    # Đặt checksum = 0 để tự tính lại và so sánh
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

    # 1. Đọc dữ liệu từ sys.stdin dưới dạng bytes và chia thành các chunk <= 1456 bytes
    raw_data = sys.stdin.buffer.read()
    chunks = [
        raw_data[i : i + MAX_PAYLOAD_SIZE]
        for i in range(0, len(raw_data), MAX_PAYLOAD_SIZE)
    ]

    # --- BƯỚC 1: KHỞI TẠO KẾT NỐI (START PACKET) ---
    # Gói START có seq_num = 0
    start_pkt = create_packet(TYPE_START, 0, b"")
    while True:
        s.sendto(start_pkt, addr)
        ready = select.select([s], [], [], 0.5)
        if ready[0]:
            try:
                data, _ = s.recvfrom(2048)
                ack_hdr, valid = parse_ack(data)
                # Gói ACK cho START có seq_num = 1
                if valid and ack_hdr.type == TYPE_ACK and ack_hdr.seq_num == 1:
                    break
            except socket.error:
                pass

    # --- BƯỚC 2: TRUYỀN DỮ LIỆU (DATA PACKETS VIA GO-BACK-N) ---
    # Các gói DATA bắt đầu đánh số seq_num từ 1
    packets = [
        create_packet(TYPE_DATA, i + 1, chunk) for i, chunk in enumerate(chunks)
    ]
    total_packets = len(packets)

    base = 1  # Gói nhỏ nhất chưa nhận được ACK
    next_seq_num = 1  # Gói tiếp theo sẵn sàng gửi
    timer_start = None

    while base <= total_packets:
        # Gửi liên tục các gói trong cửa sổ window_size cho phép
        while next_seq_num < base + window_size and next_seq_num <= total_packets:
            s.sendto(packets[next_seq_num - 1], addr)
            if base == next_seq_num:
                timer_start = time.time()  # Bật Timer cho gói ở đầu cửa sổ
            next_seq_num += 1

        # Lắng nghe ACK trả về
        ready = select.select([s], [], [], 0.05)
        if ready[0]:
            try:
                data, _ = s.recvfrom(2048)
                ack_hdr, valid = parse_ack(data)
                if valid and ack_hdr.type == TYPE_ACK:
                    # Cumulative ACK: Nếu ACK lớn hơn base hiện tại, tiến cửa sổ lên
                    if ack_hdr.seq_num > base:
                        base = ack_hdr.seq_num
                        if base < next_seq_num:
                            timer_start = time.time()  # Reset timer cho base mới
                        else:
                            timer_start = None
            except socket.error:
                pass

        # Timeout 500ms (Go-Back-N): Gửi lại toàn bộ gói trong cửa sổ
        if timer_start and (time.time() - timer_start >= 0.5):
            timer_start = time.time()
            for i in range(base, next_seq_num):
                s.sendto(packets[i - 1], addr)

    # --- BƯỚC 3: KẾT THÚC KẾT NỐI (END PACKET) ---
    end_seq = total_packets + 1
    end_pkt = create_packet(TYPE_END, end_seq, b"")
    end_timer = time.time()

    s.sendto(end_pkt, addr)
    while time.time() - end_timer < 0.5:  # Chờ 500ms theo đúng đặc tả
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