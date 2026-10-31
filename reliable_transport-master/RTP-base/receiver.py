import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

# Các hằng số loại gói tin
TYPE_START = 0
TYPE_END = 1
TYPE_DATA = 2
TYPE_ACK = 3

MAX_HEADER_SIZE = 16


def make_ack_packet(seq_num):
    """Tạo gói tin ACK kèm checksum chuẩn."""
    ack_hdr = PacketHeader(type=TYPE_ACK, seq_num=seq_num, length=0)
    raw_pkt = ack_hdr / b""
    ack_hdr.checksum = compute_checksum(raw_pkt)
    return bytes(ack_hdr / b"")


def receiver(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))

    expected_seq = 0
    buffer = {}  # Bộ đệm lưu trữ các gói tin đến lệch thứ tự (out-of-order)
    connection_started = False

    while True:
        pkt, address = s.recvfrom(2048)
        if len(pkt) < MAX_HEADER_SIZE:
            continue

        # Trích xuất Header và Payload
        pkt_header = PacketHeader(pkt[:MAX_HEADER_SIZE])
        msg = pkt[MAX_HEADER_SIZE : MAX_HEADER_SIZE + pkt_header.length]

        # Kiểm tra Checksum
        pkt_checksum = pkt_header.checksum
        pkt_header.checksum = 0
        computed_checksum = compute_checksum(pkt_header / msg)
        if pkt_checksum != computed_checksum:
            continue  # Bỏ qua gói tin bị hỏng (corrupted)

        pkt_type = pkt_header.type
        seq_num = pkt_header.seq_num

        # 1. Xử lý gói START
        if pkt_type == TYPE_START:
            if not connection_started or seq_num == 0:
                connection_started = True
                expected_seq = 1
                # Gửi ACK cho START với seq_num = 1
                ack_pkt = make_ack_packet(1)
                s.sendto(ack_pkt, address)
            continue

        if not connection_started:
            continue

        # 2. Xử lý gói DATA
        if pkt_type == TYPE_DATA:
            # Loại bỏ các gói nằm ngoài window_size cho phép
            if seq_num >= expected_seq + window_size:
                continue

            # Lưu vào bộ đệm nếu là gói tin hợp lệ trong window
            if seq_num >= expected_seq:
                buffer[seq_num] = msg

            # Ghi các gói tin đúng thứ tự liên tiếp ra sys.stdout
            while expected_seq in buffer:
                sys.stdout.buffer.write(buffer[expected_seq])
                sys.stdout.flush()
                del buffer[expected_seq]
                expected_seq += 1

            # Cumulative ACK: Gửi ACK với số thứ tự gói tin đang chờ tiếp theo
            ack_pkt = make_ack_packet(expected_seq)
            s.sendto(ack_pkt, address)

        # 3. Xử lý gói END
        elif pkt_type == TYPE_END:
            if seq_num == expected_seq:
                ack_pkt = make_ack_packet(seq_num + 1)
                s.sendto(ack_pkt, address)
                break

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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()