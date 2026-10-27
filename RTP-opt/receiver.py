import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

# Packet types
START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16


def log(*args):
    """Debug output goes to stderr; stdout carries only the received message."""
    print(*args, file=sys.stderr)
    sys.stderr.flush()


def make_ack(seq_num):
    header = PacketHeader(type=ACK, seq_num=seq_num, length=0, checksum=0)
    header.checksum = compute_checksum(header)
    return bytes(header)


def parse_packet(raw):
    """Return (header, payload) if the checksum is valid, else None."""
    if len(raw) < HEADER_SIZE:
        return None
    header = PacketHeader(raw[:HEADER_SIZE])
    if header.length != len(raw) - HEADER_SIZE:
        return None
    payload = raw[HEADER_SIZE:]
    received = header.checksum
    header.checksum = 0
    if compute_checksum(header / payload) != received:
        return None
    return header, payload


def receiver(receiver_ip, receiver_port, window_size):
    """Receive one RTP connection; ACK each DATA packet individually (no cumulative ACK)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP only
    s.bind((receiver_ip, receiver_port))
    out = sys.stdout.buffer

    connected = False
    expected = 1          # N: next in-order seq_num
    buffer = {}           # out-of-order packets: seq_num -> payload

    while True:
        raw, address = s.recvfrom(2048)
        parsed = parse_packet(raw)
        if parsed is None:
            continue                      # bad checksum -> drop, no ACK
        header, payload = parsed
        seq = header.seq_num

        if header.type == START:
            if not connected:
                connected = True
                expected = 1
                buffer = {}
                s.sendto(make_ack(1), address)
                log("[receiver] connection started")
            elif expected == 1:
                s.sendto(make_ack(1), address)   # repeat a lost START ACK
            continue

        if not connected:
            continue

        if header.type == DATA:
            if seq >= expected + window_size:
                continue                  # outside the window -> drop
            if seq >= expected:
                buffer[seq] = payload
            while expected in buffer:
                out.write(buffer.pop(expected))
                expected += 1
            out.flush()
            # Individual ACK: same seq_num as the DATA packet
            # (duplicates of already-delivered packets are ACKed again too).
            s.sendto(make_ack(seq), address)

        elif header.type == END:
            if seq == expected:
                s.sendto(make_ack(seq + 1), address)
                log("[receiver] END received, exiting")
                break

    out.flush()
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
