import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

# Packet types
START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16                      # 4 int fields x 4 bytes
MAX_PACKET_SIZE = 1472                # 1500 (Ethernet) - 20 (IP) - 8 (UDP)
MAX_PAYLOAD = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5                         # 500 ms


def log(*args):
    """Debug output goes to stderr so it never mixes with real data."""
    print(*args, file=sys.stderr)
    sys.stderr.flush()


def make_packet(pkt_type, seq_num, payload=b""):
    """Build a packet: header (with CRC32 checksum) followed by payload."""
    header = PacketHeader(type=pkt_type, seq_num=seq_num, length=len(payload), checksum=0)
    header.checksum = compute_checksum(header / payload)
    return bytes(header / payload)


def parse_ack(raw):
    """Return the seq_num of a valid ACK, or None if the packet is corrupted / not an ACK."""
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
    if header.type != ACK:
        return None
    return header.seq_num


def send_and_wait(s, addr, pkt, expected_ack, give_up_after=None):
    """Send pkt and wait for the ACK with seq_num == expected_ack.

    Retransmits every 500 ms. If give_up_after is set, stop after that many
    seconds even without an ACK (used for END)."""
    start = time.time()
    s.sendto(pkt, addr)
    last_send = start
    while True:
        now = time.time()
        if give_up_after is not None and now - start >= give_up_after:
            return False
        wait = TIMEOUT - (now - last_send)
        if give_up_after is not None:
            wait = min(wait, give_up_after - (now - start))
        if wait <= 0:
            s.sendto(pkt, addr)
            last_send = time.time()
            continue
        s.settimeout(wait)
        try:
            raw, _ = s.recvfrom(2048)
        except socket.timeout:
            continue
        if parse_ack(raw) == expected_ack:
            return True


def sender(receiver_ip, receiver_port, window_size):
    """Read the message from stdin and send it reliably with Go-Back-N."""
    addr = (receiver_ip, receiver_port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP only

    # 1. Split the message into chunks. DATA seq_nums start at 1.
    message = sys.stdin.buffer.read()
    chunks = [message[i:i + MAX_PAYLOAD] for i in range(0, len(message), MAX_PAYLOAD)]
    packets = {i + 1: make_packet(DATA, i + 1, chunk) for i, chunk in enumerate(chunks)}
    last_seq = len(chunks)            # seq_num of the last DATA packet
    log(f"[sender] {len(message)} bytes -> {last_seq} DATA packets, window={window_size}")

    # 2. START (seq 0) -> wait for ACK with seq 1.
    send_and_wait(s, addr, make_packet(START, 0), expected_ack=1)
    log("[sender] connection established")

    # 3. Sliding window.
    #    base     = oldest unacknowledged seq_num
    #    next_seq = next seq_num that has never been sent
    base = 1
    next_seq = 1
    timer_start = time.time()

    while base <= last_seq:
        # Fill the window with new packets.
        while next_seq < base + window_size and next_seq <= last_seq:
            s.sendto(packets[next_seq], addr)
            next_seq += 1

        # Timeout: window did not move for 500 ms -> resend the whole window.
        remaining = TIMEOUT - (time.time() - timer_start)
        if remaining <= 0:
            log(f"[sender] timeout, resend window [{base}, {next_seq - 1}]")
            for seq in range(base, next_seq):
                s.sendto(packets[seq], addr)
            timer_start = time.time()
            continue

        s.settimeout(remaining)
        try:
            raw, _ = s.recvfrom(2048)
        except socket.timeout:
            continue

        ack = parse_ack(raw)
        if ack is None:
            continue                      # corrupted / not an ACK -> ignore
        # Cumulative ACK: receiver has everything below `ack`.
        if base < ack <= next_seq:
            base = ack
            timer_start = time.time()     # window moved -> reset timer
            log(f"[sender] window -> [{base}, {base + window_size - 1}]")
        # ack <= base: duplicate / old ACK (reordering, duplication) -> ignore

    # 4. END (seq = last_seq + 1). Exit on its ACK or after 500 ms.
    end_seq = last_seq + 1
    got = send_and_wait(s, addr, make_packet(END, end_seq), expected_ack=end_seq + 1,
                        give_up_after=TIMEOUT)
    log(f"[sender] done ({'END acked' if got else 'END timer expired'})")
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
