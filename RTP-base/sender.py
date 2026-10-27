import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

PKT_START, PKT_END, PKT_DATA, PKT_ACK = range(4)
HDR_LEN = 16
CHUNK = 1472 - HDR_LEN
RTO = 0.5

class RtpSender:
    def __init__(self, ip, port, window):
        self.dest = (ip, port)
        self.window = window
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    @staticmethod
    def build(kind, seq, data=b""):
        hdr = PacketHeader(type=kind, seq_num=seq, length=len(data), checksum=0)
        hdr.checksum = compute_checksum(hdr / data)
        return bytes(hdr / data)

    def read_ack(self, timeout):
        self.sock.settimeout(max(timeout, 0.001))
        try:
            raw, _ = self.sock.recvfrom(2048)
        except socket.timeout:
            return None
        if len(raw) < HDR_LEN:
            return None
        hdr, body = PacketHeader(raw[:HDR_LEN]), raw[HDR_LEN:]
        if hdr.type != PKT_ACK or hdr.length != len(body):
            return None
        crc = hdr.checksum
        hdr.checksum = 0
        return hdr.seq_num if compute_checksum(hdr / body) == crc else None

    def exchange(self, pkt, want, limit=None):
        t0 = time.monotonic()
        while limit is None or time.monotonic() - t0 < limit:
            self.sock.sendto(pkt, self.dest)
            resend_at = time.monotonic() + RTO
            if limit is not None:
                resend_at = min(resend_at, t0 + limit)
            while time.monotonic() < resend_at:
                if self.read_ack(resend_at - time.monotonic()) == want:
                    return True
        return False

    def transfer(self, payload):
        segs = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)]
        frames = [None] + [self.build(PKT_DATA, n, s) for n, s in enumerate(segs, 1)]
        total = len(segs)

        self.exchange(self.build(PKT_START, 0), want=1)

        win_lo, win_hi = 1, 1
        deadline = time.monotonic() + RTO
        while win_lo <= total:
            while win_hi < win_lo + self.window and win_hi <= total:
                self.sock.sendto(frames[win_hi], self.dest)
                win_hi += 1

            left = deadline - time.monotonic()
            if left <= 0:

                for n in range(win_lo, win_hi):
                    self.sock.sendto(frames[n], self.dest)
                deadline = time.monotonic() + RTO
                continue

            ack = self.read_ack(left)
            if ack is not None and win_lo < ack <= win_hi:
                win_lo = ack
                deadline = time.monotonic() + RTO

        self.exchange(self.build(PKT_END, total + 1), want=total + 2, limit=RTO)
        self.sock.close()

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

    RtpSender(args.receiver_ip, args.receiver_port, args.window_size).transfer(
        sys.stdin.buffer.read()
    )

if __name__ == "__main__":
    main()