import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

PKT_START, PKT_END, PKT_DATA, PKT_ACK = range(4)
HDR_LEN = 16

class RtpReceiver:
    def __init__(self, ip, port, window):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.window = window
        self.active = False
        self.next_expected = 1
        self.stash = {}
        self.out = sys.stdout.buffer

    @staticmethod
    def decode(raw):
        if len(raw) < HDR_LEN:
            return None
        hdr, body = PacketHeader(raw[:HDR_LEN]), raw[HDR_LEN:]
        if hdr.length != len(body):
            return None
        crc = hdr.checksum
        hdr.checksum = 0
        if compute_checksum(hdr / body) != crc:
            return None
        return hdr, body

    def send_ack(self, seq, peer):
        hdr = PacketHeader(type=PKT_ACK, seq_num=seq, length=0, checksum=0)
        hdr.checksum = compute_checksum(hdr)
        self.sock.sendto(bytes(hdr), peer)

    def on_start(self, hdr, body, peer):
        if not self.active:
            self.active = True
            self.next_expected = 1
            self.stash.clear()
            self.send_ack(1, peer)
        elif self.next_expected == 1:
            self.send_ack(1, peer)

        return False

    def on_data(self, hdr, body, peer):
        seq = hdr.seq_num
        if seq >= self.next_expected + self.window:
            return False
        if seq >= self.next_expected:
            self.stash[seq] = body
        while self.next_expected in self.stash:
            self.out.write(self.stash.pop(self.next_expected))
            self.next_expected += 1
        self.out.flush()

        self.send_ack(seq, peer)
        return False

    def on_end(self, hdr, body, peer):
        if hdr.seq_num != self.next_expected:
            return False
        self.send_ack(hdr.seq_num + 1, peer)
        return True

    def run(self):
        handlers = {PKT_START: self.on_start, PKT_DATA: self.on_data, PKT_END: self.on_end}
        finished = False
        while not finished:
            raw, peer = self.sock.recvfrom(2048)
            pkt = self.decode(raw)
            if pkt is None:
                continue
            hdr, body = pkt
            handler = handlers.get(hdr.type)
            if handler is None or (hdr.type != PKT_START and not self.active):
                continue
            finished = handler(hdr, body, peer)
        self.out.flush()
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

    RtpReceiver(args.receiver_ip, args.receiver_port, args.window_size).run()

if __name__ == "__main__":
    main()