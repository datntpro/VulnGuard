"""Sniffer egress (stdlib, AF_PACKET) — chạy chung netns với vg-under-test. Ghi JSON/dòng vào /log/hits.jsonl:
  {ts, proto: tcp|udp|icmp|ipv6|ip<N>, dst, dport, src}
Chỉ ghi gói ĐI RA (PACKET_OUTGOING), bỏ loopback; TCP chỉ ghi SYN (không ACK) = nỗ lực kết nối mới."""
import json, os, socket, struct, time

LOG = "/log/hits.jsonl"
os.makedirs("/log", exist_ok=True)
open(LOG, "a").close()
PACKET_OUTGOING = 4


def emit(**rec):
    rec["ts"] = time.time()
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")


def handle(frame):
    if len(frame) < 15:
        return
    et = struct.unpack("!H", frame[12:14])[0]
    ip = frame[14:]
    if et == 0x0800 and len(ip) >= 20:
        ihl = (ip[0] & 0x0F) * 4
        proto, src, dst = ip[9], socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        if dst.startswith("127."):
            return
        l4 = ip[ihl:]
        if proto == 6 and len(l4) >= 14:
            flags = l4[13]
            if flags & 0x02 and not flags & 0x10:
                emit(proto="tcp", src=src, dst=dst, dport=struct.unpack("!H", l4[2:4])[0])
        elif proto == 17 and len(l4) >= 4:
            emit(proto="udp", src=src, dst=dst, dport=struct.unpack("!H", l4[2:4])[0])
        elif proto == 1:
            emit(proto="icmp", src=src, dst=dst, dport=None)
        else:
            emit(proto=f"ip{proto}", src=src, dst=dst, dport=None)
    elif et == 0x86DD and len(ip) >= 40:
        nxt = ip[6]
        dst = socket.inet_ntop(socket.AF_INET6, ip[24:40])
        if dst == "::1":
            return
        emit(proto="ipv6", src=socket.inet_ntop(socket.AF_INET6, ip[8:24]), dst=dst, dport=None, next_header=nxt)


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
while True:
    frame, addr = s.recvfrom(65535)
    if addr[2] == PACKET_OUTGOING:
        try:
            handle(frame)
        except Exception:
            pass
