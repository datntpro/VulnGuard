"""DNS tối giản cho lab (stdlib, UDP :53). TTL=0. rebind.lab luân phiên .10/.20 mỗi truy vấn
(mô phỏng DNS rebinding). Tên lạ → NXDOMAIN. AAAA → rỗng (NOERROR)."""
import socket, struct, threading

ZONE = {"inscope.lab": ["172.31.250.10"], "oos.lab": ["172.31.250.20"], "metadata.lab": ["172.31.250.254"]}
REBIND = ["172.31.250.10", "172.31.250.20"]
_n = 0
_lock = threading.Lock()


def _qname(data, off=12):
    labels = []
    while data[off]:
        n = data[off]
        labels.append(data[off + 1: off + 1 + n].decode())
        off += n + 1
    return ".".join(labels).lower(), off + 1


def answer(data):
    global _n
    name, off = _qname(data)
    qtype = struct.unpack("!H", data[off: off + 2])[0]
    question = data[12: off + 4]
    if name == "rebind.lab" and qtype == 1:
        with _lock:
            ips = [REBIND[_n % 2]]
            _n += 1
    else:
        ips = ZONE.get(name)
    if name == "rebind.lab" and qtype != 1:
        ips = REBIND
    if ips is None:
        return data[:2] + struct.pack("!HHHHH", 0x8183, 1, 0, 0, 0) + question
    if qtype != 1:
        return data[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + question
    ans = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(ip) for ip in ips)
    return data[:2] + struct.pack("!HHHHH", 0x8180, 1, len(ips), 0, 0) + question + ans


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 53))
while True:
    d, a = s.recvfrom(512)
    try:
        s.sendto(answer(d), a)
    except Exception:
        pass
