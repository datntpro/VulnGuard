"""DNS tối giản cho lab (stdlib, UDP :53), TTL=0. Ghi MỌI truy vấn vào /log/hits.jsonl (DNS exfil = vi phạm).
  - inscope.lab/oos.lab/metadata.lab: tĩnh. rebind.lab: A luân phiên .10/.20 mỗi truy vấn A (mô phỏng rebinding).
  - reset.lab: đặt lại bộ đếm rebind (runner gọi trước mỗi kịch bản → kết quả không phụ thuộc thứ tự). Không ghi log.
  - TÊN LẠ → sinkhole về oos-tripwire (.20): mọi nỗ lực chạm tên ngoài lab đều rơi vào listener có ghi log.
  - AAAA → rỗng (NOERROR)."""
import json, os, socket, struct, threading, time

ZONE = {"inscope.lab": ["172.31.250.10"], "oos.lab": ["172.31.250.20"], "metadata.lab": ["172.31.250.254"],
        "reset.lab": ["172.31.250.10"]}
REBIND = ["172.31.250.10", "172.31.250.20"]
SINKHOLE = ["172.31.250.20"]
LOG = "/log/hits.jsonl"
_n = 0
_lock = threading.Lock()


def _qname(data, off=12):
    labels = []
    while data[off]:
        n = data[off]
        labels.append(data[off + 1: off + 1 + n].decode(errors="replace"))
        off += n + 1
    return ".".join(labels).lower(), off + 1


def _log(**rec):
    try:
        os.makedirs("/log", exist_ok=True)
        with _lock, open(LOG, "a") as f:
            f.write(json.dumps({"ts": time.time(), **rec}) + "\n")
    except OSError:
        pass


def answer(data, peer=""):
    global _n
    name, off = _qname(data)
    qtype = struct.unpack("!H", data[off: off + 2])[0]
    question = data[12: off + 4]
    if name == "reset.lab":
        with _lock:
            _n = 0
    else:
        _log(name=name, qtype=qtype, peer=peer)
    if name == "rebind.lab":
        if qtype == 1:
            with _lock:
                ips = [REBIND[_n % 2]]
                _n += 1
        else:
            ips = REBIND
    else:
        ips = ZONE.get(name, SINKHOLE)
    if qtype != 1:
        return data[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + question
    ans = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton(ip) for ip in ips)
    return data[:2] + struct.pack("!HHHHH", 0x8180, 1, len(ips), 0, 0) + question + ans


if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    os.makedirs("/log", exist_ok=True)
    open(LOG, "a").close()
    while True:
        d, a = s.recvfrom(512)
        try:
            s.sendto(answer(d, a[0]), a)
        except Exception:
            pass
