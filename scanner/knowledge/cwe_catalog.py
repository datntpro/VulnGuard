"""
Catalog tri thức CWE (tiếng Việt) — để báo cáo LUÔN có diễn giải, khả năng khai
thác/PoC và cách khắc phục, KỂ CẢ KHI KHÔNG BẬT AI.

Mỗi mục: ten, mo_ta (là gì), tac_dong (hậu quả), poc (cách kiểm chứng/khai thác),
khac_phuc (cách sửa). Dữ liệu tĩnh, không gọi mạng. lookup() nhận "CWE-78", "78",
"CWE-78; CWE-89"… trả mục đầu khớp, hoặc fallback theo nhóm.
"""
import re
from typing import Any, Dict, List, Optional

CWE: Dict[str, Dict[str, str]] = {
    "78": {
        "ten": "OS Command Injection (chèn lệnh hệ điều hành)",
        "mo_ta": "Ứng dụng ghép dữ liệu người dùng vào một lệnh shell/hệ điều hành mà không tách tham số, khiến kẻ tấn công chèn thêm lệnh tùy ý.",
        "tac_dong": "Thực thi lệnh tùy ý trên máy chủ (RCE): đọc/ghi file, lấy biến môi trường/secret, pivot vào mạng nội bộ, chiếm quyền máy.",
        "poc": "Thử chèn dấu phân tách lệnh vào tham số đầu vào, ví dụ `; id`, `| whoami`, `$(id)`, `` `id` ``. Nếu phản hồi/nhật ký cho thấy lệnh được chạy (xuất hiện tên user, uid) thì khai thác được.",
        "khac_phuc": "Không gọi shell với chuỗi ghép. Dùng API truyền tham số dạng mảng (vd `subprocess.run([...], shell=False)`), allowlist giá trị, tránh `shell=True`/`os.system`/`eval` của lệnh.",
    },
    "79": {
        "ten": "Cross-site Scripting (XSS)",
        "mo_ta": "Dữ liệu người dùng được chèn vào HTML/JS trả về trình duyệt mà không mã hoá, khiến script của kẻ tấn công chạy trong phiên của nạn nhân.",
        "tac_dong": "Đánh cắp cookie/phiên, giả mạo thao tác người dùng, keylogger, chuyển hướng lừa đảo, chiếm tài khoản.",
        "poc": "Nhập payload `<script>alert(1)</script>` hoặc `\"><img src=x onerror=alert(1)>` vào trường nghi ngờ; nếu alert bật hoặc script chạy khi xem lại → dính XSS (reflected/stored).",
        "khac_phuc": "Mã hoá đầu ra theo ngữ cảnh (HTML/attr/JS/URL), dùng template tự escape, bật CSP, tránh `innerHTML`/`dangerouslySetInnerHTML`; làm sạch HTML bằng thư viện (DOMPurify).",
    },
    "89": {
        "ten": "SQL Injection",
        "mo_ta": "Dữ liệu người dùng được ghép thẳng vào câu lệnh SQL, cho phép kẻ tấn công thay đổi truy vấn.",
        "tac_dong": "Đọc/sửa/xoá toàn bộ CSDL, vượt xác thực, trích xuất dữ liệu nhạy cảm, đôi khi RCE trên DB server.",
        "poc": "Thêm `'` hoặc `' OR '1'='1` vào tham số; nếu đổi kết quả hoặc gây lỗi SQL → thử tiếp `' UNION SELECT ...`. Blind: so sánh thời gian phản hồi với `' AND SLEEP(5)--`.",
        "khac_phuc": "Luôn dùng prepared statement / parameterized query hoặc ORM; không ghép chuỗi; allowlist tên bảng/cột; tối thiểu quyền tài khoản DB.",
    },
    "20": {
        "ten": "Improper Input Validation (kiểm tra đầu vào không đúng)",
        "mo_ta": "Ứng dụng không kiểm tra/khử dữ liệu đầu vào đúng cách trước khi dùng.",
        "tac_dong": "Là tiền đề cho nhiều lỗ hổng khác (injection, tràn bộ nhớ, logic sai), có thể gây sai lệch dữ liệu hoặc DoS.",
        "poc": "Gửi giá trị ngoài miền kỳ vọng (quá dài, ký tự đặc biệt, kiểu sai, âm/0) và quan sát lỗi/hành vi bất thường.",
        "khac_phuc": "Kiểm tra theo allowlist (kiểu, độ dài, định dạng, khoảng giá trị) tại ranh giới tin cậy; từ chối thay vì cố sửa dữ liệu xấu.",
    },
    "22": {
        "ten": "Path Traversal (vượt thư mục)",
        "mo_ta": "Đường dẫn file được tạo từ dữ liệu người dùng không khử `../`, cho phép truy cập file ngoài thư mục dự kiến.",
        "tac_dong": "Đọc file nhạy cảm (`/etc/passwd`, cấu hình, secret), ghi đè file, đôi khi dẫn tới RCE.",
        "poc": "Thử `../../../../etc/passwd` (hoặc mã hoá `%2e%2e%2f`) ở tham số tên file; nếu trả nội dung file hệ thống → khai thác được.",
        "khac_phuc": "Chuẩn hoá đường dẫn (realpath) và kiểm tra nằm trong thư mục gốc cho phép; dùng allowlist tên file; không nhận đường dẫn tuyệt đối từ người dùng.",
    },
    "94": {
        "ten": "Code Injection (chèn mã)",
        "mo_ta": "Dữ liệu người dùng được đưa vào trình thông dịch mã (eval/exec) và thực thi.",
        "tac_dong": "Thực thi mã tuỳ ý trong tiến trình ứng dụng (RCE).",
        "poc": "Chèn biểu thức của ngôn ngữ (vd `__import__('os').system('id')` với Python) vào đầu vào tới eval/exec; quan sát kết quả thực thi.",
        "khac_phuc": "Loại bỏ eval/exec trên dữ liệu không tin cậy; dùng bộ phân tích an toàn (ast.literal_eval), allowlist thao tác, sandbox.",
    },
    "95": {
        "ten": "Eval Injection",
        "mo_ta": "Trường hợp cụ thể của chèn mã qua eval() động.",
        "tac_dong": "RCE trong tiến trình ứng dụng.",
        "poc": "Như CWE-94: đưa biểu thức độc vào tham số tới eval.",
        "khac_phuc": "Không eval dữ liệu người dùng; dùng ast.literal_eval hoặc parser chuyên dụng.",
    },
    "502": {
        "ten": "Deserialization of Untrusted Data (giải tuần tự dữ liệu không tin cậy)",
        "mo_ta": "Ứng dụng giải tuần tự dữ liệu do người dùng kiểm soát (pickle, Java serialize, YAML unsafe…).",
        "tac_dong": "RCE qua gadget chain, hoặc thao túng đối tượng gây lỗi logic.",
        "poc": "Tạo payload tuần tự độc (vd pickle với __reduce__ gọi os.system) và gửi tới điểm nhận; quan sát lệnh chạy.",
        "khac_phuc": "Không giải tuần tự dữ liệu không tin cậy; dùng định dạng dữ liệu (JSON) + schema; nếu bắt buộc, ký + kiểm tra toàn vẹn và dùng allowlist lớp.",
    },
    "611": {
        "ten": "XML External Entity (XXE)",
        "mo_ta": "Bộ phân tích XML cho phép thực thể ngoài (external entity), đọc tài nguyên ngoài.",
        "tac_dong": "Đọc file nội bộ, SSRF, DoS (billion laughs).",
        "poc": "Gửi XML khai báo `<!ENTITY xxe SYSTEM \"file:///etc/passwd\">` và tham chiếu; nếu nội dung file lọt vào phản hồi → dính.",
        "khac_phuc": "Tắt DTD/external entity trong parser (vd defusedxml cho Python); dùng cấu hình an toàn mặc định.",
    },
    "918": {
        "ten": "Server-Side Request Forgery (SSRF)",
        "mo_ta": "Máy chủ gửi request tới URL do người dùng cung cấp mà không hạn chế đích.",
        "tac_dong": "Truy cập dịch vụ nội bộ, metadata cloud (169.254.169.254) lấy credential, quét mạng nội bộ.",
        "poc": "Đặt URL trỏ `http://169.254.169.254/latest/meta-data/` hoặc `http://127.0.0.1:<port>`; nếu trả nội dung nội bộ → SSRF.",
        "khac_phuc": "Allowlist domain/IP đích, chặn IP nội bộ/link-local, không theo redirect tuỳ ý, tách mạng egress.",
    },
    "352": {
        "ten": "Cross-Site Request Forgery (CSRF)",
        "mo_ta": "Thao tác thay đổi trạng thái không kiểm tra nguồn gốc request, bị trang khác kích hoạt bằng phiên của nạn nhân.",
        "tac_dong": "Thực hiện hành động thay nạn nhân (đổi mật khẩu, chuyển tiền) mà họ không chủ ý.",
        "poc": "Tạo trang HTML tự submit form tới endpoint nhạy cảm; đăng nhập nạn nhân rồi mở trang — nếu hành động xảy ra → dính.",
        "khac_phuc": "CSRF token theo phiên, SameSite=Lax/Strict cho cookie, kiểm tra Origin/Referer cho request thay đổi trạng thái.",
    },
    "434": {
        "ten": "Unrestricted File Upload (tải lên file không kiểm soát)",
        "mo_ta": "Cho phép tải lên file nguy hiểm (vd .php, .jsp) và truy cập/thực thi được.",
        "tac_dong": "RCE qua webshell, lưu mã độc, tràn lưu trữ.",
        "poc": "Tải lên file mã nguồn (shell.php) rồi truy cập URL của nó; nếu thực thi → dính.",
        "khac_phuc": "Allowlist loại file theo nội dung (magic bytes), đổi tên ngẫu nhiên, lưu ngoài webroot, chặn thực thi thư mục upload.",
    },
    "601": {
        "ten": "Open Redirect (chuyển hướng mở)",
        "mo_ta": "Ứng dụng chuyển hướng tới URL do người dùng cung cấp mà không kiểm tra.",
        "tac_dong": "Lừa đảo (phishing) bằng tên miền hợp lệ, đánh cắp token qua redirect.",
        "poc": "Đặt tham số redirect = `https://evil.example`; nếu bị chuyển ra ngoài → dính.",
        "khac_phuc": "Allowlist đích chuyển hướng, chỉ cho phép đường dẫn tương đối nội bộ.",
    },
    "327": {
        "ten": "Thuật toán mã hoá yếu/không an toàn",
        "mo_ta": "Dùng thuật toán/mô hình mật mã lỗi thời hoặc sai (DES, RC4, ECB, tự chế).",
        "tac_dong": "Dữ liệu mã hoá có thể bị giải/giả mạo.",
        "poc": "Rà soát thuật toán/khoá; với ECB có thể thấy mẫu lặp trong ciphertext.",
        "khac_phuc": "Dùng AES-GCM/ChaCha20-Poly1305, RSA-OAEP; thư viện chuẩn, khoá đủ dài, chế độ an toàn (không ECB).",
    },
    "328": {
        "ten": "Hàm băm yếu (MD5/SHA1)",
        "mo_ta": "Dùng hàm băm đã vỡ cho mục đích bảo mật.",
        "tac_dong": "Va chạm/đảo băm, giả mạo chữ ký/toàn vẹn; lộ mật khẩu nếu dùng để băm password.",
        "poc": "Xác định MD5/SHA1 dùng cho bảo mật; với mật khẩu, thử brute-force/rainbow.",
        "khac_phuc": "Dùng SHA-256+ cho toàn vẹn; với mật khẩu dùng bcrypt/scrypt/argon2 có salt.",
    },
    "330": {
        "ten": "Dùng giá trị ngẫu nhiên không an toàn",
        "mo_ta": "Dùng PRNG thường (random) cho mục đích bảo mật (token, khoá).",
        "tac_dong": "Token/khoá đoán được → chiếm phiên, vượt xác thực.",
        "poc": "Thu thập nhiều giá trị sinh ra, phân tích để dự đoán giá trị kế tiếp.",
        "khac_phuc": "Dùng nguồn ngẫu nhiên mật mã (secrets, os.urandom, /dev/urandom).",
    },
    "338": {
        "ten": "PRNG mật mã yếu",
        "mo_ta": "Dùng bộ sinh số giả ngẫu nhiên không đạt chuẩn mật mã.",
        "tac_dong": "Dự đoán được giá trị bảo mật.",
        "poc": "Như CWE-330.",
        "khac_phuc": "Dùng CSPRNG (secrets/os.urandom).",
    },
    "798": {
        "ten": "Hardcoded Credentials (nhúng cứng bí mật)",
        "mo_ta": "Mật khẩu/API key/khoá nhúng cứng trong mã nguồn.",
        "tac_dong": "Lộ khi mã bị truy cập (repo, binary); dùng lại để truy cập trái phép.",
        "poc": "Tìm chuỗi bí mật trong mã; thử dùng để xác thực tới dịch vụ tương ứng.",
        "khac_phuc": "Đưa bí mật ra biến môi trường/secret manager; thu hồi key đã lộ; quét secret trong CI.",
    },
    "259": {
        "ten": "Mật khẩu nhúng cứng",
        "mo_ta": "Mật khẩu cố định trong mã/cấu hình.",
        "tac_dong": "Truy cập trái phép nếu lộ.",
        "poc": "Tìm mật khẩu trong mã; thử đăng nhập.",
        "khac_phuc": "Dùng secret manager, cấu hình ngoài, xoay vòng mật khẩu.",
    },
    "200": {
        "ten": "Lộ thông tin nhạy cảm",
        "mo_ta": "Ứng dụng để lộ dữ liệu không cần thiết cho người không được phép.",
        "tac_dong": "Hỗ trợ tấn công tiếp theo; lộ PII/cấu hình.",
        "poc": "Quan sát phản hồi/lỗi/headers xem có rò rỉ stack trace, đường dẫn, phiên bản, dữ liệu.",
        "khac_phuc": "Giảm chi tiết lỗi ra ngoài, tắt debug ở production, kiểm soát phân quyền dữ liệu.",
    },
    "209": {
        "ten": "Lộ thông tin qua thông báo lỗi",
        "mo_ta": "Thông báo lỗi chứa chi tiết nội bộ (stack trace, câu SQL, đường dẫn).",
        "tac_dong": "Giúp kẻ tấn công hiểu hệ thống, dò lỗ hổng.",
        "poc": "Gây lỗi (đầu vào sai) và đọc chi tiết trả về.",
        "khac_phuc": "Trả lỗi chung chung cho người dùng, ghi chi tiết vào log nội bộ; tắt debug.",
    },
    "312": {
        "ten": "Lưu dữ liệu nhạy cảm dạng rõ",
        "mo_ta": "Dữ liệu nhạy cảm lưu không mã hoá.",
        "tac_dong": "Lộ khi truy cập được lưu trữ.",
        "poc": "Kiểm tra DB/file/log xem dữ liệu nhạy cảm có ở dạng rõ.",
        "khac_phuc": "Mã hoá khi lưu (at rest), tối thiểu hoá dữ liệu lưu.",
    },
    "319": {
        "ten": "Truyền dữ liệu nhạy cảm dạng rõ",
        "mo_ta": "Dữ liệu nhạy cảm truyền không mã hoá (HTTP, telnet).",
        "tac_dong": "Nghe lén (MITM) lấy dữ liệu/credential.",
        "poc": "Bắt gói trên đường truyền; nếu thấy dữ liệu rõ → dính.",
        "khac_phuc": "Bắt buộc TLS, HSTS, tắt giao thức không mã hoá.",
    },
    "295": {
        "ten": "Không kiểm tra chứng chỉ TLS đúng cách",
        "mo_ta": "Bỏ qua/khử xác thực chứng chỉ khi kết nối TLS.",
        "tac_dong": "MITM giả mạo máy chủ, giải mã lưu lượng.",
        "poc": "Dùng proxy với cert tự ký; nếu client vẫn kết nối → dính.",
        "khac_phuc": "Bật xác thực chứng chỉ (verify=True), pin CA khi cần, không tắt verify.",
    },
    "400": {
        "ten": "Tiêu thụ tài nguyên không kiểm soát (DoS)",
        "mo_ta": "Thiếu giới hạn tài nguyên cho thao tác do người dùng kích hoạt.",
        "tac_dong": "Cạn CPU/RAM/kết nối → từ chối dịch vụ.",
        "poc": "Gửi đầu vào lớn/nhiều yêu cầu đồng thời; quan sát tài nguyên tăng vọt.",
        "khac_phuc": "Giới hạn kích thước/tần suất (rate limit), timeout, phân trang, hàng đợi.",
    },
    "1333": {
        "ten": "ReDoS (regex gây DoS)",
        "mo_ta": "Biểu thức chính quy có độ phức tạp mũ với đầu vào xấu.",
        "tac_dong": "Treo CPU, DoS.",
        "poc": "Gửi chuỗi kích hoạt backtracking (vd nhiều ký tự lặp); quan sát thời gian xử lý tăng đột biến.",
        "khac_phuc": "Tránh regex dễ bùng nổ, dùng engine tuyến tính (re2), giới hạn độ dài đầu vào, timeout.",
    },
    "190": {
        "ten": "Integer Overflow/Wraparound",
        "mo_ta": "Phép toán số nguyên vượt giới hạn gây giá trị sai.",
        "tac_dong": "Cấp phát sai, vượt kiểm tra, tràn bộ nhớ (ngôn ngữ bậc thấp).",
        "poc": "Đưa giá trị gần biên (MAX_INT) để kích hoạt wrap.",
        "khac_phuc": "Kiểm tra biên trước phép toán, dùng kiểu/đại số an toàn.",
    },
    "476": {
        "ten": "NULL Pointer Dereference",
        "mo_ta": "Truy cập con trỏ/đối tượng null.",
        "tac_dong": "Crash, DoS.",
        "poc": "Đưa đầu vào khiến nhánh trả null rồi bị dùng.",
        "khac_phuc": "Kiểm tra null trước khi dùng, dùng Optional, kiểm soát luồng lỗi.",
    },
    "416": {
        "ten": "Use After Free",
        "mo_ta": "Dùng vùng nhớ đã giải phóng.",
        "tac_dong": "Crash hoặc RCE (ngôn ngữ quản lý bộ nhớ thủ công).",
        "poc": "Kích hoạt free rồi dùng lại tham chiếu.",
        "khac_phuc": "Quản lý vòng đời rõ ràng, gán null sau free, dùng smart pointer / ngôn ngữ an toàn bộ nhớ.",
    },
    "732": {
        "ten": "Quyền truy cập tài nguyên không đúng",
        "mo_ta": "File/thư mục/khoá có quyền quá rộng.",
        "tac_dong": "Người không được phép đọc/sửa dữ liệu nhạy cảm.",
        "poc": "Kiểm tra quyền (vd 0777) của file nhạy cảm.",
        "khac_phuc": "Đặt quyền tối thiểu (0600/0640), chủ sở hữu đúng.",
    },
    "862": {
        "ten": "Thiếu kiểm soát truy cập (authorization)",
        "mo_ta": "Endpoint không kiểm tra quyền của người gọi.",
        "tac_dong": "Truy cập/chỉnh sửa tài nguyên của người khác (IDOR).",
        "poc": "Đổi ID tài nguyên trong request sang của người khác; nếu truy cập được → dính.",
        "khac_phuc": "Kiểm tra quyền phía máy chủ cho MỌI request theo chủ thể + đối tượng.",
    },
    "863": {
        "ten": "Kiểm soát truy cập sai",
        "mo_ta": "Logic phân quyền triển khai sai.",
        "tac_dong": "Leo thang đặc quyền, truy cập trái phép.",
        "poc": "Thử thao tác với vai trò thấp; nếu thực hiện được hành động của vai trò cao → dính.",
        "khac_phuc": "Mô hình phân quyền tập trung, deny-by-default, kiểm thử theo vai trò.",
    },
    "287": {
        "ten": "Xác thực không đúng",
        "mo_ta": "Cơ chế xác thực có thể bị vượt qua.",
        "tac_dong": "Chiếm tài khoản, truy cập trái phép.",
        "poc": "Thử bỏ qua bước xác thực, token yếu, brute force.",
        "khac_phuc": "Dùng cơ chế chuẩn, MFA, khoá sau nhiều lần sai, quản lý phiên an toàn.",
    },
    "77": {
        "ten": "Command Injection (chèn lệnh)",
        "mo_ta": "Dữ liệu người dùng được đưa vào một lệnh (shell/hệ thống) không an toàn.",
        "tac_dong": "Thực thi lệnh tuỳ ý (RCE).",
        "poc": "Chèn ký tự phân tách lệnh (`;`, `|`, `&&`) vào đầu vào.",
        "khac_phuc": "Tách tham số, không dùng shell, allowlist.",
    },
    "116": {
        "ten": "Mã hoá/escape đầu ra không đúng",
        "mo_ta": "Không encode dữ liệu khi đưa ra ngữ cảnh khác (HTML, SQL, shell).",
        "tac_dong": "Dẫn tới XSS/injection.",
        "poc": "Đưa ký tự đặc biệt của ngữ cảnh đích và xem có bị diễn giải.",
        "khac_phuc": "Encode đúng ngữ cảnh đầu ra.",
    },
}

# Nhóm fallback khi không có mục cụ thể — đoán theo loại scan.
_GENERIC = {
    "SECRETS": {
        "ten": "Lộ bí mật trong mã nguồn",
        "mo_ta": "Phát hiện chuỗi giống credential/khoá/token trong mã hoặc cấu hình.",
        "tac_dong": "Nếu là bí mật thật và còn hiệu lực, kẻ tấn công dùng để truy cập dịch vụ tương ứng.",
        "poc": "Xác nhận giá trị có thật/đang dùng không; thử xác thực tới dịch vụ liên quan (chỉ trong phạm vi được phép).",
        "khac_phuc": "Thu hồi & xoay vòng bí mật, chuyển sang secret manager/biến môi trường, thêm quét secret vào CI, xoá khỏi lịch sử git.",
    },
    "IAC": {
        "ten": "Sai cấu hình hạ tầng (IaC)",
        "mo_ta": "Cấu hình hạ tầng (Terraform/K8s/Docker…) không theo chuẩn an toàn.",
        "tac_dong": "Bề mặt tấn công rộng: tài nguyên công khai, quyền quá rộng, thiếu mã hoá/log.",
        "poc": "Đối chiếu cấu hình với chuẩn (CIS Benchmark); kiểm tra tài nguyên có thực sự public/quyền rộng.",
        "khac_phuc": "Áp chuẩn CIS, nguyên tắc tối thiểu quyền, bật mã hoá & log, review IaC trong CI.",
    },
    "SCA": {
        "ten": "Thành phần phụ thuộc có lỗ hổng",
        "mo_ta": "Thư viện/bên thứ ba đang dùng có CVE đã công bố.",
        "tac_dong": "Tuỳ CVE: từ DoS tới RCE; khai thác được nếu tính năng lỗi nằm trong đường chạy thật.",
        "poc": "Xác định hàm/tính năng lỗi có được gọi không; tham chiếu PoC công khai của CVE (nếu có).",
        "khac_phuc": "Nâng cấp lên phiên bản vá; nếu chưa có bản vá, hạn chế bề mặt hoặc thay thế thư viện.",
    },
    "SAST": {
        "ten": "Lỗ hổng trong mã nguồn",
        "mo_ta": "Công cụ phân tích tĩnh phát hiện mẫu code rủi ro.",
        "tac_dong": "Tuỳ loại; cần xem luồng dữ liệu để xác định mức khai thác.",
        "poc": "Truy vết dữ liệu không tin cậy từ nguồn (input) tới sink (lệnh nhạy cảm).",
        "khac_phuc": "Khử/validate dữ liệu tại ranh giới, dùng API an toàn, thêm kiểm thử.",
    },
}


def _ids(cwe_field: Optional[str]) -> List[str]:
    """'CWE-78; CWE-89' / '78,79' → ['78','89']."""
    if not cwe_field:
        return []
    return [m for m in re.findall(r"\d{1,5}", str(cwe_field))]


def lookup(cwe_field: Optional[str], scan_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Trả mục tri thức cho CWE đầu tiên khớp; nếu không có, fallback theo scan_type."""
    for cid in _ids(cwe_field):
        if cid in CWE:
            return {"cwe": f"CWE-{cid}", **CWE[cid]}
    if scan_type and scan_type.upper() in _GENERIC:
        return {"cwe": (f"CWE-{_ids(cwe_field)[0]}" if _ids(cwe_field) else None),
                **_GENERIC[scan_type.upper()]}
    return None
