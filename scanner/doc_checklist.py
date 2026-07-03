"""
Checklist an toàn thông tin dùng để AI review tài liệu phát triển hệ thống.

Dựa trên OWASP ASVS (Application Security Verification Standard) v4/v5 — mỗi tiêu chí
được diễn giải lại ở mức "tài liệu cần nêu rõ điều gì" (không phải mức code), vì input
là SRS/FRS/BRD, thiết kế kiến trúc (HLD/LLD), hoặc đặc tả API/DB schema — chứ không phải
source code (việc đó đã có Scan Engine của VulnGuard lo).

Mỗi entry: (criteria_id, category, criteria_text)
criteria_id tham chiếu chương ASVS gần nhất để người review tra cứu lại gốc nếu cần.
"""
from api.docreview_models import DocType

# ─────────────────────────────────────────────
# Checklist: SRS / FRS / BRD — đặc tả yêu cầu
# ─────────────────────────────────────────────
SRS_FRS_BRD_CHECKLIST = [
    ("ASVS-2.1", "Xác thực (Authentication)",
     "Tài liệu có mô tả rõ cơ chế xác thực người dùng (đăng nhập, MFA, độ mạnh mật khẩu, khóa tài khoản sau N lần sai) không?"),
    ("ASVS-3.2", "Quản lý phiên (Session Management)",
     "Tài liệu có yêu cầu về thời gian sống của session/token, đăng xuất, vô hiệu hóa session khi đổi mật khẩu không?"),
    ("ASVS-4.1", "Kiểm soát truy cập (Access Control)",
     "Tài liệu có định nghĩa rõ các vai trò (role), phân quyền (RBAC/ABAC) và nguyên tắc least privilege cho từng chức năng không?"),
    ("ASVS-5.1", "Validate dữ liệu đầu vào",
     "Tài liệu có yêu cầu validate/sanitize dữ liệu đầu vào của người dùng (form, file upload, API) không?"),
    ("ASVS-8.1", "Phân loại & bảo vệ dữ liệu",
     "Tài liệu có phân loại dữ liệu nhạy cảm (PII, tài chính, sức khỏe...) và yêu cầu mã hóa/che dữ liệu (mask/encrypt) tương ứng không?"),
    ("ASVS-9.1", "Bảo mật truyền tải (Communications)",
     "Tài liệu có yêu cầu mã hóa kênh truyền (HTTPS/TLS) cho dữ liệu nhạy cảm không?"),
    ("ASVS-7.1", "Logging & Audit Trail",
     "Tài liệu có yêu cầu ghi log các hành vi quan trọng (đăng nhập, thay đổi quyền, giao dịch) phục vụ audit không?"),
    ("ASVS-1.1", "Đánh giá rủi ro / Threat Modeling",
     "Tài liệu có đề cập đến phân tích rủi ro bảo mật, tác nhân đe dọa (threat actor), hoặc kịch bản lạm dụng (abuse case) không?"),
    ("ASVS-13.1", "Bảo mật API/Tích hợp bên thứ ba",
     "Nếu hệ thống tích hợp API/bên thứ ba, tài liệu có nêu yêu cầu xác thực, giới hạn rate limit, và xử lý lỗi an toàn không?"),
    ("ASVS-4.3", "Chống lạm dụng (Anti-automation)",
     "Tài liệu có yêu cầu chống brute-force, rate limiting, CAPTCHA cho các chức năng nhạy cảm (login, OTP, form public) không?"),
    ("ASVS-14.1", "Tuân thủ pháp lý / Compliance",
     "Tài liệu có nêu yêu cầu tuân thủ quy định liên quan (Nghị định 13/2023 bảo vệ dữ liệu cá nhân, PCI-DSS, ISO 27001...) nếu áp dụng không?"),
    ("ASVS-16.1", "Sao lưu & khôi phục",
     "Tài liệu có yêu cầu backup dữ liệu, kế hoạch khôi phục sau sự cố (RTO/RPO) không?"),
    ("ASVS-1.2", "Xử lý lỗi & thông báo",
     "Tài liệu có yêu cầu thông báo lỗi không lộ thông tin nhạy cảm (stack trace, thông tin hệ thống) cho người dùng cuối không?"),
]

# ─────────────────────────────────────────────
# Checklist: Thiết kế kiến trúc (HLD/LLD)
# ─────────────────────────────────────────────
ARCHITECTURE_CHECKLIST = [
    ("ASVS-1.1", "Mô hình hóa mối đe dọa (Threat Modeling)",
     "Tài liệu kiến trúc có chỉ ra trust boundary, data flow, và các điểm tấn công tiềm ẩn (attack surface) không?"),
    ("ASVS-1.4", "Phân vùng mạng / Network Segmentation",
     "Kiến trúc có phân tách rõ các vùng mạng (DMZ, internal, database tier) và kiểm soát truy cập giữa các vùng không?"),
    ("ASVS-2.1", "Kiến trúc xác thực",
     "Tài liệu có mô tả thành phần/luồng xác thực tập trung (SSO/IdP) hoặc cơ chế xác thực giữa các service không?"),
    ("ASVS-4.1", "Kiến trúc phân quyền",
     "Kiến trúc có mô tả cơ chế authorization giữa các service/microservice (vd: token scope, mTLS, API gateway policy) không?"),
    ("ASVS-6.2", "Quản lý khóa & secret",
     "Tài liệu có nêu giải pháp quản lý secret/credential (vault, KMS, secret manager) — không hardcode trong config/code không?"),
    ("ASVS-9.1", "Mã hóa khi truyền (in-transit)",
     "Kiến trúc có yêu cầu TLS giữa các thành phần nội bộ và với client, đặc biệt qua mạng không tin cậy không?"),
    ("ASVS-9.2", "Mã hóa khi lưu trữ (at-rest)",
     "Tài liệu có yêu cầu mã hóa dữ liệu nhạy cảm tại nơi lưu trữ (database, object storage, backup) không?"),
    ("ASVS-7.2", "Giám sát & Logging tập trung",
     "Kiến trúc có thành phần thu thập log/giám sát tập trung (SIEM, centralized logging) phục vụ phát hiện bất thường không?"),
    ("ASVS-1.6", "Bảo mật phụ thuộc bên thứ ba",
     "Tài liệu có đề cập việc kiểm soát rủi ro từ thư viện/dịch vụ bên thứ ba (SCA, vendor risk) không?"),
    ("ASVS-1.5", "Khả năng chịu lỗi & DR/HA",
     "Kiến trúc có thiết kế cho high-availability/disaster recovery, tránh single point of failure ảnh hưởng tới bảo mật/uptime không?"),
    ("ASVS-1.7", "Least Privilege hạ tầng",
     "Các thành phần (service account, container, VM) có được thiết kế theo nguyên tắc least privilege không?"),
    ("ASVS-13.2", "Bảo mật API Gateway/Edge",
     "Nếu có API Gateway/edge layer, tài liệu có nêu rõ chức năng rate limiting, WAF, input filtering ở lớp này không?"),
]

# ─────────────────────────────────────────────
# Checklist: Đặc tả API / DB Schema
# ─────────────────────────────────────────────
API_DB_SCHEMA_CHECKLIST = [
    ("ASVS-4.1", "Authorization theo endpoint",
     "Mỗi API endpoint có khai báo rõ quyền/role cần thiết để gọi (authorization requirement) không?"),
    ("ASVS-2.1", "Authentication scheme",
     "Đặc tả API có nêu rõ cơ chế xác thực (API key, OAuth2, JWT...) áp dụng cho từng endpoint/nhóm endpoint không?"),
    ("ASVS-5.1", "Input validation / Schema",
     "Mỗi field trong request schema có định nghĩa kiểu dữ liệu, độ dài, ràng buộc hợp lệ (validation rule) không?"),
    ("ASVS-5.5", "Output encoding / Response schema",
     "Response schema có tránh trả về field nhạy cảm không cần thiết (over-exposure), và có chuẩn hóa lỗi không tiết lộ chi tiết hệ thống không?"),
    ("ASVS-4.3", "Rate limiting / chống abuse",
     "Đặc tả API có nêu giới hạn rate limit/throttling cho từng endpoint, đặc biệt endpoint nhạy cảm (login, search, export) không?"),
    ("ASVS-8.1", "Phân loại dữ liệu nhạy cảm trong schema",
     "DB schema có đánh dấu rõ các field PII/nhạy cảm (email, CCCD, số thẻ...) và yêu cầu mã hóa/mask tương ứng không?"),
    ("ASVS-8.3", "Least privilege truy cập DB",
     "Tài liệu có nêu rõ DB account/role dùng cho ứng dụng chỉ có quyền tối thiểu cần thiết (không dùng account admin) không?"),
    ("ASVS-7.1", "Audit log truy cập dữ liệu nhạy cảm",
     "Đặc tả có yêu cầu ghi log truy cập/thay đổi đối với bảng/field dữ liệu nhạy cảm không?"),
    ("ASVS-13.3", "Versioning & Deprecation an toàn",
     "Tài liệu API có chính sách versioning/deprecation rõ ràng, tránh duy trì version cũ có lỗ hổng đã biết không?"),
    ("ASVS-9.1", "Bảo mật kết nối DB",
     "Tài liệu có yêu cầu kết nối DB qua kênh mã hóa (TLS) và không expose DB port ra ngoài không?"),
    ("ASVS-16.1", "Backup & retention",
     "Tài liệu có nêu chính sách backup, retention, và xóa dữ liệu (data lifecycle) cho dữ liệu nhạy cảm không?"),
]

# ─────────────────────────────────────────────
# Checklist chung — dùng cho loại tài liệu khác (OTHER)
# ─────────────────────────────────────────────
GENERIC_CHECKLIST = [
    ("ASVS-2.1", "Xác thực", "Tài liệu có đề cập đến cơ chế xác thực người dùng/hệ thống không?"),
    ("ASVS-4.1", "Kiểm soát truy cập", "Tài liệu có đề cập đến phân quyền/kiểm soát truy cập không?"),
    ("ASVS-8.1", "Bảo vệ dữ liệu", "Tài liệu có đề cập đến bảo vệ dữ liệu nhạy cảm (mã hóa, mask) không?"),
    ("ASVS-9.1", "Bảo mật truyền tải", "Tài liệu có yêu cầu mã hóa kênh truyền dữ liệu không?"),
    ("ASVS-7.1", "Logging & Audit", "Tài liệu có yêu cầu ghi log/audit trail không?"),
    ("ASVS-1.1", "Threat Modeling", "Tài liệu có đề cập rủi ro bảo mật/threat model không?"),
    ("ASVS-14.1", "Compliance", "Tài liệu có đề cập tuân thủ quy định pháp lý liên quan không?"),
]


CHECKLISTS = {
    DocType.SRS_FRS_BRD: SRS_FRS_BRD_CHECKLIST,
    DocType.ARCHITECTURE: ARCHITECTURE_CHECKLIST,
    DocType.API_DB_SCHEMA: API_DB_SCHEMA_CHECKLIST,
    DocType.OTHER: GENERIC_CHECKLIST,
}

DOC_TYPE_LABELS = {
    DocType.SRS_FRS_BRD: "SRS / FRS / BRD (Đặc tả yêu cầu)",
    DocType.ARCHITECTURE: "Thiết kế kiến trúc (HLD / LLD)",
    DocType.API_DB_SCHEMA: "Đặc tả API / DB Schema",
    DocType.OTHER: "Khác (checklist chung)",
}


def get_checklist(doc_type: DocType):
    """Trả về list (criteria_id, category, criteria_text) theo loại tài liệu."""
    return CHECKLISTS.get(doc_type, GENERIC_CHECKLIST)


def list_doc_types():
    return [
        {"value": dt.value, "label": DOC_TYPE_LABELS[dt], "criteria_count": len(CHECKLISTS[dt])}
        for dt in DocType
    ]
