# Người dùng Kiro: cấp quyền Bedrock qua IAM Identity Center / Kiro users: Bedrock access via IAM Identity Center

> Trạng thái nguồn: nội dung đánh dấu **[AWS doc]** đã được đối chiếu với tài liệu AWS chính thức (`docs.aws.amazon.com`, đọc 2026-11-28). Nội dung đánh dấu **[chưa xác minh]** chưa có nguồn chính thức: kiểm tra trước khi áp dụng.
> Source status: items tagged **[AWS doc]** were checked against official AWS docs (read 2026-11-28); items tagged **[unverified]** were not confirmed on a primary AWS source.
> Cross-reference: [[Per-user AI keys|AI-Per-User-Keys]], [[AI Key Rotation Runbook|AI-Key-Rotation-Runbook]]. English: [jump](#english).

---

## Tiếng Việt

### 0. Vì sao không có "tích hợp Kiro"

- VulnGuard **không** tích hợp Kiro. Không tìm thấy API suy luận công khai của Kiro để máy chủ khác gọi. Kiro API key (`ksk_…`) chỉ dùng để xác thực `kiro-cli` chạy không giao diện, không phải khoá gọi model **[chưa xác minh trên trang chính thức: trang terms của kiro.dev trả 404 khi đọc, nên điều khoản cấm dùng qua công cụ bên thứ ba chỉ có nguồn thứ cấp]**.
- Hướng hợp lệ gần nhất: dùng **cùng tổ chức AWS / IAM Identity Center** đã cấp Kiro để cấp quyền **Amazon Bedrock** cho từng người. Mỗi người có một Bedrock API key riêng, dán vào Settings › AI › Khoá AI của tôi. `kiro-cli login` chỉ đăng nhập Kiro; nó **không** tạo AWS profile có quyền Bedrock.
- Đừng dán khoá `ksk_…` của Kiro vào VulnGuard: nó không phải khoá gọi model của provider nào VulnGuard hỗ trợ.

### 1. Hạn mức dùng chung (đọc trước)

Quota Bedrock tính theo **tài khoản AWS × Region × model** **[AWS doc: quotas-runtime — "Per model, per Region", "Per account, per Region"]**. Nhiều người trong **cùng một tài khoản** dùng chung hạn mức đó dù mỗi người có key riêng. Key riêng cho bạn: phân bổ chi phí, thu hồi từng người, cô lập sự cố, nhưng **không tăng thông lượng**. Muốn tăng: xin tăng quota (mục 5), dùng cross-region inference profile, hoặc tách tài khoản theo nhóm.

### 2. Permission set trong IAM Identity Center

Permission set là mẫu chứa một hoặc nhiều IAM policy; có thể thêm **inline policy**; khi gán cho user/group ở một tài khoản, Identity Center tạo role tương ứng trong tài khoản đó **[AWS doc: singlesignon permissionsetsconcept]**. Thời lượng phiên mặc định 1 giờ, tối đa 12 giờ (đặt `Session duration` ở permission set).

Tạo permission set tên `BedrockInvoke` (Identity Center › Permission sets › Create › Custom permission set › Inline policy) với policy sau. Thay `<ACCOUNT_ID>`, danh sách Region và model/profile theo chính sách của bạn:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeClaudeViaBedrock",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:Converse",
        "bedrock:ConverseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-*",
        "arn:aws:bedrock:*:<ACCOUNT_ID>:inference-profile/*anthropic.claude-*"
      ]
    },
    {
      "Sid": "UseBedrockApiKeys",
      "Effect": "Allow",
      "Action": "bedrock:CallWithBearerToken",
      "Resource": "*"
    },
    {
      "Sid": "ListModelsForConsoleAndProbe",
      "Effect": "Allow",
      "Action": [
        "bedrock:ListFoundationModels",
        "bedrock:GetFoundationModel",
        "bedrock:ListInferenceProfiles",
        "bedrock:GetInferenceProfile"
      ],
      "Resource": "*"
    }
  ]
}
```

Giải thích và mức xác minh:
- `bedrock:CallWithBearerToken` là hành động điều khiển việc **dùng** Bedrock API key; có condition key `bedrock:bearerTokenType` (`SHORT_TERM` / `LONG_TERM`) **[AWS doc: bedrock api-keys-permissions]**. `Resource: "*"` cho statement này là lựa chọn của tài liệu này **[chưa xác minh]**; kiểm tra bảng "Actions, resources, and condition keys" của Bedrock cho resource type được hỗ trợ.
- Gọi qua **inference profile** cần cho phép cả ARN của profile **và** foundation model ở mỗi Region đích (profile địa lý: model ở Region nguồn + mọi Region đích; profile `global.`: ba ARN gồm `inference-profile/global.<model>`, `foundation-model/<model>` ở Region nguồn và `arn:aws:bedrock:::foundation-model/<model>` không có Region/tài khoản) **[AWS doc: geographic/global-cross-region-inference]**. Policy mẫu ở trên là **rộng** (`*` Region): hãy thu hẹp theo ARN thực tế của model bạn dùng; với profile `global.` cần bổ sung statement cho `arn:aws:bedrock:::foundation-model/…` và điều kiện `aws:RequestedRegion` đúng như tài liệu AWS. Danh sách action chính xác tối thiểu cho Converse/InvokeModel tuỳ model: **[chưa xác minh]**, hãy chạy thử bằng nút Test của VulnGuard.
- Nếu SCP của tổ chức chặn một Region đích thì request **thất bại** dù các Region khác được phép **[AWS doc]**.
- `ListFoundationModels`… chỉ để liệt kê model; không bắt buộc cho việc gọi model **[chưa xác minh]**.
- Model access: một số model yêu cầu bật/chấp nhận điều khoản trong Bedrock console của tài khoản trước khi gọi được **[chưa xác minh quy trình hiện tại]**. Lỗi sẽ hiện thành `NO_MODEL_ACCESS` khi Test.

Gán: Identity Center › AWS accounts › chọn tài khoản › Assign users or groups › chọn nhóm (vd `vulnguard-ai-users`, cùng nhóm đã dùng cho Kiro nếu phù hợp) › chọn permission set `BedrockInvoke`.

### 3. Tạo Bedrock API key

Có hai loại **[AWS doc: bedrock api-keys, api-keys-generate]**:

| | Short-term | Long-term |
|---|---|---|
| Hiệu lực | Tối đa 12 giờ hoặc hết phiên (cái nào ngắn hơn); chỉ dùng được ở Region đã tạo | Đến ngày hết hạn bạn đặt |
| Quyền | Thừa hưởng từ principal tạo ra nó | Gắn với một **IAM user** mới và các policy gắn vào user đó |
| AWS khuyến nghị | Dùng cho production | Chỉ nên để thử nghiệm |

VulnGuard lưu khoá để chạy job dài (Pentest run, lịch quét), nên key short-term hết hạn trong ≤ 12 giờ **không phù hợp** để lưu lâu; dùng được cho thử nghiệm ngắn. Với vận hành thật, hai hướng:

**A. Admin phát hành key long-term có hạn dùng ngắn (khuyến nghị cho triển khai nhỏ).** Trong tài khoản Bedrock, cho mỗi người một IAM user riêng (tên theo người để audit), gắn policy tối thiểu, tạo key có hạn:

```sh
aws iam create-user --user-name vg-bedrock-<ten-nguoi>
aws iam attach-user-policy --user-name vg-bedrock-<ten-nguoi> \
  --policy-arn arn:aws:iam::aws:policy/AmazonBedrockLimitedAccess      # hoặc policy tuỳ chỉnh hẹp hơn
aws iam create-service-specific-credential --user-name vg-bedrock-<ten-nguoi> \
  --service-name bedrock.amazonaws.com --credential-age-days 30
# khoá nằm ở trường ServiceApiKeyValue của kết quả; chỉ hiện một lần
```

(đúng như ví dụ CLI trong tài liệu AWS **[AWS doc: api-keys]**). Chuyển key cho người đó qua kênh an toàn, họ dán vào VulnGuard. Thu hồi: `aws iam update-service-specific-credential … --status Inactive` rồi `delete-service-specific-credential`. Đặt quy trình xoay mỗi 30–90 ngày; có thể hạn chế tuổi key tối đa bằng condition `iam:ServiceSpecificCredentialAgeDays` trong SCP/policy **[AWS doc]**. Quản trị IAM user riêng cho từng người vẫn là một gánh nặng; đổi lại có audit và thu hồi theo người.

**B. Người dùng tự tạo trong Bedrock console** (Bedrock › API keys): cần quyền IAM tạo user/credential (ví dụ `iam:CreateServiceSpecificCredential`) **[AWS doc: api-keys-permissions]**; permission set `BedrockInvoke` ở trên **không** cấp quyền IAM đó, nên thường không đủ. Chỉ cấp thêm khi hiểu rõ rủi ro.

Điều **chưa xác minh**: cách người dùng SSO tạo **short-term key** từ phiên Identity Center (console hay thư viện `aws-bedrock-token-generator`) và việc người dùng chỉ-SSO có thể tạo long-term key mà không có quyền IAM hay không. Hãy kiểm tra trên tài liệu AWS hiện hành.

Giới hạn: Bedrock API key chỉ dùng cho action Bedrock / Bedrock Runtime; **không** dùng cho `InvokeModelWithBidirectionalStream`, Agents for Bedrock, Data Automation **[AWS doc: api-keys-use]**. VulnGuard chỉ gọi suy luận nên không bị ảnh hưởng.

Chặn toàn bộ dùng key (khẩn cấp): deny `bedrock:CallWithBearerToken` (và `bedrock-mantle:CallWithBearerToken`) bằng SCP **[AWS doc]**.

### 4. Nhập vào VulnGuard

Settings › AI › Khoá AI của tôi › Thêm khoá › provider **Amazon Bedrock**: dán key, chọn `region` đúng nơi key được tạo (key short-term chỉ chạy ở Region đó), nhập **model id hoặc inference-profile id** chính xác như trong Bedrock console (ví dụ dạng `us.anthropic.claude-…`; mặc định trong VulnGuard là `anthropic.claude-opus-5-5`, **chưa xác minh** là id gọi được trực tiếp ở mọi Region, một số model mới chỉ gọi được qua inference profile). Bấm lưu: VulnGuard kiểm tra bằng một lời gọi `Converse` nhỏ trước khi lưu. Key được truyền cho client của đúng lời gọi, không đặt vào biến môi trường tiến trình.

ADMIN có thể giới hạn bằng policy `allowed`, ví dụ `["bedrock:*claude*"]`.

### 5. Quota, cross-region, tăng thông lượng

- Tăng quota: Service Quotas, quota "Cross-Region InvokeModel tokens per minute" (và on-demand tương ứng) cho model/Region của bạn; chỉ khi cột Adjustable là "Yes"; không được duyệt tự động, ưu tiên khách hàng đang dùng gần hết quota hiện có **[AWS doc: quotas-increase, quotas-runtime]**.
- Gọi qua inference profile dùng quota "cross-region" của profile (địa lý: `us.`, `eu.`, `apac.`, `in.`; toàn cầu: `global.`) thay vì quota on-demand theo Region; profile `global.` rẻ hơn khoảng 10% nhưng request có thể được xử lý ở bất kỳ Region thương mại nào được hỗ trợ **[AWS doc: cross-region-inference]**. Điều này ảnh hưởng chủ quyền dữ liệu: cân nhắc theo chính sách của công ty. Việc "gọi qua profile dùng đúng quota cross-region" là suy luận từ bảng quota, tài liệu không nêu nguyên văn **[chưa xác minh]**.
- Provisioned Throughput không dùng được với inference profile **[AWS doc]**.
- Cho cách ly thật sự theo nhóm: tách tài khoản AWS theo nhóm.

---

## English

### 0. Why there is no "Kiro integration"

- VulnGuard does **not** integrate Kiro. No public Kiro inference API was found for another server to call. Kiro API keys (`ksk_…`) only authenticate headless `kiro-cli`; they are not model-call keys. **[Unverified on the primary page: the kiro.dev terms page returned 404 when read, so the clause against third-party use is from secondary sources only.]**
- The closest legitimate path: use the **same AWS organisation / IAM Identity Center** that issues Kiro to grant **Amazon Bedrock** access per person. Each person gets their own Bedrock API key and pastes it into Settings › AI › My AI keys. `kiro-cli login` only signs in to Kiro; it does **not** create an AWS profile with Bedrock permissions.
- Do not paste Kiro `ksk_…` keys into VulnGuard: they are not model-call keys for any provider VulnGuard supports.

### 1. Shared quota (read first)

Bedrock quotas are per **AWS account × Region × model** **[AWS doc: quotas-runtime]**. Several people in the **same account** share it even with personal keys. Personal keys give cost attribution, per-person revocation and fault isolation, **not** more throughput. To get more: request quota increases (section 5), use cross-region inference profiles, or split AWS accounts per team.

### 2. Permission set

A permission set is a template of one or more IAM policies, inline policies allowed; assigning it to a user/group in an account makes Identity Center create the matching role there **[AWS doc: permissionsetsconcept]**. Session duration defaults to 1 h, max 12 h.

Create a permission set `BedrockInvoke` with the inline policy shown in the Vietnamese section 2 (same JSON). Notes and verification level:
- `bedrock:CallWithBearerToken` controls **use** of Bedrock API keys, with condition key `bedrock:bearerTokenType` (`SHORT_TERM`/`LONG_TERM`) **[AWS doc]**. Using `Resource: "*"` for it is this guide's choice **[unverified]**; check Bedrock's "Actions, resources, and condition keys" table.
- Invoking through an **inference profile** requires allowing the profile ARN **and** the foundation-model ARN in every destination Region (global profiles: three ARNs including `arn:aws:bedrock:::foundation-model/<model>` and `aws:RequestedRegion` = `unspecified` handling) **[AWS doc]**. The sample is deliberately **broad**; narrow it to your real model ARNs. A blocked destination Region in an SCP makes the request **fail** **[AWS doc]**.
- The minimum action list for Converse/InvokeModel per model **[unverified]**: use VulnGuard's Test button to confirm. `List*`/`Get*` actions are for discovery only and may not be required **[unverified]**.
- Some models need access/terms accepted in the Bedrock console first **[unverified current flow]**; it shows up as `NO_MODEL_ACCESS` on Test.

Assign: Identity Center › AWS accounts › pick the account › Assign users or groups › group (e.g. `vulnguard-ai-users`) › `BedrockInvoke`.

### 3. Creating a Bedrock API key

Two kinds **[AWS doc: api-keys, api-keys-generate]**:

| | Short-term | Long-term |
|---|---|---|
| Lifetime | ≤ 12 h or session end; usable only in the Region it was generated in | Until the expiry you set |
| Permissions | Inherited from the generating principal | A new **IAM user** and its attached policies |
| AWS advice | Recommended for production | Recommended only for exploration |

VulnGuard stores a key to run long jobs (Pentest runs, scheduled scans), so a short-term key (≤ 12 h) is unsuitable for storage. Practical options:

**A. Admin issues short-expiry long-term keys** (use the CLI block above: `create-user`, `attach-user-policy`, `create-service-specific-credential … --service-name bedrock.amazonaws.com --credential-age-days 30`; the secret is `ServiceApiKeyValue`, shown once). Deliver it securely; the person pastes it into VulnGuard. Revoke with `update-service-specific-credential --status Inactive` then `delete-service-specific-credential`. Rotate every 30–90 days; cap key age with condition `iam:ServiceSpecificCredentialAgeDays` **[AWS doc]**.

**B. Users create keys in the Bedrock console**: needs IAM permissions such as `iam:CreateServiceSpecificCredential` **[AWS doc]**, which `BedrockInvoke` does not grant; usually not enough.

**Unverified:** how an SSO-only user generates a **short-term** key from an Identity Center session (console vs the `aws-bedrock-token-generator` library), and whether SSO-only users can create long-term keys without IAM permissions. Check current AWS docs.

Limits: Bedrock API keys cover Bedrock and Bedrock Runtime actions only; not `InvokeModelWithBidirectionalStream`, Agents, Data Automation **[AWS doc]** (VulnGuard only does inference). Emergency stop: SCP deny on `bedrock:CallWithBearerToken` (and `bedrock-mantle:CallWithBearerToken`) **[AWS doc]**.

### 4. Enter it in VulnGuard

Settings › AI › My AI keys › Add key › **Amazon Bedrock**: paste the key, set `region` to where it was created, and enter the **model id or inference-profile id** exactly as shown in the Bedrock console (e.g. `us.anthropic.claude-…`). VulnGuard's default is `anthropic.claude-opus-5-5`; it is **unverified** that this id is directly invocable in every Region (newer models may require an inference profile). Save validates with a tiny `Converse` call first. The key is passed to that call's client, never placed in the process environment. ADMIN may restrict with policy `allowed`, e.g. `["bedrock:*claude*"]`.

### 5. Quota, cross-region, throughput

- Increase: Service Quotas → "Cross-Region InvokeModel tokens per minute" (and on-demand) for your model/Region, only where Adjustable = Yes; not automatic; priority goes to customers using their existing allocation **[AWS doc]**.
- Profiles: geographic (`us.`, `eu.`, `apac.`, `in.`) or `global.`; `global.` is ~10 % cheaper but may be processed in any supported commercial Region **[AWS doc]**; weigh data-residency. That calls via a profile draw on the cross-Region quota is an inference from the quota table **[unverified]**. Provisioned Throughput is not supported with inference profiles **[AWS doc]**.
- For real isolation split AWS accounts per team.
