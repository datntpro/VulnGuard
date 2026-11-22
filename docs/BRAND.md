# VulnGuard Brand System — "Sentinel"

Bộ nhận diện v2 cho VulnGuard. Token nằm trong `web/brand.css`, logo trong `web/assets/logo.svg`.

## Ý tưởng
**Sentinel** (lính canh) — một tấm khiên với 2 tia quét hội tụ thành chữ **V**.
Chủ đề: *"Bảo mật từ code đến hạ tầng — chạy local, AI hỗ trợ."*

## Màu
| Token | Hex | Dùng cho |
|---|---|---|
| `--brand-500` | `#5B5BF7` | Sentinel Indigo — màu chính |
| `--signal-400` | `#2DD4E8` | Scan Cyan — nhấn, "tia quét" |
| `--brand-gradient` | indigo→cyan 135° | nút chính, logo, tiêu đề |

Severity giữ cố định giữa light/dark: critical `#F43F5E`, high `#FB8A3C`, medium `#F5C443`, low `#34D399`, info `#60A5FA`.

Nền tối (mặc định): `--bg #090D18`, card `--bg2 #0F1524`. Có theme sáng + theo hệ thống (toggle ở sidebar, lưu localStorage).

## Chữ
- **Be Vietnam Pro** — giao diện (hỗ trợ tiếng Việt tốt).
- **JetBrains Mono** — code, path, CVE.

## Chuyển động (motion)
Nhanh, tiết chế, easing expo-out. Primitive trong `brand.css`:
`.vg-enter` (fade-up khi đổi trang), `.vg-stagger` (lần lượt cho lưới thẻ),
`.vg-lift` (nhấc nhẹ khi hover card/nút), `.vg-skeleton` (shimmer khi tải),
`.vg-live-dot` (chấm nhịp cho trạng thái realtime), `.vg-gradient-text`.
Thời lượng 140–480ms. Tôn trọng `prefers-reduced-motion`.

## Logo
`web/assets/logo.svg` — khiên gradient + chữ V (2 tia quét) + đường scan ngang.
Dùng kèm wordmark "VulnGuard" (Guard tô gradient).
