# Compliance Mapping — Lab 24

> **Lưu ý quan trọng:** Bảng này là bản đồ học tập, không phải chứng nhận tuân thủ pháp lý.
> Các điều khoản pháp luật VN dưới đây được trích dẫn theo tên luật/nghị định; số điều cụ thể
> chỉ được ghi khi đã đối chiếu văn bản gốc. Mọi mục ghi "chưa xác minh điều khoản cụ thể"
> cần được kiểm lại với văn bản chính thức trước khi dùng trong bối cảnh pháp lý thực tế.

---

## Bảng mapping

| Nguồn / Chủ đề | Control đã thực hiện | Bằng chứng (file:dòng) | Giới hạn |
|---|---|---|---|
| **Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15** — Nguyên tắc tối thiểu hoá dữ liệu (data minimisation); xử lý dữ liệu phải có mục đích xác định *(chưa xác minh số điều cụ thể)* | PII gate `detect()`/`redact()` che CCCD, SĐT, STK, email trước khi text đi qua ranh giới Run A→B. `policy.check()` kiểm `request_purpose` phải thuộc danh sách được phép của principal. | `agent/pii.py:58–100` (detect), `agent/runner.py:83` (redact_docs), `agent/policy.py:95–104` (purpose check) | Regex chỉ bắt 4 loại PII; không nhận dạng tên người (PERSON). Purpose list là fixture giả lập, không phải hệ thống phân quyền production. |
| **Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15** — Không được chuyển dữ liệu nhạy cảm ra ngoài khi không có căn cứ hợp pháp *(chưa xác minh số điều cụ thể)* | Rule tối thiểu trong `policy.check()`: `classification="restricted" + egress_enabled=True` → DENY vô điều kiện, kể cả DPO. `http_post` không được gọi khi policy deny. | `agent/policy.py:75–82` (minimum rule), `agent/runner.py:148–169` (http_post check), `reports/attack-after.log` (0 byte) | Rule chỉ bảo vệ egress ra `127.0.0.1:10024`; môi trường production cần allowlist rộng hơn và mTLS. |
| **NĐ 356/2025/NĐ-CP** — Yêu cầu ghi nhật ký xử lý dữ liệu cá nhân, lưu trữ đủ để kiểm tra *(chưa xác minh số điều cụ thể)* | Audit ledger append-only với hash chain SHA-256. Mỗi tool call (allow và deny) ghi `ts`, `agent_id`, `run_id`, `on_behalf_of`, `tool`, `args_hash`, `decision`, `reason`. `verify()` phát hiện sửa đổi giữa file. | `agent/ledger.py:1–80`, `reports/ledger.jsonl` (94 dòng sau 2 lần chạy), `agent/ledger.py:verify()` trả `True` | Hash chain không phát hiện được xoá dòng cuối hoặc rewrite toàn file + tính lại chuỗi nếu thiếu mốc tin cậy bên ngoài. PII thô không ghi vào ledger (chỉ `args_hash`). |
| **NĐ 356/2025/NĐ-CP** — Kiểm soát truy cập theo vai trò *(chưa xác minh số điều cụ thể)* | OBO (On-Behalf-Of): quyền hiệu lực = `principal.allowed_tools ∩ agent_scopes`. `support_l1` chỉ có `search_docs`; `dpo` có `read_customer` cho `support-reply`. Delegation không thể mở rộng quyền cha. | `agent/policy.py:106–140` (scope intersection), `data/principals.json`, `tests/test_obo.py` (5/5 pass) | Principal là fixture giả lập (`data/principals.json`), không tích hợp IdP/IAM thật. `--as` là mô phỏng, không xác thực danh tính. |
| **Luật AI 134/2025/QH15** — Hệ thống AI phải có cơ chế kiểm soát và giám sát con người; không tự quyết định gây hại *(chưa xác minh số điều cụ thể)* | Trifecta split: Run A không chạm private store; Run B không đọc free text của attacker để quyết định gọi `read_customer`. Mọi tool call qua PEP trước khi thực thi. Agent không tự POST dữ liệu — policy deny ngăn bước egress. | `agent/runner.py:88–100` (ticket_id từ tên file), `agent/runner.py:103–143` (Run B tra related_tickets), `tests/test_split.py` (PASSED) | Containment là kiến trúc kỹ thuật, không phải kiểm soát pháp lý. Cần human-in-the-loop thật sự cho quyết định có hậu quả cao. |
| **Luật AI 134/2025/QH15** — Minh bạch về cách hoạt động của hệ thống AI *(chưa xác minh số điều cụ thể)* | `injection-corpus.md` ghi 4 kỹ thuật tấn công và cơ chế phòng thủ. `reports/baseline.md` mô tả trạng thái trước contain. Ledger ghi lý do mỗi quyết định. | `injection-corpus.md`, `reports/baseline.md`, `agent/ledger.py` (reason field bắt buộc) | Ledger chỉ máy đọc được (JSONL); chưa có giao diện human-readable để người dùng cuối xem. |
| **OWASP ASI01 — Prompt Injection** | Trifecta split ngăn free text của attacker ảnh hưởng đến Run B. `find_injection()` log injection nhưng không dùng `customer_ids` từ đó. Ticket ID lấy từ tên file (typed, sanitised), không từ nội dung. | `agent/runner.py:85–100` (lấy ticket_id từ tên file), `tests/test_injection.py` (8/8 pass, 4 lure × 2 principal), `tests/test_split.py` (PASSED) | Mock LLM dùng heuristic marker; model thật có thể bị bypass bằng kỹ thuật injection tinh vi hơn. |
| **OWASP ASI03 — Excessive Agency** | Agent không có quyền tự gọi `http_post` với dữ liệu nhạy cảm. `egress_enabled=True + restricted` luôn deny tại policy. Agent chỉ có 3 tool trong `_AGENT_SCOPES`; không tool nào ghi file hay gọi service ngoài. | `agent/runner.py:29` (`_AGENT_SCOPES`), `agent/policy.py:75–82` (minimum rule deny), `reports/attack-after.log` (0 byte) | Lab scope nhỏ; agent thật cần kiểm soát tool granular hơn và review định kỳ. |
| **OWASP ASI04 — Data Exfiltration** | PII bị redact trước khi đưa vào summarize. `http_post` bị chặn bởi policy trước khi tool được gọi. Sink localhost chỉ nhận request khi tool thật sự chạy — `attack-after.log` 0 byte xác nhận không có POST nào thoát ra. | `agent/runner.py:83` (pii.redact), `agent/runner.py:155–169` (http_post denied, không gọi tool), `reports/attack-after.log` (0 byte vs `reports/attack-before.log` 1196 bytes / 4 dòng) | Sink hardcode `127.0.0.1:10024`; không bảo vệ được nếu attacker kiểm soát được DNS hoặc network layer. |

---

## Nguồn tham khảo

- Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15: cần tra cứu tại [Cổng thông tin pháp điển](https://phapdien.moj.gov.vn) — chưa xác minh số điều cụ thể
- NĐ 356/2025/NĐ-CP: cần tra cứu tại Cổng thông tin Chính phủ — chưa xác minh số điều cụ thể  
- Luật AI 134/2025/QH15: cần tra cứu tại Cổng thông tin pháp điển — chưa xác minh số điều cụ thể
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/): ASI01 Prompt Injection, ASI03 Excessive Agency, ASI04 Data and Model Poisoning/Exfiltration
