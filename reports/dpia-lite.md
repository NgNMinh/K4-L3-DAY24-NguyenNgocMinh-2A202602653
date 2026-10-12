# DPIA-Lite — Mô tả luồng dữ liệu (bản học tập)

> Đây là bản mô tả học tập về luồng xử lý dữ liệu trong Lab 24.
> Không phải hồ sơ đánh giá tác động bảo vệ dữ liệu (DPIA) chính thức
> theo nghĩa pháp lý. Mọi dữ liệu trong lab là **dữ liệu giả lập tổng hợp**.

---

## 1. Dữ liệu nào được xử lý?

**Corpus ticket (`corpus/ticket-*.md`):**
- Nội dung hỗ trợ khách hàng dạng Markdown
- Có thể chứa mã khách hàng (`KH-XXXXXX`), số điện thoại, email trong text tự do
- Đặc biệt: một số ticket (901–904b) chứa **chỉ thị injection giả** nhúng trong comment HTML, zero-width space, hoặc giả danh thẩm quyền

**Hồ sơ khách hàng (`data/customers.json`):**
- Dữ liệu tổng hợp giả lập: `customer_id`, `name`, `cccd` (12 số), `phone`, `bank_account`, `email`, `related_tickets`
- Phân loại: `restricted` — không được egress ra ngoài
- 26 bản ghi, trong đó `KH-000999` (Lê Thu Trang) là mục tiêu của các lure

**Ledger (`reports/ledger.jsonl`):**
- Ghi mỗi tool call: `ts`, `agent_id`, `run_id`, `on_behalf_of`, `tool`, `args_hash`, `classification`, `decision`, `reason`, `prev_hash`, `hash`
- **Không chứa PII thô** — chỉ chứa `args_hash` (SHA-256 16 ký tự đầu của tham số)

---

## 2. Ai xử lý, mục đích gì?

| Principal | Vai trò | Tool được phép | Mục đích |
|-----------|---------|---------------|---------|
| `support_l1` | Nhân viên hỗ trợ cấp 1 | `search_docs` | Tóm tắt ticket đang mở (`summarize-tickets`) |
| `dpo` | Data Protection Officer | `search_docs`, `read_customer` | Tóm tắt ticket + xem xét hồ sơ khách (`support-reply`, `privacy-audit`) |
| *(không có principal)* | — | — | `http_post` — không principal nào được egress dữ liệu restricted |

Nguồn tin cậy cho phân quyền: `data/principals.json` (fixture giả lập, không phải IdP production).

---

## 3. Dữ liệu đi qua đâu?

```
Người dùng (--as dpo)
    │
    ▼
agent/loop.py → runner.handle()
    │
    ├─ Run A: tools.search_docs(query)
    │         └─ đọc corpus/*.md (untrusted content)
    │         └─ pii.redact() trên từng doc
    │         └─ lấy ticket_id từ TÊN FILE (không từ nội dung)
    │         └─ llm.find_injection() → log nhưng bỏ qua customer_id trong text
    │
    ├─ [PEP] policy.check(search_docs) → allow/deny → ledger.append()
    │
    ├─ Run B: tra data/customers.json theo related_tickets[ticket_id]
    │         └─ [PEP] policy.check(read_customer) → allow/deny → ledger.append()
    │         └─ nếu allow: tools.read_customer(customer_id)
    │              └─ dữ liệu chỉ dùng nội bộ, không ra ngoài
    │
    ├─ [PEP] policy.check(http_post, egress=True, restricted)
    │         └─ DENY (rule tối thiểu) → ledger.append(deny)
    │         └─ tools.http_post() KHÔNG được gọi
    │
    └─ llm.summarize(redacted_docs) → trả kết quả cho người dùng

Sink (sink/sink.py tại 127.0.0.1:10024):
    └─ Chỉ nhận request nếu http_post thật sự được gọi
    └─ attack-after.log: 0 byte (không có POST nào)

Ledger (reports/ledger.jsonl):
    └─ Mọi tool call → append() với hash chain
    └─ verify() → True
```

---

## 4. Đã chặn/cho phép gì? Còn giới hạn gì?

### Đã chặn

| Mối đe doạ | Cơ chế | Bằng chứng |
|---|---|---|
| Prompt injection qua corpus | Trifecta split: Run B không đọc free text | `tests/test_split.py` PASSED; `KH-000777` không bị đọc |
| Exfil PII qua `http_post` | Rule tối thiểu: `restricted + egress → DENY` | `attack-after.log` = 0 byte; ledger có `http_post deny` |
| `support_l1` đọc hồ sơ restricted | OBO scope: `read_customer` không trong `allowed_tools` | `tests/test_obo.py` 5/5 PASSED |
| Delegation mở rộng quyền | `effective = principal ∩ agent_scopes ∩ parent_scopes` | `test_delegation_cannot_expand_parent_scope` PASSED |
| PII lộ trong tóm tắt | `pii.redact()` trước `llm.summarize()` | `agent/runner.py:83` |

### Còn giới hạn

| Giới hạn | Lý do |
|---|---|
| **Mock, không phải model thật** | `MockLLM` dùng heuristic marker; model thật (Claude) có thể bị bypass bằng injection tinh vi hơn hoặc ngôn ngữ khác |
| **Quyền giả lập** | `data/principals.json` là fixture; không tích hợp SSO/IdP/RBAC production; `--as` không xác thực danh tính thật |
| **Regex PII không toàn diện** | Bắt được CCCD/SĐT/STK/email; không nhận dạng tên người (PERSON), địa chỉ, số hợp đồng |
| **Hash chain không chặn rewrite toàn bộ** | Nếu xoá toàn bộ file và tính lại chuỗi thì `verify()` vẫn True; cần mốc tin cậy bên ngoài (timestamp server, external audit log) |
| **Sink là localhost** | `tools.http_post` hardcode `127.0.0.1:10024`; không kiểm soát được các kênh egress khác (DNS, side channel) |
| **Không có human-in-the-loop** | Policy tự động; không có bước xét duyệt của con người trước khi `read_customer` với hồ sơ nhạy cảm |
