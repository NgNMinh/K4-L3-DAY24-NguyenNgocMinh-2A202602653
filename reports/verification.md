# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:

---

## CP3a — PII detection (agent/pii.py)

**Lệnh chạy:**
```
.venv/Scripts/python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp
```

**Kết quả:**
- gold = 118 (số vùng PII được gán nhãn trong testset)
- pred = 118 (số vùng code tìm ra)
- tp   = 118 (số vùng tìm đúng)
- precision = 1.000
- recall    = 1.000

**Bộ pattern regex đã dùng:**

| Loại | Pattern | Ghi chú |
|------|---------|---------|
| `VN_CCCD` | `(?<!\d)\d{12}(?!\d)` | Đúng 12 số, không liền số khác hai đầu |
| `VN_PHONE` | `0\d{9}` và các biến thể có dấu cách/gạch | 10 số bắt đầu bằng 0 |
| `VN_BANK_ACCOUNT` | `(?:STK\|số tài khoản\|...)[\s:]*(\d{8,16})(?!\d)` | Yêu cầu nhãn đứng trước |
| `EMAIL` | `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` | Dạng chuẩn |

**Thứ tự ưu tiên khi overlap:** EMAIL → VN_BANK_ACCOUNT → VN_CCCD → VN_PHONE.
Quan trọng: bank account phải được detect *trước* CCCD vì số tài khoản 12 chữ số
khớp cả hai pattern; khi có nhãn STK/tài khoản đứng trước, ưu tiên bank.

**Giới hạn của regex:**
- `VN_PHONE` chỉ bắt số bắt đầu bằng `0` (10 số) — không bắt đầu số quốc tế `+84`.
- `VN_BANK_ACCOUNT` yêu cầu nhãn `STK`/`số tài khoản` đứng trước — số tài khoản
  xuất hiện không có nhãn (ví dụ trong câu tự do) sẽ bị bỏ qua để tránh false positive
  với số CCCD 12 số.
- `VN_CCCD` không phân biệt được CCCD thật với chuỗi số ngẫu nhiên 12 chữ số nếu
  không có nhãn đi kèm — có thể gây false positive trong văn bản số học thuần tuý.
- Không hỗ trợ nhận dạng tên người (PERSON entity) — cần NER/spaCy cho stretch goal.
