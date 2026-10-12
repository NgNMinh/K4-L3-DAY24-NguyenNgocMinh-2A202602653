"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Interface bắt buộc:

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        type: "VN_CCCD" | "VN_PHONE" | "VN_BANK_ACCOUNT" | "EMAIL"
        start/end là offset ký tự trong text (Python slice: text[start:end]).

    redact(text: str) -> str
        Thay mọi entity bằng "[REDACTED_<TYPE>]".
        Thay từ cuối chuỗi về đầu để offset không bị lệch.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# VN_CCCD: đúng 12 chữ số liên tiếp, không liền với chữ số khác ở hai đầu
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

# VN_PHONE: bắt đầu bằng 0, tổng 10 chữ số (có thể có dấu cách/gạch giữa
# các nhóm). Dạng phổ biến: 0xxx xxx xxx hoặc 0xxxxxxxxx.
# Dùng lookahead/lookbehind để không bắt chữ số đứng sát ở ngoài.
_PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(0\d[\s\-]?\d{4}[\s\-]?\d{4}"  # 0xx xxxx xxxx (10 số)
    r"|0\d{3}[\s\-]?\d{3}[\s\-]?\d{3}"  # 0xxx xxx xxx (10 số)
    r"|0\d{9})"  # 0xxxxxxxxx (10 số liên tiếp)
    r"(?!\d)"
)

# VN_BANK_ACCOUNT: 8–16 chữ số, phải có nhãn STK / số tài khoản / tài khoản
# đứng trước (trong 30 ký tự). Dùng pattern có lookbehind giới hạn độ dài.
# Vì lookbehind Python phải fixed-width, dùng cách ghép context thủ công.
_BANK_LABEL_RE = re.compile(
    r"(?:STK|số\s+tài\s+khoản|tài\s+khoản|stk)"
    r"[\s:]*"
    r"(\d{8,16})"
    r"(?!\d)",
    re.IGNORECASE | re.UNICODE,
)

# EMAIL: local@domain.tld — đủ rộng cho các biến thể .vn, .com, v.v.
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.ASCII,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _no_overlap(entities: list[dict], new: dict) -> bool:
    """Trả True nếu new không chồng với bất kỳ entity nào đã có."""
    for e in entities:
        if new["start"] < e["end"] and e["start"] < new["end"]:
            return False
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect(text: str) -> list[dict]:
    """Trả danh sách {"type", "start", "end"} cho mọi PII tìm thấy trong text."""
    entities: list[dict] = []

    # --- EMAIL (ưu tiên trước để tránh phần số trong địa chỉ bị bắt nhầm) ---
    for m in _EMAIL_RE.finditer(text):
        e = {"type": "EMAIL", "start": m.start(), "end": m.end()}
        if _no_overlap(entities, e):
            entities.append(e)

    # --- VN_BANK_ACCOUNT (trước CCCD vì bank 12 số sẽ bị CCCD chiếm mất nếu để sau) ---
    for m in _BANK_LABEL_RE.finditer(text):
        # group(1) là phần số thực sự
        start = m.start(1)
        end = m.end(1)
        e = {"type": "VN_BANK_ACCOUNT", "start": start, "end": end}
        if _no_overlap(entities, e):
            entities.append(e)

    # --- VN_CCCD (sau bank để tránh bắt nhầm số tài khoản 12 chữ số) ---
    for m in _CCCD_RE.finditer(text):
        e = {"type": "VN_CCCD", "start": m.start(), "end": m.end()}
        if _no_overlap(entities, e):
            entities.append(e)

    # --- VN_PHONE ---
    for m in _PHONE_RE.finditer(text):
        # Lấy toàn bộ match, chuẩn hoá start/end (bỏ khoảng trắng dẫn đầu)
        raw = m.group(0)
        start = m.start() + len(raw) - len(raw.lstrip())
        end = m.end()
        e = {"type": "VN_PHONE", "start": start, "end": end}
        if _no_overlap(entities, e):
            entities.append(e)

    # Sắp xếp theo vị trí xuất hiện
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay mọi PII phát hiện được bằng [REDACTED_<TYPE>].

    Thay từ cuối chuỗi về đầu để offset các vùng chưa xử lý không bị lệch.
    """
    entities = detect(text)
    # Sắp xếp ngược (cuối trước)
    for e in sorted(entities, key=lambda x: x["start"], reverse=True):
        placeholder = f"[REDACTED_{e['type']}]"
        text = text[: e["start"]] + placeholder + text[e["end"] :]
    return text
