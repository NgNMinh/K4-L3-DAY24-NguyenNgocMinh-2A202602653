"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
    verify(path: pathlib.Path) -> bool
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _hash_entry(entry_without_hash: dict) -> str:
    """SHA-256 của json.dumps(..., sort_keys=True) để thứ tự field không quan trọng."""
    serialized = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    """Lấy hash của dòng cuối cùng trong file, hoặc '000...0' nếu file rỗng/chưa có."""
    if not path.exists() or path.stat().st_size == 0:
        return "0" * 64
    last_line = ""
    with path.open(encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                last_line = stripped
    if not last_line:
        return "0" * 64
    try:
        return json.loads(last_line)["hash"]
    except (json.JSONDecodeError, KeyError):
        return "0" * 64


def append(entry: dict, path: Path) -> dict:
    """Ghi 1 dòng JSON vào ledger, kèm prev_hash và hash của dòng này.

    entry phải có tối thiểu: ts, agent_id, run_id, tool, args_hash,
    classification, decision, reason.
    Hàm tự thêm prev_hash và hash.
    Trả về dict đầy đủ đã ghi.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = _last_hash(path)

    # Xây entry đầy đủ (chưa có field "hash")
    full_entry = dict(entry)
    full_entry["prev_hash"] = prev_hash

    # Tính hash từ nội dung entry kể cả prev_hash, nhưng KHÔNG kể field "hash"
    full_entry["hash"] = _hash_entry(full_entry)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(full_entry, ensure_ascii=False) + "\n")

    return full_entry


def verify(path: Path) -> bool:
    """Kiểm toàn bộ file:
    - mọi dòng có reason non-empty
    - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so với '0'*64)
    - hash lưu trong dòng n khớp khi tính lại
    Trả False nếu bất kỳ điều kiện nào sai.
    """
    if not path.exists():
        return True  # file chưa có = hợp lệ (chưa ghi gì)

    prev_hash = "0" * 64
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError:
                return False

            # Kiểm reason không rỗng
            if not entry.get("reason"):
                return False

            # Kiểm prev_hash khớp với hash dòng trước
            if entry.get("prev_hash") != prev_hash:
                return False

            # Tính lại hash: bỏ field "hash" ra rồi tính
            stored_hash = entry.get("hash", "")
            entry_for_hash = {k: v for k, v in entry.items() if k != "hash"}
            computed = _hash_entry(entry_for_hash)
            if computed != stored_hash:
                return False

            prev_hash = stored_hash

    return True
