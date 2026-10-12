"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Principals store (fixture mô phỏng, load một lần khi import)
# ---------------------------------------------------------------------------

_PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"

def _load_principals() -> dict:
    try:
        return json.loads(_PRINCIPALS_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}

_PRINCIPALS: dict = _load_principals()

_VALID_CLASSIFICATIONS = {"public", "internal", "restricted"}


# ---------------------------------------------------------------------------
# PolicyContext
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


# ---------------------------------------------------------------------------
# check()
# ---------------------------------------------------------------------------

def check(context: PolicyContext) -> tuple[bool, str]:
    """Trả (allow, reason). reason luôn là chuỗi không rỗng."""

    # ------------------------------------------------------------------
    # 1. Kiểm data_classification hợp lệ
    # ------------------------------------------------------------------
    if context.data_classification not in _VALID_CLASSIFICATIONS:
        return False, (
            f"data_classification không hợp lệ: '{context.data_classification}'. "
            f"Chỉ chấp nhận: {sorted(_VALID_CLASSIFICATIONS)}."
        )

    # ------------------------------------------------------------------
    # 2. Rule tối thiểu: restricted + egress → DENY (kể cả DPO)
    # ------------------------------------------------------------------
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, (
            "DENY — rule tối thiểu: dữ liệu classified='restricted' không được "
            "phép gửi ra ngoài (egress_enabled=True). Rule này không có ngoại lệ "
            "theo principal hay purpose."
        )

    # ------------------------------------------------------------------
    # 3. Kiểm TTL (expires_at)
    # ------------------------------------------------------------------
    if context.expires_at:
        try:
            expires = datetime.fromisoformat(context.expires_at)
            # Đảm bảo so sánh timezone-aware
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if datetime.now(tz=timezone.utc) > expires:
                return False, (
                    f"DENY — phiên làm việc đã hết hạn lúc {context.expires_at}. "
                    "Yêu cầu token/session mới."
                )
        except ValueError:
            return False, (
                f"DENY — expires_at có định dạng không hợp lệ: '{context.expires_at}'. "
                "Yêu cầu ISO-8601 UTC."
            )

    # ------------------------------------------------------------------
    # 4. Kiểm principal_id (khi có requested_tool — OBO check)
    # ------------------------------------------------------------------
    if context.requested_tool or context.principal_id:
        # 4a. principal phải tồn tại trong store
        if not context.principal_id or context.principal_id not in _PRINCIPALS:
            return False, (
                f"DENY — principal '{context.principal_id}' không tồn tại hoặc "
                "chưa được cấp quyền. Kiểm lại data/principals.json."
            )

        principal = _PRINCIPALS[context.principal_id]

        # 4b. Kiểm purpose
        if context.request_purpose:
            allowed_purposes: list[str] = principal.get("purposes", [])
            if allowed_purposes and context.request_purpose not in allowed_purposes:
                return False, (
                    f"DENY — principal '{context.principal_id}' không có quyền "
                    f"thực hiện purpose '{context.request_purpose}'. "
                    f"Các purpose được phép: {allowed_purposes}."
                )

        # 4c. Kiểm tool với scope intersection (OBO)
        if context.requested_tool:
            principal_tools: set[str] = set(principal.get("allowed_tools", []))

            # Quyền hiệu lực = principal_tools ∩ agent_scopes
            if context.agent_scopes:
                effective = principal_tools & set(context.agent_scopes)
            else:
                effective = principal_tools

            # Nếu delegation_depth > 0: còn giao với parent_scopes
            if context.delegation_depth > 0:
                if context.parent_scopes:
                    effective = effective & set(context.parent_scopes)
                else:
                    # Không có parent_scopes nhưng là delegated call → deny
                    # (không thể xác định quyền cha)
                    return False, (
                        f"DENY — delegation_depth={context.delegation_depth} "
                        "nhưng parent_scopes rỗng; không thể tính quyền hiệu lực. "
                        "Agent cha phải truyền explicit scopes."
                    )

            if context.requested_tool not in effective:
                return False, (
                    f"DENY — tool '{context.requested_tool}' nằm ngoài quyền "
                    f"hiệu lực của principal '{context.principal_id}'. "
                    f"Quyền hiệu lực: {sorted(effective) if effective else '∅'}. "
                    f"(principal={sorted(principal_tools)}, "
                    f"agent_scopes={sorted(context.agent_scopes)}"
                    + (f", parent_scopes={sorted(context.parent_scopes)}"
                       if context.delegation_depth > 0 else "")
                    + ")."
                )

    # ------------------------------------------------------------------
    # 5. Allow — tất cả điều kiện đã hợp lệ
    # ------------------------------------------------------------------
    parts = [
        f"ALLOW — classification='{context.data_classification}'",
        f"egress={context.egress_enabled}",
        f"principal='{context.principal_id or '(none)'}'",
    ]
    if context.requested_tool:
        parts.append(f"tool='{context.requested_tool}'")
    if context.request_purpose:
        parts.append(f"purpose='{context.request_purpose}'")
    if context.delegation_depth > 0:
        parts.append(f"delegation_depth={context.delegation_depth}")

    return True, ", ".join(parts) + "."
