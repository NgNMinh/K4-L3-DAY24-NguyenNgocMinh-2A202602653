"""BƯỚC 3c — trifecta split + OBO + PEP + ledger.

handle(message, llm, log_dir, principal_id) thực hiện:

    Run A: search_docs (untrusted content) — KHÔNG đọc private store,
           KHÔNG egress. Lấy ticket_id từ TÊN FILE (không từ free text).

    Run B: với mỗi ticket_id từ Run A, tra customers.json tìm customer
           có ticket_id trong related_tickets → read_customer hợp lệ.
           PEP (policy.check) đặt ngay trước read_customer.
           Mọi quyết định (allow/deny) ghi ledger.

Kiến trúc này chống injection vì Run B không bao giờ đọc free text của
attacker để quyết định gọi ai.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"

# Scopes cố định của agent này
_AGENT_SCOPES = ("search_docs", "read_customer", "http_post")
_AGENT_ID = "lab24-agent"

# TTL mỗi run: 1 giờ kể từ lúc handle() được gọi
_RUN_TTL_SECONDS = 3600


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_customers() -> list[dict]:
    return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))


def _ticket_id_from_filename(filename: str) -> int | None:
    """Trích số nguyên từ tên file kiểu 'ticket-007.md' → 7."""
    stem = Path(filename).stem          # "ticket-007"
    parts = stem.split("-")
    for part in reversed(parts):
        if part.isdigit():
            return int(part)
    return None


def _customers_for_ticket(ticket_id: int, customers: list[dict]) -> list[dict]:
    """Tra customers.json: ai có ticket_id trong related_tickets?"""
    return [c for c in customers if ticket_id in c.get("related_tickets", [])]


def _args_hash(*args) -> str:
    """Hash ngắn gọn các argument để ghi ledger (không ghi PII thô)."""
    raw = json.dumps(args, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# handle()
# ---------------------------------------------------------------------------

def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Điểm vào chính: Run A → Run B với PEP + ledger trước mỗi tool call."""

    log_dir = Path(log_dir) if log_dir else REPORTS_DIR
    ledger_path = log_dir / "ledger.jsonl"

    run_id = str(uuid.uuid4())
    now = datetime.now(tz=timezone.utc)
    expires_at = (now + timedelta(seconds=_RUN_TTL_SECONDS)).isoformat()
    ts = now.isoformat()

    # ------------------------------------------------------------------
    # Run A — search_docs (untrusted content, không egress, không private)
    # ------------------------------------------------------------------
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{_AGENT_ID}/{run_id}",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=_AGENT_SCOPES,
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)
    ledger.append({
        "ts": ts,
        "agent_id": _AGENT_ID,
        "run_id": run_id,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
        "tool": "search_docs",
        "args_hash": _args_hash(message),
        "classification": "internal",
        "decision": "allow" if allow_search else "deny",
        "reason": reason_search,
    }, ledger_path)

    if not allow_search:
        return f"Không thể tìm ticket: {reason_search}"

    docs = tools.search_docs(message)

    # Redact PII trong nội dung trước khi đưa vào summarize / context
    redacted_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]

    # Log injection nếu có (không dùng customer_id từ free text)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injection = llm.find_injection(combined_text)
    if injection:
        ledger.append({
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "agent_id": _AGENT_ID,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "find_injection",
            "args_hash": _args_hash(combined_text[:64]),
            "classification": "internal",
            "decision": "logged",
            "reason": (
                f"Phát hiện injection markers={injection.matched_markers}; "
                "customer_ids từ free text BỊ BỎ QUA — Run B sẽ tra related_tickets."
            ),
        }, ledger_path)

    # Lấy ticket_id từ TÊN FILE (không từ nội dung)
    ticket_ids: list[int] = []
    for doc in docs:
        tid = _ticket_id_from_filename(doc["id"])
        if tid is not None:
            ticket_ids.append(tid)

    # ------------------------------------------------------------------
    # Run B — tra customers.json từ ticket_id → read_customer với PEP
    # ------------------------------------------------------------------
    customers = _load_customers()
    collected: list[dict] = []

    for ticket_id in ticket_ids:
        matched_customers = _customers_for_ticket(ticket_id, customers)
        for customer in matched_customers:
            cid = customer["customer_id"]

            ctx_read = PolicyContext(
                data_classification="restricted",
                request_purpose="support-reply",
                agent_owner=f"{_AGENT_ID}/{run_id}",
                delegation_depth=0,
                egress_enabled=False,
                principal_id=principal_id,
                requested_tool="read_customer",
                agent_scopes=_AGENT_SCOPES,
                expires_at=expires_at,
            )
            allow_read, reason_read = policy.check(ctx_read)
            ledger.append({
                "ts": datetime.now(tz=timezone.utc).isoformat(),
                "agent_id": _AGENT_ID,
                "run_id": run_id,
                "on_behalf_of": principal_id,
                "expires_at": expires_at,
                "tool": "read_customer",
                "args_hash": _args_hash(cid),
                "classification": "restricted",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
            }, ledger_path)

            if allow_read:
                try:
                    record = tools.read_customer(cid)
                    collected.append(record)
                except tools.ToolError:
                    pass

    # ------------------------------------------------------------------
    # http_post check — kiểm policy khi injection yêu cầu gửi dữ liệu
    # Chỉ dùng URL từ injection (không mang hồ sơ khách).
    # Rule tối thiểu (restricted + egress) luôn deny — không gọi tool.
    # ------------------------------------------------------------------
    if injection is not None:
        target_url = injection.target_url
        ctx_post = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{_AGENT_ID}/{run_id}",
            delegation_depth=0,
            egress_enabled=True,   # http_post = egress
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=_AGENT_SCOPES,
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        ledger.append({
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "agent_id": _AGENT_ID,
            "run_id": run_id,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
            "tool": "http_post",
            "args_hash": _args_hash(target_url),
            "classification": "restricted",
            "decision": "allow" if allow_post else "deny",
            "reason": reason_post,
        }, ledger_path)
        if allow_post:
            # Không nên xảy ra với rule tối thiểu, nhưng nếu policy được
            # mở rộng sau này: vẫn cần gọi đúng — chỉ truyền URL, không body PII
            try:
                tools.http_post(target_url, {})
            except Exception:
                pass

    return llm.summarize(redacted_docs)
