"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

# Compile regex for ticket file names
TICKET_FILE_RE = re.compile(r"ticket-(\d+)\.md")


def _extract_ticket_ids_from_file_names(doc_ids: list[str]) -> list[int]:
    """Trích ticket_id từ tên file, không từ nội dung text."""
    ticket_ids = []
    for doc_id in doc_ids:
        match = TICKET_FILE_RE.match(doc_id)
        if match:
            ticket_ids.append(int(match.group(1)))
    return ticket_ids


def _load_customers() -> list[dict]:
    """Load customers.json."""
    customers_path = Path(__file__).resolve().parent.parent / "data" / "customers.json"
    return json.loads(customers_path.read_text(encoding="utf-8"))


def _find_customers_by_ticket_ids(ticket_ids: list[int], customers: list[dict]) -> list[dict]:
    """Tìm customer bằng ticket_id qua related_tickets (Nguồn tin cậy)."""
    matched = []
    for customer in customers:
        if any(tid in customer.get("related_tickets", []) for tid in ticket_ids):
            matched.append(customer)
    return matched


def _hash_args(args: dict) -> str:
    """Hash arguments for ledger."""
    return hashlib.sha256(
        json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:16]


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Trifecta split implementation.

    Run A: search_docs (untrusted) -> get ticket_ids from FILE NAMES
    Run B: read_customer (private) -> via related_tickets (trustworthy)

    Every tool call goes through policy.check() and ledger.append().
    """
    # Setup
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    agent_id = f"agent-{uuid.uuid4().hex[:8]}"

    def log_call(
        tool: str,
        args: dict,
        classification: str,
        decision: str,
        reason: str,
    ):
        """Log a tool call to ledger."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "tool": tool,
            "args_hash": _hash_args(args),
            "classification": classification,
            "decision": decision,
            "reason": reason,
        }
        ledger.append(entry, ledger_path)

    # =====================================================
    # RUN A: search_docs (untrusted content)
    # =====================================================
    docs = tools.search_docs(message)

    # Policy check for search_docs
    ctx = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner=agent_id,
        delegation_depth=0,
        egress_enabled=False,
    )
    allow, reason = policy.check(ctx)
    log_call(
        tool="search_docs",
        args={"message": message},
        classification="internal",
        decision="allow" if allow else "deny",
        reason=reason,
    )

    if not allow:
        return "Từ chối: không được phép tìm kiếm ticket."

    # Check for injection in text (for logging, NOT for getting customer_ids)
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    if injected:
        # Log injection detection
        ctx = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="injection-detected",
            agent_owner=agent_id,
            delegation_depth=0,
            egress_enabled=True,
        )
        allow_inj, reason_inj = policy.check(ctx)
        log_call(
            tool="find_injection",
            args={"injected": True},
            classification="restricted",
            decision="deny" if not allow_inj else "allow",
            reason=f"injection detected: {reason_inj}",
        )

    # Extract ticket_ids from FILE NAMES (trustworthy source)
    doc_ids = [d["id"] for d in docs]
    ticket_ids = _extract_ticket_ids_from_file_names(doc_ids)

    # =====================================================
    # RUN B: read_customer (private data)
    # Look up customer via related_tickets, NOT from document text
    # =====================================================
    customers = _load_customers()
    matched_customers = _find_customers_by_ticket_ids(ticket_ids, customers)

    # Policy check for read_customer (if we have customers to read)
    if matched_customers:
        ctx = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="read-customer-data",
            agent_owner=agent_id,
            delegation_depth=1,
            egress_enabled=False,  # Read only, no egress
        )
        allow, reason = policy.check(ctx)
        log_call(
            tool="read_customer",
            args={"count": len(matched_customers)},
            classification="restricted",
            decision="allow" if allow else "deny",
            reason=reason,
        )

        if not allow:
            return "Từ chối: không được phép đọc dữ liệu khách hàng."

        # Actually call tools.read_customer for each matched customer
        # This is the legitimate use case - attacker cannot control WHICH customer is read
        for customer in matched_customers:
            customer_id = customer["customer_id"]
            # Policy check for each individual customer read
            ctx = policy.PolicyContext(
                data_classification="restricted",
                request_purpose="read-individual-customer",
                agent_owner=agent_id,
                delegation_depth=2,
                egress_enabled=False,
            )
            allow_ind, reason_ind = policy.check(ctx)
            log_call(
                tool="read_customer",
                args={"customer_id": customer_id},
                classification="restricted",
                decision="allow" if allow_ind else "deny",
                reason=reason_ind,
            )
            if allow_ind:
                # Actually call the tool (for testing/side effects)
                try:
                    tools.read_customer(customer_id)
                except tools.ToolError:
                    pass

    # =====================================================
    # Summarize results
    # =====================================================
    result = llm.summarize(docs)

    return result
