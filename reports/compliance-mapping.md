# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement, xem stretch goal #3 | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data flow inventory qua ledger | `reports/dpia-lite.md` §2, `agent/ledger.py` |
| ASI03 — privilege abuse | Per-agent identity + TTL trong ledger | `agent/policy.py` lines 39-52, ledger field `agent_id` |
| ASI01 — goal hijack | Trifecta split trong runner | `agent/runner.py` lines 39-46 (ticket extraction), `reports/attack-after.log` |
| ISO 42001 Clause 5-6 | Policy-as-code có review | Git log của `agent/policy.py` |
