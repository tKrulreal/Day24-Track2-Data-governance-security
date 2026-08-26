# DPIA-lite (1 trang)

## 1. Dữ liệu gì

Agent chạm vào các loại dữ liệu sau:

| Tool | Dữ liệu | Phân loại |
|------|----------|-----------|
| `search_docs` | Nội dung ticket từ corpus/ | Internal (có thể chứa PII attacker ghi vào) |
| `read_customer` | Tên, CCCD (12 số), SĐT, STK ngân hàng, email | **Restricted** (PII khách hàng) |

PII được phát hiện bằng regex trong `agent/pii.py`:
- CCCD: `\d{12}`
- SĐT: `0\d{9,10}`
- STK: `\d{8,16}` (khi có context "STK"/"tài khoản")
- Email: standard email pattern

## 2. Mục đích gì

Agent được thiết kế để:
- **search_docs**: Tìm kiếm ticket hỗ trợ khách hàng theo query
- **read_customer**: Lấy thông tin khách hàng để trả lời yêu cầu hỗ trợ

**Cơ sở pháp lý xử lý**: Hợp đồng dịch vụ khách hàng, hỗ trợ sau bán hàng.

## 3. Chảy đi đâu

### 3.1. Nội bộ (lab)

| Đích | Dữ liệu | Control |
|------|----------|---------|
| `reports/sink.log` | POST body chứa PII | Chặn bởi `policy.py` + `runner.py` trifecta split |
| `reports/ledger.jsonl` | Hash chain của mọi tool call | Append-only, tamper-evident |

### 3.2. Xuyên biên giới (nếu dùng --model)

**Nếu dùng `--model claude-opus-5` hoặc `--model claude-haiku-4-5`**:
- Dữ liệu (query + corpus content) được gửi đến Anthropic API (US)
- Đây là **chuyển dữ liệu xuyên biên giới** theo NĐ 356/2025
- **Control**: Không có egress control khi dùng model thật (chỉ có trong lab)
- **Recommendation**: Nếu dùng thật, cần:
  - Mã hóa dữ liệu truyền đi (TLS)
  - Ký BAA với Anthropic
  - Giới hạn retention của model provider

### 3.3. Trong lab (--mock)

Với `--mock` (default, dùng cho chấm điểm):
- Không có dữ liệu ra khỏi hệ thống
- Sink tại localhost:9999 chỉ để mô phỏng exfiltration
- Ledger ghi tất cả tool call để audit
