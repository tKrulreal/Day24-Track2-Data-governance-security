"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Regex patterns cho các loại PII Việt Nam
VN_CCCD_PATTERN = re.compile(r"\b(\d{12})\b")
VN_PHONE_PATTERN = re.compile(r"\b0\d{9,10}\b")
VN_BANK_ACCOUNT_PATTERN = re.compile(r"\b\d{8,16}\b")
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện PII trong văn bản.

    Returns: list[{"type": str, "start": int, "end": int}]
    """
    entities = []

    # CCCD - 12 chữ số
    for match in VN_CCCD_PATTERN.finditer(text):
        entities.append({
            "type": "VN_CCCD",
            "start": match.start(),
            "end": match.end(),
        })

    # Số điện thoại Việt Nam - 0 + 9-10 chữ số
    for match in VN_PHONE_PATTERN.finditer(text):
        # Tránh match CCCD (12 số bắt đầu bằng 0 có thể trùng)
        # Kiểm tra độ dài cụ thể
        num = match.group()
        if len(num) >= 10:  # 10-11 số
            entities.append({
                "type": "VN_PHONE",
                "start": match.start(),
                "end": match.end(),
            })

    # Số tài khoản ngân hàng - 8-16 chữ số
    for match in VN_BANK_ACCOUNT_PATTERN.finditer(text):
        num = match.group()
        # Kiểm tra context xung quanh có từ "STK" hoặc "tài khoản"
        start = max(0, match.start() - 20)
        end = min(len(text), match.end() + 5)
        context = text[start:end].lower()
        if "stk" in context or "tài khoản" in context or "số tk" in context:
            entities.append({
                "type": "VN_BANK_ACCOUNT",
                "start": match.start(),
                "end": match.end(),
            })

    # Email
    for match in EMAIL_PATTERN.finditer(text):
        entities.append({
            "type": "EMAIL",
            "start": match.start(),
            "end": match.end(),
        })

    return entities


def redact(text: str) -> str:
    """Thay thế PII bằng [REDACTED_TYPE].

    Thay từ cuối văn bản về đầu để offset không bị lệch.
    """
    entities = detect(text)
    if not entities:
        return text

    # Sắp xếp theo start descending (từ cuối về đầu)
    entities.sort(key=lambda e: e["start"], reverse=True)

    result = text
    for entity in entities:
        placeholder = f"[REDACTED_{entity['type']}]"
        result = result[:entity["start"]] + placeholder + result[entity["end"]:]

    return result
