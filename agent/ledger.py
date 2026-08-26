"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _compute_hash(entry_without_hash: dict) -> str:
    """Tính SHA256 hash từ entry (không có field 'hash')."""
    # Dùng sort_keys=True để thứ tự field không ảnh hưởng
    content = json.dumps(entry_without_hash, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    """Append một entry vào ledger với hash chain."""
    # Tạo thư mục cha nếu chưa có
    path.parent.mkdir(parents=True, exist_ok=True)

    # Xác định prev_hash
    if path.exists() and path.stat().st_size > 0:
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            last_line = json.loads(lines[-1])
            prev_hash = last_line.get("hash", "0" * 64)
    else:
        prev_hash = "0" * 64

    # Tạo entry mới với prev_hash
    new_entry = dict(entry)
    new_entry["prev_hash"] = prev_hash

    # Tính hash của entry (không bao gồm field 'hash')
    entry_for_hash = {k: v for k, v in new_entry.items() if k != "hash"}
    new_entry["hash"] = _compute_hash(entry_for_hash)

    # Append vào file
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(new_entry, ensure_ascii=False) + "\n")

    return new_entry


def verify(path: Path) -> bool:
    """Verify ledger tamper-evident."""
    if not path.exists() or path.stat().st_size == 0:
        return True  # Empty ledger is valid

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        return True

    prev_hash = "0" * 64

    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False

        # Kiểm tra reason non-empty
        if not entry.get("reason"):
            return False

        # Kiểm tra prev_hash
        if entry.get("prev_hash") != prev_hash:
            return False

        # Tính lại hash và so sánh
        entry_for_hash = {k: v for k, v in entry.items() if k != "hash"}
        expected_hash = _compute_hash(entry_for_hash)
        if entry.get("hash") != expected_hash:
            return False

        # Cập nhật prev_hash cho dòng tiếp theo
        prev_hash = entry.get("hash", "0" * 64)

    return True
