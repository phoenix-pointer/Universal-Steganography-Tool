# unisteg/plugins/image_appended.py

from __future__ import annotations
from typing import List

from ..plugin_base import BasePlugin, FileInfo, ScanResult


class ImageAppendedPlugin(BasePlugin):
    name = "image_appended"
    supported_mimetypes = ["image/png", "image/jpeg", "image/bmp"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = []
        with open(info.path, "rb") as f:
            data = f.read()

        if info.mimetype == "image/png":
            marker = b"IEND"
            idx = data.rfind(marker)
            if idx != -1:
                end_pos = idx + 8  # heuristic: 'IEND'(4) + CRC(4)
                if end_pos < len(data):
                    extra_len = len(data) - end_pos
                    findings.append(
                        f"Detected {extra_len} extra bytes after PNG IEND (possible appended payload)."
                    )
                else:
                    findings.append("No extra data after PNG IEND.")
            else:
                findings.append("Could not locate PNG IEND; file may be malformed.")
        else:
            tail = data[-2048:] if len(data) > 2048 else data
            if any(b != 0x00 for b in tail):
                findings.append(
                    "Non-zero tail data detected; may indicate appended payload or normal padding."
                )
            else:
                findings.append("Tail mostly zero; no obvious appended data.")

        return ScanResult(file=info.path, findings=findings)

    def embed(self, info: FileInfo, payload: bytes, *, algo: str = "append", **_) -> bytes:
        with open(info.path, "rb") as f:
            original = f.read()
        out_data = original + payload
        out_path = info.path + ".appended"
        with open(out_path, "wb") as f:
            f.write(out_data)
        return out_data

    def extract(self, info: FileInfo, *, algo: str = "append", length: int | None = None, **_) -> bytes:
        if length is None:
            raise ValueError("Pass payload length (bytes) for appended-data extraction.")
        with open(info.path, "rb") as f:
            data = f.read()
        return data[-length:]
