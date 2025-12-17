# unisteg/plugins/text_appended.py

from __future__ import annotations
from typing import List

from ..plugin_base import BasePlugin, FileInfo, ScanResult


class TextAppendedPlugin(BasePlugin):
    name = "text_appended"
    supported_mimetypes = ["text/plain"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = []
        with open(info.path, "rb") as f:
            data = f.read()

        # look at last 1 KB for non-printable junk
        tail = data[-1024:] if len(data) > 1024 else data
        non_printable = sum(1 for b in tail if b < 9 or (13 < b < 32))
        if non_printable:
            findings.append(
                f"Detected {non_printable} non-printable bytes near end of file (possible binary payload)."
            )
        else:
            findings.append("No obvious binary trailer in text tail.")
        return ScanResult(file=info.path, findings=findings)

    def embed(self, info: FileInfo, payload: bytes, *, algo: str = "append", **_) -> bytes:
        with open(info.path, "rb") as f:
            original = f.read()
        marker = b"\n---STEG-END---\n"
        out_data = original + marker + payload
        out_path = info.path + ".tapp"
        with open(out_path, "wb") as f:
            f.write(out_data)
        return out_data

    def extract(self, info: FileInfo, *, algo: str = "append", **_) -> bytes:
        with open(info.path, "rb") as f:
            data = f.read()
        marker = b"\n---STEG-END---\n"
        idx = data.rfind(marker)
        if idx == -1:
            raise ValueError("Marker not found; no appended payload in text.")
        return data[idx + len(marker) :]
