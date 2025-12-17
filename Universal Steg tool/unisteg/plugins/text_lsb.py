# unisteg/plugins/text_lsb.py

from __future__ import annotations
from typing import List

from ..plugin_base import BasePlugin, FileInfo, ScanResult


ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u200e", "\u200f"}


class TextLSBPlugin(BasePlugin):
    name = "text_lsb"
    supported_mimetypes = ["text/plain"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = []
        with open(info.path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        zw_count = sum(1 for ch in text if ch in ZERO_WIDTH)
        trailing_spaces = sum(1 for line in text.splitlines() if line.rstrip() != line)

        if zw_count:
            findings.append(f"Detected {zw_count} zero-width characters (possible unicode stego).")
        if trailing_spaces:
            findings.append(f"Detected {trailing_spaces} lines with trailing whitespace.")
        if not findings:
            findings.append("No obvious zero-width or whitespace stego indicators.")
        return ScanResult(file=info.path, findings=findings)

    def embed(self, info: FileInfo, payload: bytes, *, algo: str = "zw", **_) -> bytes:
        raise NotImplementedError("Text embedding not implemented yet")

    def extract(self, info: FileInfo, *, algo: str = "zw", **_) -> bytes:
        raise NotImplementedError("Text extraction not implemented yet")
