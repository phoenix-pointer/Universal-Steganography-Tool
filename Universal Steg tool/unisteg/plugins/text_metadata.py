# unisteg/plugins/text_metadata.py

from __future__ import annotations
from typing import List

from ..plugin_base import BasePlugin, FileInfo, ScanResult


class TextMetadataPlugin(BasePlugin):
    name = "text_metadata"
    supported_mimetypes = ["text/plain"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = []
        with open(info.path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        if lines and lines[0].startswith("---"):
            findings.append("YAML-style front matter detected at top of file (metadata region).")
        if lines and lines[0].startswith("#!"):
            findings.append("Shebang/header line present (metadata-like; not necessarily stego).")
        if not findings:
            findings.append("No obvious structured text metadata at file start.")
        return ScanResult(file=info.path, findings=findings)

    def embed(self, info: FileInfo, payload: bytes, *, algo: str = "header", **_) -> bytes:
        raise NotImplementedError("Text metadata embedding not implemented yet")

    def extract(self, info: FileInfo, *, algo: str = "header", **_) -> bytes:
        raise NotImplementedError("Text metadata extraction not implemented yet")
