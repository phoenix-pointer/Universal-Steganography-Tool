# unisteg/plugins/audio_metadata.py

from __future__ import annotations
from typing import List

from ..plugin_base import BasePlugin, FileInfo, ScanResult


class AudioMetadataPlugin(BasePlugin):
    name = "audio_metadata"
    supported_mimetypes = ["audio/wav", "audio/mpeg"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = []

        with open(info.path, "rb") as f:
            data = f.read()

        if info.mimetype == "audio/wav":
            if data.startswith(b"RIFF") and b"LIST" in data:
                findings.append("Found RIFF LIST/INFO chunks (metadata present, may hide data).")
        elif info.mimetype == "audio/mpeg":
            if data[-128:-125] == b"TAG":
                findings.append("Detected ID3v1-style tag at end of MP3 (metadata present).")

        if not findings:
            findings.append("No obvious audio metadata markers detected.")
        return ScanResult(file=info.path, findings=findings)

    def embed(self, info: FileInfo, payload: bytes, *, algo: str = "tag", **_) -> bytes:
        raise NotImplementedError("Audio metadata embedding not implemented yet")

    def extract(self, info: FileInfo, *, algo: str = "tag", **_) -> bytes:
        raise NotImplementedError("Audio metadata extraction not implemented yet")
