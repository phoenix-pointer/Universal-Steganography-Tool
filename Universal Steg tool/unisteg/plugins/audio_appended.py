# unisteg/plugins/audio_appended.py

from __future__ import annotations
from typing import List

from ..plugin_base import BasePlugin, FileInfo, ScanResult


class AudioAppendedPlugin(BasePlugin):
    name = "audio_appended"
    supported_mimetypes = ["audio/wav", "audio/mpeg"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = []
        with open(info.path, "rb") as f:
            data = f.read()

        tail = data[-4096:] if len(data) > 4096 else data
        if any(b != 0x00 for b in tail):
            findings.append(
                "Non-zero tail data detected; may indicate appended payload beyond normal audio frames."
            )
        else:
            findings.append("Tail mostly zero; no obvious appended data.")
        return ScanResult(file=info.path, findings=findings)

    def embed(self, info: FileInfo, payload: bytes, *, algo: str = "append", **_) -> bytes:
        with open(info.path, "rb") as f:
            original = f.read()
        out_data = original + payload
        out_path = info.path + ".aapp"
        with open(out_path, "wb") as f:
            f.write(out_data)
        return out_data

    def extract(self, info: FileInfo, *, algo: str = "append", length: int | None = None, **_) -> bytes:
        if length is None:
            raise ValueError("Pass payload length (bytes) for audio appended extract")
        with open(info.path, "rb") as f:
            data = f.read()
        return data[-length:]
