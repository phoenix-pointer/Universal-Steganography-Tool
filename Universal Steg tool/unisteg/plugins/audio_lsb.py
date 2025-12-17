# unisteg/plugins/audio_lsb.py

from __future__ import annotations
import wave
from pathlib import Path
from typing import Any, List

from ..plugin_base import BasePlugin, FileInfo, ScanResult


class AudioLSBPlugin(BasePlugin):
    name = "audio_lsb"
    supported_mimetypes = ["audio/wav"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = [
            "WAV audio is commonly used for LSB steganography; no detailed LSB analysis implemented."
        ]
        return ScanResult(file=info.path, findings=findings)

    def embed(
        self,
        info: FileInfo,
        payload: bytes,
        *,
        algo: str = "lsb1",
        **options: Any,
    ) -> bytes:
        if algo != "lsb1":
            raise ValueError("Unknown algo for audio_lsb")

        in_path = info.path
        out_path = str(Path(in_path).with_suffix(".lsb.wav"))

        with wave.open(in_path, "rb") as song:
            params = song.getparams()
            frames = bytearray(song.readframes(song.getnframes()))

        bits = "".join(f"{b:08b}" for b in payload)
        if len(bits) > len(frames):
            raise ValueError("Payload too large for this audio file")

        for i, bit in enumerate(bits):
            frames[i] = (frames[i] & 0b11111110) | int(bit)

        with wave.open(out_path, "wb") as out:
            out.setparams(params)
            out.writeframes(bytes(frames))

        return Path(out_path).read_bytes()

    def extract(
        self,
        info: FileInfo,
        *,
        algo: str = "lsb1",
        length: int | None = None,
        **options: Any,
    ) -> bytes:
        if algo != "lsb1":
            raise ValueError("Unknown algo for audio_lsb")
        if length is None:
            raise ValueError("Pass payload length (bytes) for audio_lsb extract")

        with wave.open(info.path, "rb") as song:
            frames = bytearray(song.readframes(song.getnframes()))

        bits_needed = length * 8
        bits = [str(frames[i] & 1) for i in range(bits_needed)]
        data = bytearray()
        for i in range(0, len(bits), 8):
            byte_bits = "".join(bits[i : i + 8])
            data.append(int(byte_bits, 2))
        return bytes(data)
