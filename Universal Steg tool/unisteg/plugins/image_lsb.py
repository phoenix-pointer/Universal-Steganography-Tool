# unisteg/plugins/image_lsb.py

from __future__ import annotations
from pathlib import Path
from typing import Any, List

from PIL import Image  # pip install pillow

from ..plugin_base import BasePlugin, FileInfo, ScanResult


class ImageLSBPlugin(BasePlugin):
    name = "image_lsb"
    supported_mimetypes = ["image/png", "image/bmp"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = [
            "LSB steganography is commonly used with this image type; statistical analysis not implemented."
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
            raise ValueError(f"Unknown algo for image_lsb: {algo}")

        img = Image.open(info.path).convert("RGB")
        pixels = img.load()

        bits = "".join(f"{b:08b}" for b in payload)
        width, height = img.size
        max_capacity = width * height * 3

        if len(bits) > max_capacity:
            raise ValueError("Payload too large for this cover image")

        bit_idx = 0
        for y in range(height):
            for x in range(width):
                if bit_idx >= len(bits):
                    break
                r, g, b = pixels[x, y]
                channels = [r, g, b]
                for c in range(3):
                    if bit_idx >= len(bits):
                        break
                    ch_bits = f"{channels[c]:08b}"
                    channels[c] = int(ch_bits[:-1] + bits[bit_idx], 2)
                    bit_idx += 1
                pixels[x, y] = tuple(channels)
            if bit_idx >= len(bits):
                break

        out_path = Path(info.path).with_suffix(".lsb.png")
        img.save(out_path)
        return out_path.read_bytes()

    def extract(
        self,
        info: FileInfo,
        *,
        algo: str = "lsb1",
        length: int | None = None,
        **options: Any,
    ) -> bytes:
        if algo != "lsb1":
            raise ValueError(f"Unknown algo for image_lsb: {algo}")
        if length is None:
            raise ValueError("Pass payload length (bytes) for image_lsb extract")

        img = Image.open(info.path).convert("RGB")
        pixels = img.load()
        width, height = img.size

        bits_needed = length * 8
        bits_collected: List[str] = []

        for y in range(height):
            for x in range(width):
                if len(bits_collected) >= bits_needed:
                    break
                r, g, b = pixels[x, y]
                for ch in (r, g, b):
                    if len(bits_collected) >= bits_needed:
                        break
                    bits_collected.append(f"{ch:08b}"[-1])
            if len(bits_collected) >= bits_needed:
                break

        data = bytearray()
        for i in range(0, len(bits_collected), 8):
            byte_bits = "".join(bits_collected[i : i + 8])
            data.append(int(byte_bits, 2))
        return bytes(data)
