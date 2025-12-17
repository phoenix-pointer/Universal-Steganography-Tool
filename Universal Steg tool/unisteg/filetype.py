# unisteg/filetype.py

from __future__ import annotations
import mimetypes
from pathlib import Path
from typing import Optional


_MAGIC_MAP = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"BM": "image/bmp",
    b"RIFF": "audio/wav",
}


def _magic_guess(path: Path) -> Optional[str]:
    with path.open("rb") as f:
        header = f.read(16)
    for magic, mtype in _MAGIC_MAP.items():
        if header.startswith(magic):
            return mtype
    return None


def detect_mimetype(path_str: str) -> str:
    path = Path(path_str)
    mt = _magic_guess(path)
    if mt:
        return mt
    guess, _ = mimetypes.guess_type(path.name)
    if guess:
        return guess
    # very rough text guess
    try:
        data = path.read_bytes()
        if all(32 <= b < 127 or b in (9, 10, 13) for b in data[:1024]):
            return "text/plain"
    except OSError:
        pass
    return "application/octet-stream"
