# unisteg/plugins/image_metadata.py

from __future__ import annotations
from typing import List

from PIL import Image, ExifTags

from ..plugin_base import BasePlugin, FileInfo, ScanResult


class ImageMetadataPlugin(BasePlugin):
    name = "image_metadata"
    supported_mimetypes = ["image/jpeg", "image/png"]

    def scan(self, info: FileInfo) -> ScanResult:
        findings: List[str] = []
        img = Image.open(info.path)

        # EXIF
        try:
            exifdata = img.getexif()
        except Exception:
            exifdata = None

        if exifdata and len(exifdata) > 0:
            tag_names = []
            for tag_id in exifdata:
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                data = exifdata.get(tag_id)
                if isinstance(data, (bytes, str)):
                    tag_names.append(str(tag))
            if tag_names:
                findings.append(
                    f"Found EXIF metadata tags: {', '.join(tag_names)} (check for suspicious/oversized values)."
                )

        # PNG textual info
        if info.mimetype == "image/png":
            keys = [k for k, v in (img.info or {}).items() if isinstance(v, str) and v]
            if keys:
                findings.append(
                    f"Found PNG textual metadata keys: {', '.join(keys)} (may hide data)."
                )

        if not findings:
            findings.append("No obvious EXIF or textual metadata found.")
        return ScanResult(file=info.path, findings=findings)

    def embed(self, info: FileInfo, payload: bytes, *, algo: str = "exif_comment", **_) -> bytes:
        raise NotImplementedError("Metadata-based embedding not implemented yet")

    def extract(self, info: FileInfo, *, algo: str = "exif_comment", **_) -> bytes:
        raise NotImplementedError("Metadata-based extraction not implemented yet")
