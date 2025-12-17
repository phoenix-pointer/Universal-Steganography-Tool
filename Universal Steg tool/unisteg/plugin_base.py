# unisteg/plugin_base.py

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Any

_PLUGIN_REGISTRY: Dict[str, "BasePlugin"] = {}


@dataclass
class FileInfo:
    path: str
    mimetype: str


@dataclass
class ScanResult:
    file: str
    findings: List[str]


class BasePlugin(ABC):
    name: str
    supported_mimetypes: List[str]

    @abstractmethod
    def scan(self, info: FileInfo) -> ScanResult:
        ...

    @abstractmethod
    def embed(
        self,
        info: FileInfo,
        payload: bytes,
        *,
        algo: str,
        **options: Any,
    ) -> bytes:
        ...

    @abstractmethod
    def extract(
        self,
        info: FileInfo,
        *,
        algo: str,
        **options: Any,
    ) -> bytes:
        ...


def register_plugin(plugin: BasePlugin) -> None:
    _PLUGIN_REGISTRY[plugin.name] = plugin


def get_plugin(name: str) -> BasePlugin | None:
    return _PLUGIN_REGISTRY.get(name)


def all_plugins() -> List[BasePlugin]:
    return list(_PLUGIN_REGISTRY.values())


def plugins_for_mimetype(mimetype: str) -> List[BasePlugin]:
    return [p for p in all_plugins() if mimetype in p.supported_mimetypes]
