# unisteg/cli.py

from __future__ import annotations
import argparse
import sys
from pathlib import Path

from .filetype import detect_mimetype
from .plugin_base import FileInfo, plugins_for_mimetype, get_plugin

# import plugins for side-effect registration
from . import plugins  # noqa: F401


def cmd_scan(args: argparse.Namespace) -> int:
    path = args.file
    mtype = detect_mimetype(path)
    info = FileInfo(path=path, mimetype=mtype)

    print(f"Detected type: {mtype}")
    matched = False
    for plugin in plugins_for_mimetype(info.mimetype):
        matched = True
        result = plugin.scan(info)
        print(f"[{plugin.name}] findings for {result.file}:")
        for f in result.findings:
            print(f"  - {f}")
    if not matched:
        print("No plugins support this mimetype.")
    return 0


def cmd_embed(args: argparse.Namespace) -> int:
    plugin = get_plugin(args.plugin)
    if plugin is None:
        print(f"Unknown plugin: {args.plugin}", file=sys.stderr)
        return 1

    mtype = detect_mimetype(args.file)
    info = FileInfo(path=args.file, mimetype=mtype)
    payload = Path(args.payload).read_bytes()

    out_bytes = plugin.embed(info, payload, algo=args.algo)
    Path(args.output).write_bytes(out_bytes)
    print(f"Wrote stego file to {args.output}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    plugin = get_plugin(args.plugin)
    if plugin is None:
        print(f"Unknown plugin: {args.plugin}", file=sys.stderr)
        return 1

    mtype = detect_mimetype(args.file)
    info = FileInfo(path=args.file, mimetype=mtype)

    kwargs = {}
    if args.length is not None:
        kwargs["length"] = args.length

    data = plugin.extract(info, algo=args.algo, **kwargs)
    Path(args.output).write_bytes(data)
    print(f"Wrote extracted payload to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="unisteg", description="Universal Steganography CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a file for steganography indicators")
    p_scan.add_argument("file")
    p_scan.set_defaults(func=cmd_scan)

    p_embed = sub.add_parser("embed", help="Embed payload into cover file")
    p_embed.add_argument("file", help="Cover file path")
    p_embed.add_argument("payload", help="Payload file path")
    p_embed.add_argument("output", help="Output stego file path")
    p_embed.add_argument("--plugin", default="image_lsb", help="Plugin name (e.g. image_lsb, audio_lsb)")
    p_embed.add_argument("--algo", default="lsb1", help="Algorithm inside plugin")
    p_embed.set_defaults(func=cmd_embed)

    p_extract = sub.add_parser("extract", help="Extract payload from stego file")
    p_extract.add_argument("file", help="Stego file path")
    p_extract.add_argument("output", help="Output payload file path")
    p_extract.add_argument("--plugin", default="image_lsb", help="Plugin name")
    p_extract.add_argument("--algo", default="lsb1", help="Algorithm inside plugin")
    p_extract.add_argument("--length", type=int, help="Payload length in bytes (for LSB/append demos)")
    p_extract.set_defaults(func=cmd_extract)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
