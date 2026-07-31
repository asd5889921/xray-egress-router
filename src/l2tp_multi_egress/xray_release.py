from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from .storage import atomic_write
from .xray import REQUIRED_XRAY_VERSION


RELEASE_BASE = f"https://github.com/XTLS/Xray-core/releases/download/v{REQUIRED_XRAY_VERSION}"
ASSETS = {
    ("x86_64", 64): "Xray-linux-64.zip",
    ("amd64", 64): "Xray-linux-64.zip",
    ("aarch64", 64): "Xray-linux-arm64-v8a.zip",
    ("arm64", 64): "Xray-linux-arm64-v8a.zip",
}


def release_asset() -> str:
    key = (platform.machine().lower(), 64 if platform.architecture()[0] == "64bit" else 32)
    try:
        return ASSETS[key]
    except KeyError as exc:
        raise RuntimeError(f"不支持的 CPU 架构: {key[0]} {key[1]} 位") from exc


def parse_digest(content: str, filename: str) -> str:
    matches = re.findall(r"\b[0-9a-fA-F]{64}\b", content)
    if not matches:
        raise RuntimeError(f"{filename}.dgst 中没有 SHA-256 摘要")
    return matches[0].lower()


def verify_binary(binary: Path) -> str:
    result = subprocess.run([str(binary), "version"], text=True, capture_output=True, timeout=10, check=False)
    output = result.stdout.splitlines()[0].strip() if result.stdout else result.stderr.strip()
    if result.returncode or f"Xray {REQUIRED_XRAY_VERSION}" not in output:
        raise RuntimeError(f"下载的 Xray 版本不符，要求 {REQUIRED_XRAY_VERSION}，检测结果: {output or '无法执行'}")
    return output


def download_and_install(destination: Path = Path("/usr/local/bin/xray")) -> str:
    """Strict release installer primitive used by the later packaging stage.

    It never falls back to latest or another version. The release digest and
    the executable's own version output must both pass before atomic replace.
    """
    asset = release_asset()
    with tempfile.TemporaryDirectory(prefix="xrer-xray-") as temporary:
        root = Path(temporary)
        archive = root / asset
        digest_file = root / f"{asset}.dgst"
        try:
            urllib.request.urlretrieve(f"{RELEASE_BASE}/{asset}", archive)
            urllib.request.urlretrieve(f"{RELEASE_BASE}/{asset}.dgst", digest_file)
        except Exception as exc:
            raise RuntimeError(f"下载 Xray v{REQUIRED_XRAY_VERSION} 失败: {exc}") from exc
        expected = parse_digest(digest_file.read_text(encoding="utf-8", errors="replace"), asset)
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"Xray 压缩包 SHA-256 校验失败: 期望 {expected}，实际 {actual}")
        with zipfile.ZipFile(archive) as bundle:
            names = {Path(name).name: name for name in bundle.namelist()}
            if "xray" not in names:
                raise RuntimeError("Xray 发布压缩包中缺少 xray 可执行文件")
            bundle.extract(names["xray"], root / "extract")
            extracted = root / "extract" / names["xray"]
        extracted.chmod(extracted.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        version = verify_binary(extracted)
        destination.parent.mkdir(parents=True, exist_ok=True)
        staged = destination.with_name(f".{destination.name}.new")
        shutil.copy2(extracted, staged)
        staged.chmod(0o755)
        os.replace(staged, destination)
        return version
