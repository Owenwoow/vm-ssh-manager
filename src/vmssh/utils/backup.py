from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path


def backup_file(path: Path) -> Path | None:
    if path.is_symlink():
        raise OSError(f"拒绝备份符号链接：{path}")
    if not path.exists():
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, backup)
    return backup


def atomic_write(path: Path, data: str, encoding: str = "utf-8") -> None:
    if path.is_symlink():
        raise OSError(f"拒绝通过符号链接写入文件：{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists() and os.name != "nt":
            tmp.chmod(path.stat().st_mode & 0o777)
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        finally:
            raise
