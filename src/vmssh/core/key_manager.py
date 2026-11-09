from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import paramiko

from vmssh.core.exceptions import IncompleteKeyError, KeyMismatchError, VMSSHError


class KeyManager:
    def __init__(self, ssh_dir: Path | None = None):
        profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
        self.ssh_dir = (ssh_dir or profile / ".ssh").expanduser()
        self.default_private_key = self.ssh_dir / "id_ed25519_vm"

    def ensure_directory(self) -> None:
        self.ssh_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _public_line(key: paramiko.PKey, comment: str = "windows-vm-key") -> str:
        encoded = base64.b64encode(key.asbytes()).decode("ascii")
        return f"{key.get_name()} {encoded} {comment}".strip()

    @staticmethod
    def _load_private(path: Path, passphrase: str | None = None) -> paramiko.PKey:
        with path.open("rb") as stream:
            header = stream.read(128)
        if b"OPENSSH PRIVATE KEY" in header:
            loaders = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]
        elif b"RSA PRIVATE KEY" in header:
            loaders = [paramiko.RSAKey]
        elif b"EC PRIVATE KEY" in header:
            loaders = [paramiko.ECDSAKey]
        elif b"DSA PRIVATE KEY" in header:
            dss = getattr(paramiko, "DSSKey", None)
            loaders = [dss] if dss else []
        else:
            loaders = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]
        last_error: Exception | None = None
        for loader in loaders:
            if loader is None:
                continue
            try:
                return loader.from_private_key_file(str(path), password=passphrase)
            except paramiko.PasswordRequiredException:
                raise
            except (paramiko.SSHException, ValueError, OSError) as exc:
                last_error = exc
        raise VMSSHError(f"无法识别或读取私钥：{path.name}。{last_error or ''}")

    def generate_default(self, passphrase: str | None = None, comment: str = "windows-vm-key") -> Path:
        return self.generate_key(self.default_private_key, passphrase, comment)

    def generate_key(self, private_path: Path | str, passphrase: str | None = None,
                     comment: str = "windows-vm-key") -> Path:
        private_path = Path(private_path).expanduser()
        if not private_path.is_absolute():
            private_path = private_path.resolve()
        private_path.parent.mkdir(parents=True, exist_ok=True)
        if private_path.name.lower().endswith(".pub"):
            raise VMSSHError("请指定私钥文件路径，不要以 .pub 结尾。")
        public_path = Path(str(private_path) + ".pub")
        if private_path.exists() or public_path.exists():
            raise IncompleteKeyError("目标密钥路径已有文件；为避免覆盖，已停止生成。")

        key = paramiko.Ed25519Key.generate()
        fd, tmp_name = tempfile.mkstemp(prefix=".vmssh-key-", dir=str(private_path.parent))
        os.close(fd)
        tmp_private = Path(tmp_name)
        try:
            tmp_private.unlink(missing_ok=True)
            key.write_private_key_file(str(tmp_private), password=passphrase or None)
            private_bytes = tmp_private.read_bytes()
            with private_path.open("xb") as stream:
                stream.write(private_bytes)
            try:
                with public_path.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(self._public_line(key, comment) + "\n")
            except Exception:
                private_path.unlink(missing_ok=True)
                raise
            try:
                if os.name != "nt":
                    private_path.chmod(0o600)
                    public_path.chmod(0o644)
                else:
                    self._tighten_windows_acl(private_path)
            except Exception:
                private_path.unlink(missing_ok=True)
                public_path.unlink(missing_ok=True)
                raise
            return private_path
        finally:
            tmp_private.unlink(missing_ok=True)

    @staticmethod
    def _tighten_windows_acl(private_path: Path) -> None:
        icacls = shutil.which("icacls")
        whoami = shutil.which("whoami")
        if not icacls or not whoami:
            raise VMSSHError("无法找到 icacls/whoami，不能确认私钥 ACL；请检查 Windows OpenSSH 私钥权限。")
        identity = subprocess.run([whoami], capture_output=True, text=True, check=True).stdout.strip()
        subprocess.run([icacls, str(private_path), "/inheritance:r"], capture_output=True, text=True, check=True)
        subprocess.run([icacls, str(private_path), "/grant:r", f"{identity}:F"], capture_output=True, text=True, check=True)

    def load_key(self, private_path: Path | str, passphrase: str | None = None) -> tuple[paramiko.PKey, str]:
        path = Path(private_path).expanduser().resolve()
        public_path = Path(str(path) + ".pub")
        if not path.exists() or not public_path.exists():
            raise IncompleteKeyError(
                f"密钥文件不完整：需要同时存在 {path.name} 和 {public_path.name}。不会自动覆盖或修复。"
            )
        key = self._load_private(path, passphrase)
        public_line = public_path.read_text(encoding="utf-8").strip()
        parts = public_line.split()
        if len(parts) < 2:
            raise KeyMismatchError("公钥文件格式不正确。")
        try:
            public_blob = base64.b64decode(parts[1], validate=True)
        except Exception as exc:
            raise KeyMismatchError("公钥文件 Base64 内容不正确。") from exc
        if parts[0] != key.get_name() or public_blob != key.asbytes():
            raise KeyMismatchError("公钥与私钥不匹配；为避免破坏数据，未进行任何修改。")
        return key, public_line

    def repair_missing_public_key(self, private_path: Path | str, passphrase: str | None = None) -> Path:
        path = Path(private_path).expanduser().resolve()
        public_path = Path(str(path) + ".pub")
        if not path.exists():
            raise IncompleteKeyError("私钥不存在，无法从公钥恢复。")
        if public_path.exists():
            raise IncompleteKeyError("公钥文件已经存在；拒绝覆盖。")
        key = self._load_private(path, passphrase)
        with public_path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(self._public_line(key) + "\n")
        return public_path

    def list_private_keys(self) -> list[Path]:
        self.ensure_directory()
        excluded = {"config", "known_hosts", "known_hosts.old", "authorized_keys"}
        result: list[Path] = []
        for path in sorted(self.ssh_dir.iterdir()):
            if not path.is_file() or path.name.endswith(".pub") or path.name in excluded:
                continue
            try:
                with path.open("rb") as stream:
                    header = stream.read(128)
            except OSError:
                continue
            if b"PRIVATE KEY" in header:
                result.append(path)
        return result

    @staticmethod
    def fingerprint(key: paramiko.PKey) -> str:
        digest = hashlib.sha256(key.asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
