from __future__ import annotations

import base64
import hashlib
import shlex
import socket
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import paramiko

from vmssh.core.exceptions import HostKeyRejectedError, RemoteOperationError


@dataclass(slots=True)
class CommandResult:
    exit_status: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_status == 0


class ConfirmingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, known_hosts: Path, confirm: Callable[[str, str, str], bool]):
        self.known_hosts = known_hosts
        self.confirm = confirm

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        digest = hashlib.sha256(key.asbytes()).digest()
        fingerprint = "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
        accepted = self.confirm(hostname, key.get_name(), fingerprint)
        if not accepted:
            raise HostKeyRejectedError(f"用户拒绝了主机密钥：{hostname} {fingerprint}")
        client.get_host_keys().add(hostname, key.get_name(), key)
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
        if self.known_hosts.is_symlink():
            raise HostKeyRejectedError("known_hosts 是符号链接；为避免写入非预期文件，已停止保存主机指纹。")
        encoded = base64.b64encode(key.asbytes()).decode("ascii")
        # Append only the newly confirmed host key; do not rewrite existing OpenSSH entries/comments.
        with self.known_hosts.open("a", encoding="utf-8", newline="") as stream:
            if self.known_hosts.exists() and self.known_hosts.stat().st_size:
                with self.known_hosts.open("rb") as check:
                    check.seek(-1, 2)
                    if check.read(1) not in {b"\n", b"\r"}:
                        stream.write("\n")
            stream.write(f"{hostname} {key.get_name()} {encoded}\n")
        if self.known_hosts.exists() and self.known_hosts.stat().st_size and os.name != "nt":
            self.known_hosts.chmod(0o600)


class SSHConnection:
    def __init__(self, ssh_dir: Path, logger: Callable[[str], None] | None = None):
        self.ssh_dir = ssh_dir
        self.known_hosts = ssh_dir / "known_hosts"
        self.logger = logger or (lambda _message: None)
        self.client: paramiko.SSHClient | None = None

    def connect_password(self, hostname: str, port: int, username: str, password: str,
                         confirm_host_key: Callable[[str, str, str], bool], timeout: int = 10) -> None:
        self._connect(hostname, port, username, confirm_host_key, password=password, pkey=None, timeout=timeout)

    def connect_key(self, hostname: str, port: int, username: str, key: paramiko.PKey,
                    confirm_host_key: Callable[[str, str, str], bool] | None = None, timeout: int = 10) -> None:
        callback = confirm_host_key or (lambda *_: False)
        self._connect(hostname, port, username, callback, password=None, pkey=key, timeout=timeout)

    def _connect(self, hostname: str, port: int, username: str, confirm_host_key,
                 password: str | None, pkey: paramiko.PKey | None, timeout: int) -> None:
        client = paramiko.SSHClient()
        if self.known_hosts.is_symlink():
            raise RemoteOperationError("known_hosts 是符号链接；为避免读取或写入非预期文件，已停止连接。")
        if self.known_hosts.exists() and not self.known_hosts.is_file():
            raise RemoteOperationError("known_hosts 路径不是普通文件。")
        if self.known_hosts.exists():
            client.load_host_keys(str(self.known_hosts))
        client.set_missing_host_key_policy(ConfirmingHostKeyPolicy(self.known_hosts, confirm_host_key))
        sock = None
        try:
            self.logger(f"检查 TCP 端口可达性：{hostname}:{port}")
            sock = socket.create_connection((hostname, port), timeout=timeout)
            client.connect(
                hostname=hostname, port=port, username=username,
                password=password, pkey=pkey, sock=sock,
                allow_agent=False, look_for_keys=False,
                timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            )
        except Exception:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            client.close()
            raise
        self.client = client

    def run(self, command: str, timeout: int = 20, stdin_text: str | None = None) -> CommandResult:
        if self.client is None:
            raise RemoteOperationError("SSH 尚未连接。")
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        if stdin_text is not None:
            stdin.write(stdin_text)
            stdin.flush()
            stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        return CommandResult(status, out, err)

    def run_sudo(self, command: str, password: str, timeout: int = 30) -> CommandResult:
        wrapped = "sudo -S -p '' -- sh -c " + shlex.quote(command)
        return self.run(wrapped, timeout=timeout, stdin_text=password + "\n")

    def sftp(self) -> paramiko.SFTPClient:
        if self.client is None:
            raise RemoteOperationError("SSH 尚未连接。")
        return self.client.open_sftp()

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
