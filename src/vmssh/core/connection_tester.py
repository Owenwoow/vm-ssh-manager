from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from vmssh.core.exceptions import RemoteOperationError
from vmssh.core.ssh_client import SSHConnection


class ConnectionTester:
    def __init__(self, ssh_dir: Path, logger=None):
        self.ssh_dir = ssh_dir
        self.logger = logger or (lambda _message: None)

    def test_public_key(self, config, key, confirm_host_key=None) -> None:
        connection = SSHConnection(self.ssh_dir, self.logger)
        try:
            connection.connect_key(config.hostname, config.port, config.username, key, confirm_host_key)
            result = connection.run("printf 'VM_SSH_KEY_AUTH_OK\\n'")
            if not result.ok or "VM_SSH_KEY_AUTH_OK" not in result.stdout:
                raise RemoteOperationError("SSH 公钥认证已连接，但远程命令验证失败。")
        finally:
            connection.close()

    def test_native_ssh_config(self, config) -> tuple[bool | None, str]:
        alias = config.host_alias
        ssh = shutil.which("ssh")
        if not ssh:
            candidate = Path("C:/Windows/System32/OpenSSH/ssh.exe")
            if candidate.exists():
                ssh = str(candidate)
        if not ssh:
            return False, "未找到 Windows OpenSSH ssh.exe；请安装 OpenSSH Client，否则无法使用 ssh <Host别名>。"
        try:
            result = subprocess.run([ssh, "-G", alias], capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"执行 ssh -G 失败：{exc}"
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip() or "ssh -G 返回非零状态。"
        values = {}
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            values.setdefault(parts[0].lower(), []).append(parts[1].strip().strip('"'))
        expected = {
            "hostname": config.hostname,
            "user": config.username,
            "port": str(config.port),
        }
        for key, wanted in expected.items():
            if values.get(key, [None])[0] != wanted:
                return False, f"ssh -G 解析出的 {key} 与预期不一致：{values.get(key, ['<missing>'])[0]}"
        wanted_identity = str(config.key_path.resolve()).replace("\\", "/").lower()
        actual_identities = [value.replace("\\", "/").lower() for value in values.get("identityfile", [])]
        if wanted_identity not in actual_identities:
            return False, "ssh -G 未解析到预期的 IdentityFile。"
        return True, "Windows OpenSSH 已成功解析 HostName、User、Port 和 IdentityFile。"
