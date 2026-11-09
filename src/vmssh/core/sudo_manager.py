from __future__ import annotations

import shlex
import uuid
from datetime import datetime, timezone

from vmssh.core.exceptions import RemoteOperationError
from vmssh.utils.validators import validate_username


def sudoers_content(username: str) -> str:
    return f"{username} ALL=(ALL:ALL) NOPASSWD: ALL\n"


class SudoManager:
    def configure_nopasswd(self, connection, username: str, password: str) -> str:
        username = validate_username(username)
        if username == "root":
            raise RemoteOperationError("root 用户不需要配置 sudoers；本功能只针对普通用户。")
        check = connection.run_sudo("id -u", password)
        if not check.ok or check.stdout.strip() != "0":
            detail = (check.stderr or check.stdout).strip()
            raise RemoteOperationError("当前用户没有可用的 sudo 管理权限，无法配置免密 sudo。" + (f" 详情：{detail}" if detail else ""))

        sftp = connection.sftp()
        token = uuid.uuid4().hex
        remote_tmp = f"/tmp/vmssh-sudoers-{token}"
        try:
            with sftp.open(remote_tmp, "x") as stream:
                stream.write(sudoers_content(username).encode("utf-8"))
            sftp.chmod(remote_tmp, 0o600)
        except Exception:
            try:
                sftp.remove(remote_tmp)
            except Exception:
                pass
            raise
        finally:
            sftp.close()

        target = f"/etc/sudoers.d/{username}"
        backup = target + ".bak-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f") + "-" + token[:8]
        staged = f"/etc/sudoers.d/.{username}.vmssh-{token}.tmp"
        script = "\n".join([
            "set -eu",
            f"trap 'rm -f -- {shlex.quote(remote_tmp)} {shlex.quote(staged)}' EXIT",
            "command -v visudo >/dev/null 2>&1 || { echo 'visudo not found' >&2; exit 20; }",
            f"if [ -L {shlex.quote(target)} ]; then echo 'sudoers target is a symlink' >&2; exit 21; fi",
            f"if [ -e {shlex.quote(target)} ] && [ ! -f {shlex.quote(target)} ]; then echo 'sudoers target is not a regular file' >&2; exit 22; fi",
            f"install -o root -g root -m 0440 -- {shlex.quote(remote_tmp)} {shlex.quote(staged)}",
            f"visudo -cf {shlex.quote(staged)}",
            f"if [ -e {shlex.quote(target)} ]; then cp -a -- {shlex.quote(target)} {shlex.quote(backup)}; echo {shlex.quote('BACKUP=' + backup)}; fi",
            f"mv -f -- {shlex.quote(staged)} {shlex.quote(target)}",
        ])
        installed = connection.run_sudo(script, password, timeout=40)
        if not installed.ok:
            # If sudo rejected the request before the shell/trap started, remove the user-owned temp file.
            cleanup = connection.sftp()
            try:
                try:
                    cleanup.remove(remote_tmp)
                except Exception:
                    pass
            finally:
                cleanup.close()
            raise RemoteOperationError("sudoers 配置未安装；原配置保持不变。" + ((installed.stderr or installed.stdout).strip()))

        verify = connection.run("sudo -k && sudo -n whoami", timeout=15)
        if verify.ok and verify.stdout.strip() == "root":
            marker = "BACKUP="
            for line in installed.stdout.splitlines():
                if line.startswith(marker):
                    return line[len(marker):]
            return ""

        # Roll back if the post-install NOPASSWD check fails.
        rollback_script = "\n".join([
            "set -eu",
            f"if [ -e {shlex.quote(backup)} ]; then cp -a -- {shlex.quote(backup)} {shlex.quote(target)}; else rm -f -- {shlex.quote(target)}; fi",
        ])
        rollback = connection.run_sudo(rollback_script, password, timeout=30)
        detail = (verify.stderr or verify.stdout).strip()
        if not rollback.ok:
            rollback_detail = (rollback.stderr or rollback.stdout).strip()
            raise RemoteOperationError("免密 sudo 验证失败，而且回滚命令也失败；请通过 VM 控制台检查 sudoers。" + (f" 回滚错误：{rollback_detail}" if rollback_detail else ""))
        raise RemoteOperationError("免密 sudo 验证失败，已回滚 sudoers 修改。" + (f" 详情：{detail}" if detail else ""))
