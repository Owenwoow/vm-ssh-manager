from __future__ import annotations

import base64
import posixpath
import stat
import uuid
from datetime import datetime, timezone

from vmssh.core.exceptions import RemoteOperationError

_KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-")


def key_identity(line: str) -> tuple[str, str] | None:
    """Extract key type/blob from authorized_keys lines, including key options."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split()
    for index, token in enumerate(parts[:-1]):
        if token.startswith(_KEY_TYPES):
            try:
                base64.b64decode(parts[index + 1], validate=True)
            except Exception:
                return None
            return token, parts[index + 1]
    return None


def _remote_home(connection) -> str:
    result = connection.run("printf '%s' \"$HOME\"")
    home = result.stdout.strip()
    if not result.ok or not home.startswith("/") or home == "/" or ".." in home.split("/"):
        raise RemoteOperationError("无法安全确定目标 Linux 用户的家目录；拒绝对根目录执行 SSH 初始化。")
    return home.rstrip("/")


def install_public_key(connection, public_key_line: str) -> bool:
    """Install key without deleting/reordering any existing authorized_keys entries.

    Returns True when appended, False when it was already present.
    """
    sftp = connection.sftp()
    try:
        home = _remote_home(connection)
        ssh_dir = posixpath.join(home, ".ssh")
        auth_file = posixpath.join(ssh_dir, "authorized_keys")
        uid_result = connection.run("id -u")
        if not uid_result.ok:
            raise RemoteOperationError("无法读取当前 Linux 用户 UID，不能确认 ~/.ssh 所有权。")
        try:
            current_uid = int(uid_result.stdout.strip())
        except ValueError as exc:
            raise RemoteOperationError("Linux 返回的 UID 格式异常。") from exc
        try:
            info = sftp.lstat(ssh_dir)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RemoteOperationError("目标 ~/.ssh 不是普通目录或是符号链接；为避免越界写入已停止。")
            dir_owner = getattr(info, "st_uid", None)
            if dir_owner is not None and dir_owner != current_uid:
                raise RemoteOperationError("~/.ssh 目录所有者不是当前登录用户；为避免错误修改已停止。")
        except FileNotFoundError:
            sftp.mkdir(ssh_dir, 0o700)
        sftp.chmod(ssh_dir, 0o700)

        try:
            info = sftp.lstat(auth_file)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RemoteOperationError("authorized_keys 不是普通文件或是符号链接；已停止修改。")
            auth_owner = getattr(info, "st_uid", None)
            if auth_owner is not None and auth_owner != current_uid:
                raise RemoteOperationError("authorized_keys 所有者不是当前登录用户；拒绝覆盖或修改。")
            with sftp.open(auth_file, "rb") as stream:
                existing = stream.read()
        except FileNotFoundError:
            existing = b""

        target_identity = key_identity(public_key_line)
        if target_identity is None:
            raise RemoteOperationError("本地公钥格式无法识别。")
        for line in existing.decode("utf-8", errors="replace").splitlines():
            if key_identity(line) == target_identity:
                sftp.chmod(auth_file, 0o600)
                auth_stat = sftp.stat(auth_file)
                auth_owner = getattr(auth_stat, "st_uid", None)
                if current_uid is not None and auth_owner is not None and auth_owner != current_uid:
                    raise RemoteOperationError("authorized_keys 所有者不是当前登录用户；请检查文件所有权。")
                return False

        addition = public_key_line.rstrip("\r\n").encode("utf-8")
        new_content = existing
        if new_content and not new_content.endswith(b"\n"):
            new_content += b"\n"
        new_content += addition + b"\n"
        temp_file = posixpath.join(ssh_dir, f".authorized_keys.vmssh-{uuid.uuid4().hex}.tmp")
        with sftp.open(temp_file, "wb") as stream:
            stream.write(new_content)
        sftp.chmod(temp_file, 0o600)
        # Keep a server-side backup before atomically replacing the authorized_keys file.
        if existing:
            backup = auth_file + ".bak-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f") + "-" + uuid.uuid4().hex[:8]
            with sftp.open(backup, "wb") as stream:
                stream.write(existing)
            sftp.chmod(backup, 0o600)
        try:
            try:
                sftp.posix_rename(temp_file, auth_file)
            except (AttributeError, IOError, OSError):
                if existing:
                    interim = auth_file + f".vmssh-old-{uuid.uuid4().hex}"
                    sftp.rename(auth_file, interim)
                    try:
                        sftp.rename(temp_file, auth_file)
                    except Exception:
                        sftp.rename(interim, auth_file)
                        raise
                    # Keep interim as an additional recovery copy.
                else:
                    sftp.rename(temp_file, auth_file)
        finally:
            try:
                sftp.remove(temp_file)
            except Exception:
                pass
        sftp.chmod(auth_file, 0o600)
        # Files created by the authenticated account should be owned by that account.
        if current_uid is not None:
            auth_stat = sftp.stat(auth_file)
            auth_owner = getattr(auth_stat, "st_uid", None)
            if auth_owner is not None and auth_owner != current_uid:
                raise RemoteOperationError("authorized_keys 所有者不是当前登录用户；请检查 ~/.ssh 文件所有权。")
        return True
    finally:
        sftp.close()


def revoke_public_key(connection, public_key_line: str) -> bool:
    """Remove only the exact public key; preserve all unrelated lines."""
    sftp = connection.sftp()
    try:
        ssh_dir = posixpath.join(_remote_home(connection), ".ssh")
        try:
            ssh_info = sftp.lstat(ssh_dir)
            if stat.S_ISLNK(ssh_info.st_mode) or not stat.S_ISDIR(ssh_info.st_mode):
                raise RemoteOperationError("目标 ~/.ssh 不是普通目录或是符号链接；拒绝撤销。")
        except FileNotFoundError:
            return False
        uid_result = connection.run("id -u")
        if not uid_result.ok:
            raise RemoteOperationError("无法读取当前 Linux 用户 UID，拒绝撤销公钥。")
        try:
            current_uid = int(uid_result.stdout.strip())
        except ValueError as exc:
            raise RemoteOperationError("Linux 返回的 UID 格式异常，拒绝撤销公钥。") from exc
        dir_owner = getattr(ssh_info, "st_uid", None)
        if dir_owner is not None and dir_owner != current_uid:
            raise RemoteOperationError("~/.ssh 目录所有者不是当前登录用户；拒绝撤销公钥。")
        auth_file = posixpath.join(ssh_dir, "authorized_keys")
        try:
            auth_info = sftp.lstat(auth_file)
            if stat.S_ISLNK(auth_info.st_mode) or not stat.S_ISREG(auth_info.st_mode):
                raise RemoteOperationError("authorized_keys 不是普通文件或是符号链接；拒绝撤销。")
            auth_owner = getattr(auth_info, "st_uid", None)
            if auth_owner is not None and auth_owner != current_uid:
                raise RemoteOperationError("authorized_keys 所有者不是当前登录用户；拒绝撤销公钥。")
            with sftp.open(auth_file, "rb") as stream:
                original = stream.read()
        except FileNotFoundError:
            return False
        wanted = key_identity(public_key_line)
        if wanted is None:
            raise RemoteOperationError("待撤销的本地公钥格式无法识别。")
        kept: list[bytes] = []
        removed = False
        for raw_line in original.splitlines(keepends=True):
            if key_identity(raw_line.decode("utf-8", errors="replace")) == wanted:
                removed = True
            else:
                # Keep every unrelated byte exactly as it was on the server.
                kept.append(raw_line)
        if not removed:
            return False
        backup = auth_file + ".bak-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f") + "-" + uuid.uuid4().hex[:8]
        with sftp.open(backup, "wb") as stream:
            stream.write(original)
        sftp.chmod(backup, 0o600)
        temp_file = auth_file + f".vmssh-{uuid.uuid4().hex}.tmp"
        with sftp.open(temp_file, "wb") as stream:
            stream.write(b"".join(kept))
        sftp.chmod(temp_file, 0o600)
        try:
            try:
                sftp.posix_rename(temp_file, auth_file)
            except (AttributeError, IOError, OSError):
                interim = auth_file + f".vmssh-old-{uuid.uuid4().hex}"
                sftp.rename(auth_file, interim)
                try:
                    sftp.rename(temp_file, auth_file)
                except Exception:
                    sftp.rename(interim, auth_file)
                    raise
        finally:
            try:
                sftp.remove(temp_file)
            except Exception:
                pass
        return True
    finally:
        sftp.close()
