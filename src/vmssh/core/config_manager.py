from __future__ import annotations

import fnmatch
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from vmssh.core.exceptions import ConfigConflictError, OperationCancelled
from vmssh.core.models import VMConfig
from vmssh.utils.backup import atomic_write, backup_file
from vmssh.utils.validators import validate_alias, validate_host, validate_port, validate_username

_MANAGED = {"hostname", "user", "port", "identityfile", "identitiesonly", "serveraliveinterval", "serveralivecountmax"}


@dataclass(slots=True)
class HostEntry:
    alias: str
    hostname: str = ""
    username: str = ""
    port: str = "22"
    identity_file: str = ""


class SSHConfigManager:
    def __init__(self, config_path: Path | None = None):
        if config_path is None:
            import os
            config_path = Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".ssh" / "config"
        self.path = Path(config_path).expanduser()

    @staticmethod
    def _host_blocks(lines: list[str]) -> list[tuple[int, int, list[str]]]:
        starts = []
        boundaries = []
        for i, line in enumerate(lines):
            host_match = re.match(r"^\s*Host\s+(.+?)\s*(?:#.*)?$", line, re.IGNORECASE)
            match_match = re.match(r"^\s*Match\s+", line, re.IGNORECASE)
            if host_match:
                try:
                    tokens = shlex.split(host_match.group(1), comments=True, posix=True)
                except ValueError:
                    tokens = host_match.group(1).split()
                starts.append((i, tokens))
                boundaries.append(i)
            elif match_match:
                boundaries.append(i)
        blocks = []
        for start, tokens in starts:
            end = next((boundary for boundary in boundaries if boundary > start), len(lines))
            blocks.append((start, end, tokens))
        return blocks

    @staticmethod
    def _pattern_applies(alias: str, tokens: list[str]) -> bool:
        positive = [token for token in tokens if not token.startswith("!")]
        negative = [token[1:] for token in tokens if token.startswith("!") and len(token) > 1]
        normalized_alias = alias.lower()
        included = any(fnmatch.fnmatchcase(normalized_alias, pattern.lower()) for pattern in positive)
        excluded = any(fnmatch.fnmatchcase(normalized_alias, pattern.lower()) for pattern in negative)
        return included and not excluded

    @staticmethod
    def _global_managed_directives(lines: list[str]) -> list[str]:
        conflicts = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            if parts and parts[0].lower() in _MANAGED:
                conflicts.append(parts[0])
        return conflicts

    @staticmethod
    def _directives(config: VMConfig) -> list[str]:
        identity = str(config.key_path.resolve()).replace("\\", "/")
        if any(char in identity for char in '\r\n"%'):
            raise ConfigConflictError("密钥路径包含换行、双引号或 OpenSSH token 字符，无法安全写入 Config。")
        if "#" in identity or " " in identity or "\t" in identity:
            identity = f'"{identity}"'
        return [
            f"    HostName {config.hostname}",
            f"    User {config.username}",
            f"    Port {config.port}",
            f"    IdentityFile {identity}",
            "    IdentitiesOnly yes",
            "    ServerAliveInterval 30",
            "    ServerAliveCountMax 4",
        ]

    def upsert(self, config: VMConfig, on_conflict=None) -> Path | None:
        config.hostname = validate_host(config.hostname)
        config.username = validate_username(config.username)
        config.host_alias = validate_alias(config.host_alias)
        config.port = validate_port(config.port)
        if config.key_path is None:
            raise ConfigConflictError("未指定 SSH 私钥路径。")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ConfigConflictError("SSH Config 路径是符号链接；为避免替换非预期文件，已停止修改。")
        if self.path.exists() and not self.path.is_file():
            raise ConfigConflictError("SSH Config 路径不是普通文件。")
        existed = self.path.exists()
        if existed:
            with self.path.open("r", encoding="utf-8", newline="") as stream:
                original = stream.read()
        else:
            original = ""
        line_ending = "\r\n" if "\r\n" in original else "\n"
        lines = original.splitlines()
        blocks = self._host_blocks(lines)
        match_starts = [i for i, line in enumerate(lines) if re.match(r"^\s*Match\s+", line, re.IGNORECASE)]
        first_match = match_starts[0] if match_starts else len(lines)
        first_scope = min([block[0] for block in blocks] + match_starts, default=len(lines))
        matches = [(start, end, tokens) for start, end, tokens in blocks if config.host_alias in tokens]
        directives = self._directives(config)
        if matches:
            start, end, tokens = matches[0]
            if len(matches) > 1:
                raise ConfigConflictError(f"SSH Config 中存在多个同名 Host：{config.host_alias}")
            if len(tokens) != 1:
                raise ConfigConflictError("该 Host 与其他别名共用一个 Host 块。为避免影响其他别名，请选择新的 Host 别名。")
            global_conflicts = self._global_managed_directives(lines[:first_scope])
            if global_conflicts:
                names = ", ".join(dict.fromkeys(global_conflicts))
                raise ConfigConflictError(
                    f"SSH Config 的全局区段已设置 {names}；OpenSSH 优先采用先出现的值，"
                    "为避免写入后仍无法生效，请先将这些设置移入 Host * 区块或手动调整配置顺序。"
                )
            prior_matching = [
                (block_start, block_end) for block_start, block_end, block_tokens in blocks
                if block_start < start and self._pattern_applies(config.host_alias, block_tokens)
            ]
            for block_start, block_end in prior_matching:
                prior_managed = []
                for line in lines[block_start + 1:block_end]:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        key = stripped.split(None, 1)[0].lower()
                        if key in _MANAGED:
                            prior_managed.append(key)
                if prior_managed:
                    names = ", ".join(dict.fromkeys(prior_managed))
                    raise ConfigConflictError(
                        f"前面的 Host 匹配规则已设置 {names}，OpenSSH 会优先采用前面的值；"
                        "请先调整通配 Host 区块顺序，再更新该 Host。"
                    )
            action = on_conflict(config.host_alias) if on_conflict else "cancel"
            if action != "update":
                raise OperationCancelled(f"用户取消更新已有 Host：{config.host_alias}")
            block = lines[start:end]
            kept = [block[0]]
            for line in block[1:]:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    kept.append(line)
                    continue
                key = stripped.split(None, 1)[0].lower()
                if key not in _MANAGED:
                    kept.append(line)
            new_block = [kept[0], *directives]
            # Preserve comments and unrelated directives after the managed settings.
            new_block.extend(kept[1:])
            lines[start:end] = new_block
        else:
            # Insert before the first existing Host block whose glob pattern
            # applies to this alias, or before Match. This ensures specific
            # settings win over earlier Host * / Host vm-* defaults.
            global_conflicts = self._global_managed_directives(lines[:first_scope])
            if global_conflicts:
                names = ", ".join(dict.fromkeys(global_conflicts))
                raise ConfigConflictError(
                    f"SSH Config 的全局区段已设置 {names}；OpenSSH 优先采用先出现的值，"
                    "请先将这些设置移入 Host * 区块或手动调整配置顺序。"
                )
            applicable = [
                block_start for block_start, _block_end, block_tokens in blocks
                if self._pattern_applies(config.host_alias, block_tokens)
            ]
            insertion_index = min([*applicable, first_match])
            insertion = [f"Host {config.host_alias}", *directives, ""]
            if insertion_index > 0 and lines[insertion_index - 1].strip():
                insertion.insert(0, "")
            lines[insertion_index:insertion_index] = insertion
        if existed:
            backup_file(self.path)
        atomic_write(self.path, line_ending.join(lines).rstrip("\r\n") + line_ending)
        return self.path

    def remove(self, alias: str) -> bool:
        alias = validate_alias(alias)
        if self.path.is_symlink():
            raise ConfigConflictError("SSH Config 路径是符号链接；拒绝删除或改写。")
        if not self.path.exists():
            return False
        with self.path.open("r", encoding="utf-8", newline="") as stream:
            original = stream.read()
        line_ending = "\r\n" if "\r\n" in original else "\n"
        lines = original.splitlines()
        blocks = self._host_blocks(lines)
        for start, end, tokens in blocks:
            if alias not in tokens:
                continue
            if len(tokens) > 1:
                tokens = [token for token in tokens if token != alias]
                lines[start] = "Host " + " ".join(tokens)
            else:
                del lines[start:end]
            backup_file(self.path)
            atomic_write(self.path, line_ending.join(lines).rstrip("\r\n") + line_ending if lines else "")
            return True
        return False

    def list_hosts(self) -> list[HostEntry]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        result: list[HostEntry] = []
        for start, end, tokens in self._host_blocks(lines):
            for alias in tokens:
                if any(c in alias for c in "*!?"):
                    continue
                entry = HostEntry(alias=alias)
                for line in lines[start + 1:end]:
                    parts = line.strip().split(None, 1)
                    if len(parts) != 2:
                        continue
                    key, value = parts[0].lower(), parts[1].strip().strip('"')
                    if key == "hostname": entry.hostname = value
                    elif key == "user": entry.username = value
                    elif key == "port": entry.port = value
                    elif key == "identityfile": entry.identity_file = value
                result.append(entry)
        return result
