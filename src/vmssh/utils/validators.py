from __future__ import annotations

import ipaddress
import re

from vmssh.core.exceptions import ValidationError

_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$", re.IGNORECASE)
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_host(value: str) -> str:
    host = value.strip()
    if not host or any(c.isspace() for c in host) or any(c in host for c in "`$;|&<>\"'\\"):
        raise ValidationError("IP/主机地址为空或包含不允许的字符。")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        normalized = host.rstrip(".")
        if len(normalized) > 253 or not normalized or not all(
            _DNS_LABEL_RE.fullmatch(part) for part in normalized.split(".")
        ):
            raise ValidationError("请输入有效的 IPv4/IPv6 地址或 DNS 主机名。")
        return normalized


def validate_username(value: str) -> str:
    username = value.strip()
    if not _USERNAME_RE.fullmatch(username):
        raise ValidationError("Linux 用户名格式不合法（仅允许字母、数字、下划线和连字符，且不能以数字开头）。")
    return username


def validate_alias(value: str) -> str:
    alias = value.strip()
    if not _ALIAS_RE.fullmatch(alias):
        raise ValidationError("SSH Host 别名仅允许字母、数字、点、下划线和连字符，长度 1–64。")
    return alias


def validate_port(value: int | str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValidationError("SSH 端口必须是 1–65535 的整数。")
    if not 1 <= port <= 65535:
        raise ValidationError("SSH 端口必须是 1–65535 的整数。")
    return port
