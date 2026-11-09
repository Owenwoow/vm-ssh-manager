from pathlib import Path

import pytest

from vmssh.core.config_manager import SSHConfigManager
from vmssh.core.exceptions import OperationCancelled
from vmssh.core.models import VMConfig


def test_add_preserves_existing_and_is_idempotent(tmp_path):
    config_path = tmp_path / "config"
    config_path.write_text("Host github.com\n    User git\n\n", encoding="utf-8")
    manager = SSHConfigManager(config_path)
    vm = VMConfig("192.0.2.132", "testuser", "ubuntu-vm", 22, tmp_path / "id_ed25519_vm")
    manager.upsert(vm)
    first = config_path.read_text(encoding="utf-8")
    assert "Host github.com" in first
    assert "Host ubuntu-vm" in first
    assert "IdentitiesOnly yes" in first
    assert len(list(tmp_path.glob("config.bak-*"))) == 1
    manager.upsert(vm, on_conflict=lambda _alias: "update")
    second = config_path.read_text(encoding="utf-8")
    assert second.count("Host ubuntu-vm") == 1
    assert second.count("HostName 192.0.2.132") == 1


def test_conflict_cancel_does_not_change_file(tmp_path):
    path = tmp_path / "config"
    path.write_text("Host vm1\n    HostName old\n", encoding="utf-8")
    manager = SSHConfigManager(path)
    vm = VMConfig("192.0.2.2", "testuser", "vm1", 22, tmp_path / "key")
    with pytest.raises(OperationCancelled):
        manager.upsert(vm, on_conflict=lambda _alias: "cancel")
    assert "HostName old" in path.read_text(encoding="utf-8")


def test_remove_only_target_host(tmp_path):
    path = tmp_path / "config"
    path.write_text("Host one\n  HostName 1.1.1.1\n\nHost two\n  HostName 2.2.2.2\n", encoding="utf-8")
    manager = SSHConfigManager(path)
    assert manager.remove("one")
    text = path.read_text(encoding="utf-8")
    assert "Host one" not in text
    assert "Host two" in text


def test_match_section_is_not_absorbed_into_host_block(tmp_path):
    path = tmp_path / "config"
    path.write_text("Host vm1\n  HostName old\nMatch user admin\n  ServerAliveInterval 99\n", encoding="utf-8")
    manager = SSHConfigManager(path)
    vm = VMConfig("192.0.2.8", "testuser", "vm1", 22, tmp_path / "key")
    manager.upsert(vm, on_conflict=lambda _alias: "update")
    text = path.read_text(encoding="utf-8")
    assert "Match user admin" in text
    assert "ServerAliveInterval 99" in text
    assert "HostName 192.0.2.8" in text


def test_preserves_windows_crlf_line_endings(tmp_path):
    path = tmp_path / "config"
    path.write_bytes(b"Host existing\r\n    User git\r\n")
    manager = SSHConfigManager(path)
    vm = VMConfig("192.0.2.10", "testuser", "vm2", 22, tmp_path / "key")
    manager.upsert(vm)
    raw = path.read_bytes()
    assert b"\r\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_new_host_is_inserted_before_matching_wildcard_block(tmp_path):
    path = tmp_path / "config"
    path.write_text(
        "Host *\n    ServerAliveInterval 99\n    User shared\n\n"
        "Host github.com\n    User git\n",
        encoding="utf-8",
    )
    manager = SSHConfigManager(path)
    vm = VMConfig("192.0.2.30", "testuser", "ubuntu-vm", 22, tmp_path / "key")
    manager.upsert(vm)
    text = path.read_text(encoding="utf-8")
    assert text.index("Host ubuntu-vm") < text.index("Host *")
    assert text.index("Host *") < text.index("Host github.com")


def test_global_managed_directive_is_reported_instead_of_creating_ineffective_host(tmp_path):
    from vmssh.core.exceptions import ConfigConflictError

    path = tmp_path / "config"
    original = "User global-user\nHost github.com\n    User git\n"
    path.write_text(original, encoding="utf-8")
    manager = SSHConfigManager(path)
    vm = VMConfig("192.0.2.31", "testuser", "ubuntu-vm", 22, tmp_path / "key")
    with pytest.raises(ConfigConflictError, match="全局区段"):
        manager.upsert(vm)
    assert path.read_text(encoding="utf-8") == original


def test_new_host_is_inserted_before_match_section_when_no_host_blocks(tmp_path):
    path = tmp_path / "config"
    path.write_text("Match user admin\n    ServerAliveInterval 99\n", encoding="utf-8")
    manager = SSHConfigManager(path)
    vm = VMConfig("192.0.2.32", "testuser", "ubuntu-vm", 22, tmp_path / "key")
    manager.upsert(vm)
    text = path.read_text(encoding="utf-8")
    assert text.index("Host ubuntu-vm") < text.index("Match user admin")
