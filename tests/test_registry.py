import json
from pathlib import Path

from vmssh.core.models import VMConfig
from vmssh.core.registry import VMRegistry


def test_registry_stores_metadata_but_no_password(tmp_path):
    path = tmp_path / "vms.json"
    registry = VMRegistry(path)
    vm = VMConfig("192.0.2.132", "testuser", "ubuntu-vm", 22, Path("C:/Users/test/.ssh/id_ed25519_vm"))
    registry.upsert(vm, sudo_enabled=True)
    raw = path.read_text(encoding="utf-8")
    assert "ubuntu-vm" in raw
    assert "password" not in raw.lower()
    assert json.loads(raw)[0]["sudo_nopasswd"] is True
