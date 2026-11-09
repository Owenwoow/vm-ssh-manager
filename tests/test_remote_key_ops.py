import io
import stat
from types import SimpleNamespace

from vmssh.core.public_key_deployer import install_public_key, revoke_public_key


class MemoryFile(io.BytesIO):
    def __init__(self, store, path, mode):
        self.store, self.path, self.mode = store, path, mode
        super().__init__(store.get(path, b"") if "r" in mode else b"")
        if "a" in mode:
            self.seek(0, io.SEEK_END)

    def close(self):
        if not self.closed and any(flag in self.mode for flag in "wax"):
            self.store[self.path] = self.getvalue()
        super().close()


class FakeSFTP:
    def __init__(self, files=None):
        self.files = dict(files or {})
        self.dirs = {"/home/testuser", "/home/testuser/.ssh"}
        self.modes = {"/home/testuser/.ssh": 0o700}
        self.owners = {"/home/testuser/.ssh": 1000}
        self.file_owners = {}

    def lstat(self, path):
        if path in self.dirs:
            return SimpleNamespace(st_mode=stat.S_IFDIR | self.modes.get(path, 0o700), st_uid=self.owners.get(path, 1000))
        if path in self.files:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=self.file_owners.get(path, 1000))
        raise FileNotFoundError(path)

    def stat(self, path):
        return self.lstat(path)

    def mkdir(self, path, mode):
        self.dirs.add(path)
        self.modes[path] = mode
        self.owners[path] = 1000

    def chmod(self, path, mode):
        self.modes[path] = mode

    def open(self, path, mode):
        return MemoryFile(self.files, path, mode)

    def posix_rename(self, src, dst):
        self.files[dst] = self.files.pop(src)

    def rename(self, src, dst):
        self.files[dst] = self.files.pop(src)

    def remove(self, path):
        self.files.pop(path, None)

    def close(self):
        pass


class FakeConnection:
    def __init__(self, sftp):
        self._sftp = sftp

    def run(self, command):
        if command.startswith("printf"):
            return SimpleNamespace(ok=True, stdout="/home/testuser", stderr="")
        if command == "id -u":
            return SimpleNamespace(ok=True, stdout="1000", stderr="")
        raise AssertionError(command)

    def sftp(self):
        return self._sftp


def test_install_is_idempotent_and_preserves_existing_lines():
    original = b"ssh-rsa QUJDREVGRw== existing-key\n"
    sftp = FakeSFTP({"/home/testuser/.ssh/authorized_keys": original})
    connection = FakeConnection(sftp)
    new_key = "ssh-ed25519 QUJDREVGR0g= vm-key"
    assert install_public_key(connection, new_key) is True
    installed = sftp.files["/home/testuser/.ssh/authorized_keys"]
    assert original in installed
    assert installed.count(b"ssh-ed25519 QUJDREVGR0g=") == 1
    assert sftp.modes["/home/testuser/.ssh"] == 0o700
    assert sftp.modes["/home/testuser/.ssh/authorized_keys"] == 0o600
    assert install_public_key(connection, new_key) is False
    assert sftp.files["/home/testuser/.ssh/authorized_keys"].count(b"ssh-ed25519 QUJDREVGR0g=") == 1


def test_revoke_removes_only_matching_key_and_keeps_backup():
    original = b"ssh-rsa QUJDREVGRw== existing-key\nssh-ed25519 QUJDREVGR0g= vm-key\n"
    sftp = FakeSFTP({"/home/testuser/.ssh/authorized_keys": original})
    connection = FakeConnection(sftp)
    assert revoke_public_key(connection, "ssh-ed25519 QUJDREVGR0g= vm-key") is True
    updated = sftp.files["/home/testuser/.ssh/authorized_keys"]
    assert b"ssh-rsa QUJDREVGRw== existing-key" in updated
    assert b"ssh-ed25519 QUJDREVGR0g=" not in updated
    assert any(name.startswith("/home/testuser/.ssh/authorized_keys.bak-") for name in sftp.files)


def test_revoke_rejects_invalid_public_key_without_touching_file():
    original = b"# keep this comment\nssh-ed25519 QUJDREVGR0g= vm-key\n"
    sftp = FakeSFTP({"/home/testuser/.ssh/authorized_keys": original})
    connection = FakeConnection(sftp)
    import pytest
    from vmssh.core.exceptions import RemoteOperationError
    with pytest.raises(RemoteOperationError):
        revoke_public_key(connection, "not a public key")
    assert sftp.files["/home/testuser/.ssh/authorized_keys"] == original


def test_install_refuses_to_replace_authorized_keys_owned_by_another_user():
    import pytest
    from vmssh.core.exceptions import RemoteOperationError

    auth_path = "/home/testuser/.ssh/authorized_keys"
    original = b"ssh-ed25519 QUJDREVGRw== old-key\n"
    sftp = FakeSFTP({auth_path: original})
    sftp.file_owners[auth_path] = 0
    connection = FakeConnection(sftp)
    with pytest.raises(RemoteOperationError, match="所有者"):
        install_public_key(connection, "ssh-ed25519 QUJDREVGR0g= new-key")
    assert sftp.files[auth_path] == original


def test_remote_home_root_is_rejected():
    import pytest
    from vmssh.core.public_key_deployer import _remote_home
    from vmssh.core.exceptions import RemoteOperationError

    class RootHomeConnection:
        def run(self, command):
            return SimpleNamespace(ok=True, stdout="/\n", stderr="")

    with pytest.raises(RemoteOperationError):
        _remote_home(RootHomeConnection())


def test_revoke_preserves_unrelated_non_utf8_bytes():
    original = b"# comment with invalid byte: \xff\nssh-ed25519 QUJDREVGR0g= vm-key\n"
    sftp = FakeSFTP({"/home/testuser/.ssh/authorized_keys": original})
    connection = FakeConnection(sftp)
    assert revoke_public_key(connection, "ssh-ed25519 QUJDREVGR0g= vm-key") is True
    assert sftp.files["/home/testuser/.ssh/authorized_keys"] == b"# comment with invalid byte: \xff\n"
