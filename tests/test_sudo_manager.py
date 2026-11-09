import io
from types import SimpleNamespace

import pytest

from vmssh.core.exceptions import RemoteOperationError, ValidationError
from vmssh.core.sudo_manager import SudoManager


class MemoryFile(io.BytesIO):
    def __init__(self, store, path):
        self.store, self.path = store, path
        super().__init__()

    def close(self):
        if not self.closed:
            self.store[self.path] = self.getvalue()
        super().close()


class FakeSFTP:
    def __init__(self):
        self.files = {}
        self.modes = {}

    def open(self, path, mode):
        assert "x" in mode
        return MemoryFile(self.files, path)

    def chmod(self, path, mode):
        self.modes[path] = mode

    def close(self):
        pass


class FakeConnection:
    def __init__(self):
        self.sftp_client = FakeSFTP()
        self.sudo_commands = []
        self.passwords = []

    def run_sudo(self, command, password, timeout=30):
        self.sudo_commands.append(command)
        self.passwords.append(password)
        if command == "id -u":
            return SimpleNamespace(ok=True, stdout="0", stderr="")
        return SimpleNamespace(ok=True, stdout="BACKUP=/etc/sudoers.d/testuser.bak-test\n", stderr="")

    def sftp(self):
        return self.sftp_client

    def run(self, command, timeout=20):
        assert command == "sudo -k && sudo -n whoami"
        return SimpleNamespace(ok=True, stdout="root\n", stderr="")


def test_sudo_manager_stages_and_validates_config_without_passing_password_in_command():
    connection = FakeConnection()
    backup = SudoManager().configure_nopasswd(connection, "testuser", "secret-not-in-command")
    assert backup == "/etc/sudoers.d/testuser.bak-test"
    remote_path = next(iter(connection.sftp_client.files))
    assert remote_path.startswith("/tmp/vmssh-sudoers-")
    assert connection.sftp_client.files[remote_path] == b"testuser ALL=(ALL:ALL) NOPASSWD: ALL\n"
    command = connection.sudo_commands[1]
    assert "visudo -cf" in command
    assert "install -o root -g root -m 0440" in command
    assert "if [ -L" in command
    assert "cp -a --" in command
    assert "mv -f" in command
    assert "secret-not-in-command" not in command
    assert connection.passwords == ["secret-not-in-command", "secret-not-in-command"]


def test_sudo_manager_rejects_invalid_username():
    with pytest.raises(ValidationError):
        SudoManager().configure_nopasswd(FakeConnection(), "testuser;id", "pw")


def test_sudo_manager_rejects_root_account():
    with pytest.raises(RemoteOperationError):
        SudoManager().configure_nopasswd(FakeConnection(), "root", "pw")


def test_sudo_manager_rolls_back_when_nopasswd_verification_fails():
    class VerificationFailure(FakeConnection):
        def run(self, command, timeout=20):
            assert command == "sudo -k && sudo -n whoami"
            return SimpleNamespace(ok=False, stdout="", stderr="sudo: a password is required")

    connection = VerificationFailure()
    with pytest.raises(RemoteOperationError, match="已回滚"):
        SudoManager().configure_nopasswd(connection, "testuser", "secret")
    assert len(connection.sudo_commands) == 3
    assert "cp -a" in connection.sudo_commands[2]
