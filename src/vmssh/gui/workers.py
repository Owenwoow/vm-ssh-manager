from __future__ import annotations

import threading
from PySide6.QtCore import QObject, Signal, Slot

from vmssh.core.models import VMConfig
from vmssh.core.task_manager import InitializationManager


class InitWorker(QObject):
    log = Signal(str)
    progress = Signal(str, str, str)
    host_key_request = Signal(str, str, str, object, object)
    conflict_request = Signal(str, object, object)
    finished = Signal(object)

    def __init__(self, vm: VMConfig, password: str, sudo_enabled: bool, sudo_password: str,
                 key_passphrase: str, create_key: bool = True,
                 deploy_key: bool = True, write_config: bool = True, test_connection: bool = True):
        super().__init__()
        self.vm = vm
        self.password = password
        self.sudo_enabled = sudo_enabled
        self.sudo_password = sudo_password
        self.key_passphrase = key_passphrase
        self.create_key = create_key
        self.deploy_key = deploy_key
        self.write_config = write_config
        self.test_connection = test_connection

    def _ask_host_key(self, host, key_type, fingerprint):
        event = threading.Event()
        response = {"value": False}
        self.host_key_request.emit(host, key_type, fingerprint, event, response)
        if not event.wait(180):
            return False
        return bool(response["value"])

    def _ask_conflict(self, alias):
        event = threading.Event()
        response = {"value": "cancel"}
        self.conflict_request.emit(alias, event, response)
        if not event.wait(180):
            return "cancel"
        return response["value"]

    @Slot()
    def run(self):
        try:
            manager = InitializationManager(logger=self.log.emit)
            report = manager.initialize(
                self.vm, self.password, self.sudo_enabled,
                self.sudo_password or self.password,
                self.key_passphrase or None,
                self._ask_host_key, self._ask_conflict,
                lambda name, status, message: self.progress.emit(name, status, message),
                self.create_key, self.deploy_key, self.write_config, self.test_connection,
            )
            self.finished.emit(report)
        except Exception as exc:
            self.log.emit(f"[ERROR] {exc}")
            self.finished.emit(None)
        finally:
            self.password = ""
            self.sudo_password = ""
            self.key_passphrase = ""


class RevokeWorker(QObject):
    log = Signal(str)
    host_key_request = Signal(str, str, str, object, object)
    finished = Signal(bool, str)

    def __init__(self, hostname: str, username: str, port: int, password: str,
                 key_path, key_passphrase: str = ""):
        super().__init__()
        self.hostname = hostname
        self.username = username
        self.port = port
        self.password = password
        self.key_path = key_path
        self.key_passphrase = key_passphrase

    def _ask_host_key(self, host, key_type, fingerprint):
        event = threading.Event()
        response = {"value": False}
        self.host_key_request.emit(host, key_type, fingerprint, event, response)
        if not event.wait(180):
            return False
        return bool(response["value"])

    @Slot()
    def run(self):
        from vmssh.core.key_manager import KeyManager
        from vmssh.core.public_key_deployer import revoke_public_key
        from vmssh.core.ssh_client import SSHConnection

        connection = SSHConnection(KeyManager().ssh_dir, self.log.emit)
        try:
            _key, public_line = KeyManager().load_key(self.key_path, self.key_passphrase or None)
            connection.connect_password(self.hostname, self.port, self.username,
                                        self.password, self._ask_host_key)
            removed = revoke_public_key(connection, public_line)
            self.finished.emit(removed, "指定公钥已撤销；服务器端保留了 authorized_keys 备份。" if removed
                               else "服务器 authorized_keys 中未找到该公钥，没有修改文件。")
        except Exception as exc:
            self.log.emit(f"[ERROR] {exc}")
            self.finished.emit(False, str(exc))
        finally:
            connection.close()
            self.password = ""
            self.key_passphrase = ""
