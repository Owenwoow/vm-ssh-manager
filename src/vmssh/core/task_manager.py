from __future__ import annotations

from vmssh.core.config_manager import SSHConfigManager
from vmssh.core.connection_tester import ConnectionTester
from vmssh.core.key_manager import KeyManager
from vmssh.core.models import InitReport, StepResult, VMConfig
from vmssh.core.public_key_deployer import install_public_key
from vmssh.core.registry import VMRegistry
from vmssh.core.ssh_client import SSHConnection
from vmssh.core.sudo_manager import SudoManager
from vmssh.core.exceptions import OperationCancelled
from vmssh.utils.validators import validate_alias, validate_host, validate_port, validate_username


class InitializationManager:
    def __init__(self, key_manager: KeyManager | None = None,
                 config_manager: SSHConfigManager | None = None,
                 registry: VMRegistry | None = None,
                 logger=None):
        self.keys = key_manager or KeyManager()
        self.config = config_manager or SSHConfigManager()
        self.registry = registry or VMRegistry()
        self.logger = logger or (lambda _message: None)

    def initialize(self, vm: VMConfig, login_password: str, enable_sudo: bool = True,
                   sudo_password: str | None = None, key_passphrase: str | None = None,
                   confirm_host_key=None, on_config_conflict=None, on_step=None,
                   create_default_key: bool = True, deploy_key: bool = True,
                   write_config: bool = True, test_connection: bool = True) -> InitReport:
        report = InitReport(vm)

        def step(name: str, status: str, message: str = ""):
            report.steps.append(StepResult(name, status, message))
            self.logger(f"[{status.upper()}] {name}: {message}" if message else f"[{status.upper()}] {name}")
            if on_step:
                on_step(name, status, message)

        try:
            vm.hostname = validate_host(vm.hostname)
            vm.username = validate_username(vm.username)
            vm.host_alias = validate_alias(vm.host_alias)
            vm.port = validate_port(vm.port)
            if vm.username == "root" and enable_sudo:
                raise ValueError("root 用户不需要 sudo；请关闭免密 sudo 选项。")
            if vm.key_path is None:
                vm.key_path = self.keys.default_private_key
            if not vm.key_path.exists() and create_default_key and vm.key_path == self.keys.default_private_key:
                self.keys.generate_default(key_passphrase)
                step("key_generation", "success", f"已生成 {vm.key_path.name}")
            key, public_line = self.keys.load_key(vm.key_path, key_passphrase)
            step("key_validation", "success", f"密钥有效：{vm.key_path.name} · {key.get_name()} · {self.keys.fingerprint(key)}")
        except Exception as exc:
            step("key_validation", "failed", str(exc))
            report.finish()
            return report

        connection = SSHConnection(self.keys.ssh_dir, self.logger)
        try:
            connection.connect_password(vm.hostname, vm.port, vm.username, login_password,
                                        confirm_host_key or (lambda *_: False))
            step("ssh_password_connection", "success", "已通过密码建立首次 SSH 连接，主机指纹已验证。")
        except Exception as exc:
            step("ssh_password_connection", "failed", str(exc))
            report.finish()
            return report

        if deploy_key:
            try:
                added = install_public_key(connection, public_line)
                step("public_key_deployment", "success", "公钥已追加。" if added else "该公钥已存在，未重复添加。")
            except Exception as exc:
                step("public_key_deployment", "failed", str(exc))
                connection.close()
                report.finish()
                return report
        else:
            step("public_key_deployment", "skipped", "用户关闭了自动部署公钥。")

        sudo_ok = False
        if enable_sudo:
            try:
                if vm.username == "root":
                    raise ValueError("免密 sudo 只针对普通用户；root 用户无需 sudo。")
                backup = SudoManager().configure_nopasswd(
                    connection, vm.username, sudo_password if sudo_password is not None else login_password
                )
                sudo_ok = True
                step("sudo_nopasswd", "success", "NOPASSWD sudo 已配置并通过清除缓存后的 sudo -k && sudo -n whoami 验证。" + (f" 备份：{backup}" if backup else ""))
            except Exception as exc:
                step("sudo_nopasswd", "failed", str(exc))
        else:
            step("sudo_nopasswd", "skipped", "用户未启用免密 sudo。")
        connection.close()

        config_ok = False
        if write_config:
            try:
                self.config.upsert(vm, on_conflict=on_config_conflict)
                config_ok = True
                step("ssh_config", "success", f"已更新 {self.config.path}")
            except OperationCancelled as exc:
                step("ssh_config", "cancelled", str(exc))
            except Exception as exc:
                step("ssh_config", "failed", str(exc))
        else:
            step("ssh_config", "skipped", "用户关闭了自动写入 SSH Config。")

        key_auth_ok = False
        if test_connection:
            try:
                ConnectionTester(self.keys.ssh_dir, self.logger).test_public_key(vm, key, confirm_host_key)
                key_auth_ok = True
                step("public_key_authentication", "success", "已使用选定私钥完成 SSH 公钥认证。")
            except Exception as exc:
                step("public_key_authentication", "failed", str(exc))
        else:
            step("public_key_authentication", "skipped", "用户关闭了连接验证。")

        if test_connection and write_config and config_ok:
            native_ok, native_message = ConnectionTester(self.keys.ssh_dir, self.logger).test_native_ssh_config(vm)
            native_status = "success" if native_ok is True else "skipped" if native_ok is None else "failed"
            step("native_ssh_config_test", native_status, native_message)
        else:
            step("native_ssh_config_test", "skipped", "未执行原生 SSH Config 解析测试。")

        if enable_sudo and sudo_ok and test_connection and key_auth_ok:
            verify = SSHConnection(self.keys.ssh_dir, self.logger)
            try:
                verify.connect_key(vm.hostname, vm.port, vm.username, key, confirm_host_key)
                result = verify.run("sudo -k && sudo -n whoami")
                if result.ok and result.stdout.strip() == "root":
                    step("sudo_verification", "success", "sudo -n whoami 返回 root。")
                else:
                    step("sudo_verification", "failed", (result.stderr or result.stdout).strip() or "未返回 root。")
            except Exception as exc:
                step("sudo_verification", "failed", str(exc))
            finally:
                verify.close()
        elif enable_sudo:
            step("sudo_verification", "skipped", "免密 sudo 已配置，但用户关闭了连接验证或公钥认证未通过。")

        if config_ok:
            self.registry.upsert(vm, sudo_ok, status="configured" if report.success else "partial")
        report.finish()
        return report
