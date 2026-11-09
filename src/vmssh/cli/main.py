from __future__ import annotations

import argparse
import getpass
import re
from pathlib import Path

from vmssh import __version__
from vmssh.core.config_manager import SSHConfigManager
from vmssh.core.exceptions import VMSSHError
from vmssh.core.key_manager import KeyManager
from vmssh.core.models import VMConfig
from vmssh.core.public_key_deployer import revoke_public_key
from vmssh.core.registry import VMRegistry
from vmssh.core.ssh_client import SSHConnection
from vmssh.core.task_manager import InitializationManager
from vmssh.utils.validators import validate_alias, validate_host, validate_port, validate_username


def yes_no(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    value = input(f"{prompt} {suffix}: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "是"}


def host_key_confirm(host: str, key_type: str, fingerprint: str) -> bool:
    print("\n首次连接主机指纹确认")
    print(f"主机：{host}")
    print(f"算法：{key_type}")
    print(f"指纹：{fingerprint}")
    print("请通过 VMware 控制台或可信渠道核对该指纹。")
    return yes_no("确认信任该主机密钥？", default=False)


def config_conflict(alias: str) -> str:
    return "update" if yes_no(f"Host {alias} 已存在，是否更新该 Host 块？", default=False) else "cancel"


def choose_key(keys: KeyManager, selected: Path | None) -> Path:
    candidates = keys.list_private_keys()
    if selected and selected.exists():
        return selected
    default = keys.default_private_key
    if default.exists():
        return default
    print("未发现默认 VM 密钥。")
    if yes_no("现在生成默认 Ed25519 密钥 id_ed25519_vm？", True):
        # Generate after asking for the passphrase in create_vm, avoiding a duplicate prompt.
        return default
    if not candidates:
        raise VMSSHError("没有可用私钥。")
    print("可用密钥：")
    for i, path in enumerate(candidates, 1):
        print(f"{i}. {path}")
    idx = int(input("选择序号：")) - 1
    return candidates[idx]


def create_vm(keys: KeyManager, registry: VMRegistry, selected_key: Path | None) -> Path | None:
    host = validate_host(input("请输入 Linux IP/主机名："))
    username = validate_username(input("请输入 Linux 用户名："))
    password = getpass.getpass("请输入 Linux 登录密码（不保存）：")
    port_raw = input("请输入 SSH 端口（默认 22）：").strip() or "22"
    port = validate_port(port_raw)
    safe_host = re.sub(r"[^A-Za-z0-9.-]", "-", host).strip(".-")
    default_alias = f"{username}-{safe_host}"[:64].rstrip(".-") or f"{username}-vm"
    alias = validate_alias(input(f"请输入 SSH Host 别名（默认 {default_alias}）：").strip() or default_alias)
    key_path = choose_key(keys, selected_key)
    key_passphrase = getpass.getpass("私钥口令（未设置则留空）：")
    if key_path.exists() and not Path(str(key_path) + ".pub").exists():
        if yes_no("检测到私钥存在但公钥文件缺失。是否从私钥安全地重新导出公钥？", False):
            keys.repair_missing_public_key(key_path, key_passphrase or None)
        else:
            raise VMSSHError("密钥文件不完整，已取消初始化。")
    if not key_path.exists() and key_path == keys.default_private_key:
        keys.generate_default(key_passphrase or None)
    if username == "root":
        enable_sudo = False
        print("检测到使用 root 账户：root 不需要 sudo，自动跳过 sudoers 配置。")
    else:
        enable_sudo = yes_no("是否配置普通用户 NOPASSWD sudo？（该用户将可取得完整 root 权限）", True)
    sudo_password = password
    if enable_sudo and not yes_no("sudo 密码是否与 Linux 登录密码相同？", True):
        sudo_password = getpass.getpass("请输入 sudo 密码（不保存）：")
    notes = input("备注（可选）：").strip()
    vm = VMConfig(host, username, alias, port, key_path, notes)
    manager = InitializationManager(keys, SSHConfigManager(), registry, logger=print)
    report = manager.initialize(vm, password, enable_sudo, sudo_password, key_passphrase or None,
                                host_key_confirm, config_conflict)
    print_report(report)
    return key_path


def print_report(report) -> None:
    print("\n========== VM SSH Manager 初始化报告 ==========")
    print(f"目标：{report.config.username}@{report.config.hostname}:{report.config.port}")
    print(f"Host：{report.config.host_alias}")
    print(f"密钥：{report.config.key_path}")
    for step in report.steps:
        label = {"success": "成功", "failed": "失败", "skipped": "跳过", "cancelled": "取消"}.get(step.status, step.status)
        print(f"[{label}] {step.name} {('- ' + step.message) if step.message else ''}")
    print("初始化完成！" if report.success else "初始化未完全成功，请根据失败步骤处理后重试。")
    if report.success:
        print(f"\n以后执行：\n  ssh {report.config.host_alias}")


def list_keys(keys: KeyManager) -> None:
    candidates = keys.list_private_keys()
    if not candidates:
        print("未发现 SSH 私钥。")
    for path in candidates:
        try:
            key, _public = keys.load_key(path)
            state = f"{key.get_name()} · {keys.fingerprint(key)}"
        except Exception as exc:
            state = "需要私钥口令或密钥文件待检查" if exc.__class__.__name__ == "PasswordRequiredException" else f"未验证：{exc}"
        print(f"- {path} {'(默认)' if path == keys.default_private_key else ''} · {state}")


def manage_vms(registry: VMRegistry, config: SSHConfigManager, keys: KeyManager) -> None:
    records = registry.all()
    if not records:
        print("尚无已登记 VM。")
        return
    for row in records:
        state = "已配置" if row.get("status", "configured") == "configured" else "部分配置"
        print(f"{row.get('host_alias')}  {row.get('username')}@{row.get('hostname')}:{row.get('port')}  key={row.get('key_path')}  [{state}]")
    alias = input("输入要管理的 Host 别名（留空返回）：").strip()
    record = next((item for item in records if item.get("host_alias") == alias), None)
    if not record:
        return
    action = input("1. 编辑本地 Host 配置  2. 删除本地 Host 配置：").strip()
    if action == "2":
        if yes_no(f"确认从 Windows SSH Config 删除 {alias}？不会删除服务器公钥。", False):
            removed = config.remove(alias)
            registry.remove(alias)
            print("已删除本地 Host 配置。" if removed else "未找到对应 Host；已清理本地登记记录。")
    elif action == "1":
        host = validate_host(input(f"IP/主机名 [{record.get('hostname')}]: ").strip() or record.get("hostname"))
        username = validate_username(input(f"用户名 [{record.get('username')}]: ").strip() or record.get("username"))
        port = validate_port(input(f"SSH 端口 [{record.get('port', 22)}]: ").strip() or record.get("port", 22))
        key_path = Path(input(f"私钥路径 [{record.get('key_path')}]: ").strip() or record.get("key_path")).expanduser()
        if not key_path.exists() or not Path(str(key_path) + ".pub").exists():
            raise VMSSHError("私钥或对应公钥文件不存在，未修改本地配置。")
        passphrase = getpass.getpass("私钥口令（未设置则留空）：")
        keys.load_key(key_path, passphrase or None)
        notes = input(f"备注 [{record.get('notes', '')}]: ").strip() or record.get("notes", "")
        vm = VMConfig(host, username, alias, port, key_path, notes)
        config.upsert(vm, on_conflict=lambda _alias: "update")
        registry.upsert(vm, bool(record.get("sudo_nopasswd")) and username != "root",
                         status=record.get("status", "configured"))
        print(f"已更新 {alias} 的本地 SSH Config 和登记信息。服务器端未修改。")


def revoke_key(keys: KeyManager) -> None:
    host = validate_host(input("Linux IP/主机名："))
    username = validate_username(input("Linux 用户名："))
    port = validate_port(input("SSH 端口（默认 22）：").strip() or "22")
    password = getpass.getpass("Linux 登录密码（不保存）：")
    key_path = Path(input(f"本地私钥路径（默认 {keys.default_private_key}）：").strip() or keys.default_private_key)
    passphrase = getpass.getpass("私钥口令（未设置则留空）：")
    _key, public_line = keys.load_key(key_path, passphrase or None)
    if not yes_no("将删除服务器 authorized_keys 中与此密钥完全匹配的条目（包括重复项），继续？", False):
        return
    connection = SSHConnection(keys.ssh_dir)
    try:
        connection.connect_password(host, port, username, password, host_key_confirm)
        removed = revoke_public_key(connection, public_line)
        print("已撤销指定公钥。" if removed else "服务器上未找到该公钥，无需修改。")
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="VM SSH Manager CLI")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args()
    keys = KeyManager()
    registry = VMRegistry()
    config = SSHConfigManager()
    selected_key: Path | None = None
    print("==================================")
    print("       VM SSH Manager CLI")
    print(f"             v{__version__}")
    print("==================================")
    while True:
        print("\n1. 新建 Linux VM SSH 配置")
        print("2. 查看本地 SSH 密钥")
        print("3. 选择已有密钥 / 生成自定义密钥")
        print("4. 管理已配置的 VM")
        print("5. 删除 SSH Host 配置")
        print("6. 撤销服务器公钥")
        print("7. 退出")
        choice = input("\n请选择：").strip()
        try:
            if choice == "1":
                selected_key = create_vm(keys, registry, selected_key)
            elif choice == "2":
                list_keys(keys)
            elif choice == "3":
                action = input("1. 选择 .ssh 中已有密钥  2. 生成自定义密钥  3. 输入已有密钥路径：").strip()
                if action == "2":
                    custom_path = Path(input("输入新私钥完整路径（例如 C:/Users/you/.ssh/id_ed25519_lab）：").strip()).expanduser()
                    passphrase = getpass.getpass("私钥口令（留空表示不设置）：")
                    selected_key = keys.generate_key(custom_path, passphrase or None)
                    print(f"已生成并选择：{selected_key}")
                elif action == "3":
                    custom_path = Path(input("输入已有私钥完整路径：").strip()).expanduser()
                    if not custom_path.is_file():
                        raise VMSSHError("指定私钥不存在。")
                    selected_key = custom_path
                    print(f"已选择：{selected_key}")
                else:
                    candidates = keys.list_private_keys()
                    for i, path in enumerate(candidates, 1): print(f"{i}. {path}")
                    if candidates:
                        selected_key = candidates[int(input("选择序号：")) - 1]
                        print(f"已选择：{selected_key}")
                    else:
                        print("未发现可用私钥。")
            elif choice == "4":
                manage_vms(registry, config, keys)
            elif choice == "5":
                alias = validate_alias(input("要删除的 Host 别名："))
                if yes_no(f"确认删除本地 Host {alias}？不影响服务器公钥。", False):
                    print("已删除。" if config.remove(alias) else "未找到该 Host。")
                    registry.remove(alias)
            elif choice == "6":
                revoke_key(keys)
            elif choice == "7":
                return 0
            else:
                print("无效选项。")
        except Exception as exc:
            print(f"操作失败：{exc}")
        except KeyboardInterrupt:
            print("\n已取消当前输入。")
        input("\n按 Enter 继续...")


if __name__ == "__main__":
    raise SystemExit(main())
