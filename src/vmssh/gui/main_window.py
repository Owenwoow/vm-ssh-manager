from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QProgressBar, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget, QInputDialog,
)

from vmssh import __version__
from vmssh.core.config_manager import SSHConfigManager
from vmssh.core.key_manager import KeyManager
from vmssh.core.models import VMConfig
from vmssh.core.registry import VMRegistry
from vmssh.gui.workers import InitWorker, RevokeWorker
from vmssh.utils.validators import validate_alias, validate_host, validate_port, validate_username


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"VM SSH Manager v{__version__}")
        self.resize(980, 780)
        self.keys = KeyManager()
        self.registry = VMRegistry()
        self.config_manager = SSHConfigManager()
        self.thread = None
        self.worker = None
        self.editing_record = None
        self._build_ui()
        self._refresh_keys()
        self._refresh_vms()
        self._apply_style()

    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)
        title = QLabel("VM SSH Manager")
        title.setObjectName("title")
        subtitle = QLabel("为 VMware Linux 虚拟机自动部署 SSH 公钥、维护 SSH Config，并可选配置免密 sudo")
        subtitle.setObjectName("subtitle")
        root.addWidget(title)
        root.addWidget(subtitle)

        key_group = QGroupBox("1. SSH 密钥管理")
        key_layout = QGridLayout(key_group)
        self.key_combo = QComboBox()
        self.key_status = QLabel("检查中")
        self.key_passphrase = QLineEdit()
        self.key_passphrase.setEchoMode(QLineEdit.Password)
        self.key_passphrase.setPlaceholderText("如果私钥已加密，请输入私钥口令（仅保留在内存）")
        choose_btn = QPushButton("选择私钥…")
        choose_btn.clicked.connect(self._choose_key)
        generate_btn = QPushButton("生成默认密钥")
        generate_btn.clicked.connect(self._generate_key)
        custom_btn = QPushButton("生成自定义密钥…")
        custom_btn.clicked.connect(self._generate_custom_key)
        key_layout.addWidget(QLabel("当前密钥"), 0, 0)
        key_layout.addWidget(self.key_combo, 0, 1)
        key_layout.addWidget(choose_btn, 0, 2)
        key_layout.addWidget(generate_btn, 0, 3)
        key_layout.addWidget(custom_btn, 0, 4)
        key_layout.addWidget(QLabel("状态 / 指纹"), 1, 0)
        key_layout.addWidget(self.key_status, 1, 1, 1, 4)
        key_layout.addWidget(QLabel("私钥口令"), 2, 0)
        key_layout.addWidget(self.key_passphrase, 2, 1, 1, 4)
        self.key_combo.currentIndexChanged.connect(self._update_key_status)
        self.key_passphrase.textChanged.connect(self._update_key_status)
        root.addWidget(key_group)

        connection_group = QGroupBox("2. Linux 虚拟机连接配置")
        form = QFormLayout(connection_group)
        self.host = QLineEdit()
        self.host.setPlaceholderText("例如 192.0.2.132")
        self.username = QLineEdit()
        self.username.setPlaceholderText("例如 testuser / kali")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("首次 SSH 登录密码，不会保存")
        self.port = QLineEdit("22")
        self.alias = QLineEdit()
        self.alias.setPlaceholderText("例如 ubuntu-vm")
        self.notes = QLineEdit()
        form.addRow("Linux IP / 主机名", self.host)
        form.addRow("Linux 用户名", self.username)
        form.addRow("Linux 登录密码", self.password)
        form.addRow("SSH 端口", self.port)
        form.addRow("SSH Host 别名", self.alias)
        form.addRow("备注", self.notes)
        root.addWidget(connection_group)

        options_group = QGroupBox("3. 初始化选项")
        options_layout = QHBoxLayout(options_group)
        self.deploy_check = QCheckBox("自动部署 SSH 公钥")
        self.deploy_check.setChecked(True)
        self.sudo_check = QCheckBox("配置普通用户免密 sudo（NOPASSWD: ALL）")
        self.sudo_check.setChecked(True)
        self.config_check = QCheckBox("写入 Windows SSH Config")
        self.config_check.setChecked(True)
        self.test_check = QCheckBox("执行连接验证")
        self.test_check.setChecked(True)
        options_layout.addWidget(self.deploy_check)
        options_layout.addWidget(self.sudo_check)
        options_layout.addWidget(self.config_check)
        options_layout.addWidget(self.test_check)
        root.addWidget(options_group)

        action_row = QHBoxLayout()
        self.start_btn = QPushButton("开始初始化")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self._start)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        action_row.addWidget(self.start_btn)
        action_row.addWidget(self.progress, 1)
        root.addLayout(action_row)

        log_group = QGroupBox("4. 执行日志 / 结果")
        log_layout = QVBoxLayout(log_group)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(180)
        log_layout.addWidget(self.log_view)
        root.addWidget(log_group, 1)

        vm_group = QGroupBox("5. 已配置的虚拟机")
        vm_layout = QVBoxLayout(vm_group)
        self.vm_table = QTableWidget(0, 6)
        self.vm_table.setHorizontalHeaderLabels(["Host", "IP", "用户", "端口", "密钥", "状态"])
        self.vm_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vm_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vm_table.setEditTriggers(QTableWidget.NoEditTriggers)
        vm_layout.addWidget(self.vm_table)
        vm_actions = QHBoxLayout()
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self._refresh_vms)
        edit_btn = QPushButton("编辑本地 Host")
        edit_btn.clicked.connect(self._edit_local_host)
        self.save_local_btn = QPushButton("保存本地编辑")
        self.save_local_btn.clicked.connect(self._save_local_host_edit)
        self.save_local_btn.setVisible(False)
        delete_btn = QPushButton("删除本地 Host 配置")
        delete_btn.clicked.connect(self._delete_local_host)
        revoke_btn = QPushButton("撤销服务器公钥")
        revoke_btn.clicked.connect(self._revoke_server_key)
        vm_actions.addWidget(refresh_btn)
        vm_actions.addWidget(edit_btn)
        vm_actions.addWidget(self.save_local_btn)
        vm_actions.addWidget(delete_btn)
        vm_actions.addWidget(revoke_btn)
        vm_actions.addStretch(1)
        vm_layout.addLayout(vm_actions)
        root.addWidget(vm_group)
        self.setCentralWidget(central)
        self.statusBar().showMessage("就绪")

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background: #f4f6f9; }
            QGroupBox { background: white; border: 1px solid #d8dee8; border-radius: 8px; margin-top: 10px; padding: 12px; font-weight: 600; }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 5px; }
            QLabel#title { font-size: 25px; font-weight: 700; color: #172033; }
            QLabel#subtitle { color: #64748b; margin-bottom: 6px; }
            QLineEdit, QComboBox, QTextEdit, QTableWidget { background: white; border: 1px solid #cbd5e1; border-radius: 5px; padding: 6px; }
            QPushButton { padding: 8px 14px; border: 1px solid #cbd5e1; border-radius: 5px; background: #fff; }
            QPushButton:hover { background: #eef2f7; }
            QPushButton#primary { background: #1d4ed8; color: white; border: 0; font-weight: 600; }
            QPushButton#primary:hover { background: #1e40af; }
        """)

    def _log(self, text: str):
        self.log_view.append(text)

    def _refresh_keys(self):
        current = self.key_combo.currentData()
        self.key_combo.blockSignals(True)
        self.key_combo.clear()
        keys = self.keys.list_private_keys()
        for path in keys:
            self.key_combo.addItem(str(path), str(path))
        if current and Path(current).exists() and self.key_combo.findData(current) < 0:
            self.key_combo.addItem(current, current)
        default = self.keys.default_private_key
        if default.exists() and self.key_combo.findData(str(default)) >= 0:
            self.key_combo.setCurrentIndex(self.key_combo.findData(str(default)))
        elif current and self.key_combo.findData(current) >= 0:
            self.key_combo.setCurrentIndex(self.key_combo.findData(current))
        self.key_combo.blockSignals(False)
        self._update_key_status()

    def _update_key_status(self):
        path_value = self.key_combo.currentData()
        if not path_value:
            self.key_status.setText("未发现默认密钥；首次初始化时可自动生成。")
            return
        path = Path(path_value)
        try:
            key, _public = self.keys.load_key(path, self.key_passphrase.text() or None)
            self.key_status.setText(f"密钥有效 · {key.get_name()} · {self.keys.fingerprint(key)}")
        except Exception as exc:
            self.key_status.setText(f"密钥文件存在，但尚未验证：{exc}")

    def _choose_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择 SSH 私钥", str(self.keys.ssh_dir), "SSH private keys (*)")
        if path:
            if self.key_combo.findData(path) < 0:
                self.key_combo.addItem(path, path)
            self.key_combo.setCurrentIndex(self.key_combo.findData(path))
            self._update_key_status()

    def _generate_key(self):
        if self.keys.default_private_key.exists() or Path(str(self.keys.default_private_key) + ".pub").exists():
            QMessageBox.warning(self, "密钥已存在", "默认密钥路径已有文件。为避免覆盖，请选择现有密钥或手动检查不完整密钥。")
            return
        passphrase, ok = QInputDialog.getText(self, "生成 Ed25519 密钥", "私钥口令（留空表示不设置）：", QLineEdit.Password)
        if not ok: return
        try:
            path = self.keys.generate_default(passphrase or None)
            self.key_passphrase.setText(passphrase)
            self._refresh_keys()
            idx = self.key_combo.findData(str(path))
            if idx >= 0: self.key_combo.setCurrentIndex(idx)
            QMessageBox.information(self, "完成", f"已生成密钥：\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "生成失败", str(exc))

    def _generate_custom_key(self):
        path, _ = QFileDialog.getSaveFileName(self, "生成自定义 Ed25519 密钥", str(self.keys.ssh_dir / "id_ed25519_custom"), "SSH private key (*)")
        if not path:
            return
        passphrase, ok = QInputDialog.getText(self, "生成自定义密钥", "私钥口令（留空表示不设置）：", QLineEdit.Password)
        if not ok:
            return
        try:
            created = self.keys.generate_key(Path(path), passphrase or None)
            self.key_passphrase.setText(passphrase)
            if self.key_combo.findData(str(created)) < 0:
                self.key_combo.addItem(str(created), str(created))
            self.key_combo.setCurrentIndex(self.key_combo.findData(str(created)))
            QMessageBox.information(self, "完成", f"已生成密钥：\n{created}")
        except Exception as exc:
            QMessageBox.critical(self, "生成失败", str(exc))

    def _start(self):
        try:
            host = validate_host(self.host.text())
            username = validate_username(self.username.text())
            port = validate_port(self.port.text() or "22")
            alias = validate_alias(self.alias.text() or f"{username}-vm")
            password = self.password.text()
            if not password:
                raise ValueError("请输入 Linux 登录密码。")
            key_data = self.key_combo.currentData()
            key_path = Path(key_data) if key_data else self.keys.default_private_key
            if not key_path.exists() and (key_path != self.keys.default_private_key):
                raise ValueError("所选私钥不存在。")
            if key_path.exists() and not Path(str(key_path) + ".pub").exists():
                answer = QMessageBox.question(
                    self, "密钥文件不完整",
                    "检测到私钥存在但公钥文件缺失。是否从私钥安全地重新导出公钥？不会覆盖任何现有文件。",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
                )
                if answer != QMessageBox.Yes:
                    return
                self.keys.repair_missing_public_key(key_path, self.key_passphrase.text() or None)
                self._refresh_keys()
            vm = VMConfig(host, username, alias, port, key_path, self.notes.text())
        except Exception as exc:
            QMessageBox.warning(self, "输入有误", str(exc))
            return

        enable_sudo = self.sudo_check.isChecked()
        if username == "root" and enable_sudo:
            QMessageBox.information(self, "无需配置 sudo", "当前使用 root 账户；root 已拥有管理员权限，将自动跳过 sudoers 配置。")
            self.sudo_check.setChecked(False)
            enable_sudo = False
        warning = "NOPASSWD: ALL 会让该用户无需密码即可取得完整 root 权限。只建议在你自己的实验虚拟机启用。"
        if enable_sudo:
            if QMessageBox.question(self, "安全确认", warning + "\n\n继续配置？", QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                return
        sudo_password = password
        if enable_sudo:
            same, ok = QInputDialog.getItem(self, "sudo 密码", "sudo 密码是否与 Linux 登录密码相同？", ["相同", "不同"], 0, False)
            if not ok: return
            if same == "不同":
                sudo_password, ok = QInputDialog.getText(self, "sudo 密码", "请输入 sudo 密码（仅保留在内存）：", QLineEdit.Password)
                if not ok: return

        self.start_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.log_view.clear()
        self._log("开始初始化。首次连接会显示 SSH 主机指纹，请通过 VMware 控制台核对。")
        self.thread = QThread(self)
        self.worker = InitWorker(vm, password, enable_sudo, sudo_password,
                                 self.key_passphrase.text(), create_key=True,
                                 deploy_key=self.deploy_check.isChecked(),
                                 write_config=self.config_check.isChecked(),
                                 test_connection=self.test_check.isChecked())
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.log.connect(self._log)
        self.worker.progress.connect(self._on_progress)
        self.worker.host_key_request.connect(self._host_key_request)
        self.worker.conflict_request.connect(self._conflict_request)
        self.worker.finished.connect(self._finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _on_progress(self, name, status, message):
        self.statusBar().showMessage(f"{name}: {status} {message}")

    def _host_key_request(self, host, key_type, fingerprint, event, response):
        text = f"主机：{host}\n算法：{key_type}\n指纹：{fingerprint}\n\n请通过 VMware 控制台或可信渠道核对。是否信任？"
        response["value"] = QMessageBox.question(self, "首次 SSH 主机指纹确认", text,
                                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes
        event.set()

    def _conflict_request(self, alias, event, response):
        response["value"] = "update" if QMessageBox.question(self, "Host 已存在", f"Host {alias} 已存在，是否更新？",
                                                               QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes else "cancel"
        event.set()

    def _finished(self, report):
        self.start_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.password.clear()
        self.key_passphrase.clear()
        if report is None:
            QMessageBox.critical(self, "初始化失败", "任务未能生成报告，请检查日志。")
        elif report.success:
            self._log("\n初始化完成！以后可以执行：ssh " + report.config.host_alias)
            QMessageBox.information(self, "初始化完成", f"已完成 SSH 初始化。\n\nssh {report.config.host_alias}")
        else:
            QMessageBox.warning(self, "初始化未完全成功", "部分步骤失败或被跳过，请查看日志；程序不会虚报成功。")
        self._refresh_vms()
        self._refresh_keys()
        self.statusBar().showMessage("就绪")
        self.worker = None
        self.thread = None

    def _refresh_vms(self):
        rows = self.registry.all()
        self.vm_table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            key_name = Path(row.get("key_path", "")).name if row.get("key_path") else ""
            status = ("已配置" if row.get("status", "configured") == "configured" else "部分配置")
            status += " · sudo免密" if row.get("sudo_nopasswd") else ""
            values = [row.get("host_alias", ""), row.get("hostname", ""), row.get("username", ""),
                      str(row.get("port", 22)), key_name, status]
            for j, value in enumerate(values):
                self.vm_table.setItem(i, j, QTableWidgetItem(value))

    def _selected_vm_record(self):
        row = self.vm_table.currentRow()
        if row < 0:
            return None
        item = self.vm_table.item(row, 0)
        alias = item.text() if item else ""
        return next((record for record in self.registry.all() if record.get("host_alias") == alias), None)

    def _edit_local_host(self):
        record = self._selected_vm_record()
        if not record:
            QMessageBox.information(self, "提示", "请先选择一台 VM。")
            return
        self.editing_record = record
        self.host.setText(record.get("hostname", ""))
        self.username.setText(record.get("username", ""))
        self.port.setText(str(record.get("port", 22)))
        self.alias.setText(record.get("host_alias", ""))
        self.alias.setEnabled(False)
        self.notes.setText(record.get("notes", ""))
        key_path = record.get("key_path", "")
        if key_path:
            if self.key_combo.findData(key_path) < 0:
                self.key_combo.addItem(key_path, key_path)
            self.key_combo.setCurrentIndex(self.key_combo.findData(key_path))
        self.save_local_btn.setVisible(True)
        self.statusBar().showMessage("正在编辑本地配置；保存不会连接或修改 Linux VM。")

    def _save_local_host_edit(self):
        if not self.editing_record:
            return
        try:
            host = validate_host(self.host.text())
            username = validate_username(self.username.text())
            port = validate_port(self.port.text() or "22")
            alias = validate_alias(self.editing_record.get("host_alias", ""))
            key_data = self.key_combo.currentData()
            if not key_data:
                raise ValueError("请选择 SSH 私钥。")
            key_path = Path(key_data)
            if not key_path.exists() or not Path(str(key_path) + ".pub").exists():
                raise ValueError("私钥或对应公钥文件不存在。")
            self.keys.load_key(key_path, self.key_passphrase.text() or None)
            vm = VMConfig(host, username, alias, port, key_path, self.notes.text())
            self.config_manager.upsert(vm, on_conflict=lambda _alias: "update")
            self.registry.upsert(vm, bool(self.editing_record.get("sudo_nopasswd")),
                                 status=self.editing_record.get("status", "configured"))
            self._log(f"已保存 {alias} 的本地 SSH Config。服务器端未修改。")
            self.editing_record = None
            self.alias.setEnabled(True)
            self.save_local_btn.setVisible(False)
            self._refresh_vms()
            self.statusBar().showMessage("本地配置已更新")
        except Exception as exc:
            QMessageBox.warning(self, "保存失败", str(exc))

    def _revoke_server_key(self):
        record = self._selected_vm_record()
        if not record:
            QMessageBox.information(self, "提示", "请先选择一台 VM。")
            return
        key_path = record.get("key_path")
        if not key_path or not Path(key_path).exists():
            QMessageBox.warning(self, "密钥不可用", "登记的本地私钥不存在，无法确定要撤销的公钥。")
            return
        if QMessageBox.question(self, "确认撤销服务器公钥",
                                "将从服务器 authorized_keys 中删除与所选密钥完全匹配的条目。\n"
                                "服务器会保留备份；撤销后该密钥将无法再登录此 VM。继续？",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        password, ok = QInputDialog.getText(self, "Linux 登录密码", "请输入该 VM 的登录密码（仅用于本次连接）：", QLineEdit.Password)
        if not ok or not password:
            return
        self.start_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.thread = QThread(self)
        self.worker = RevokeWorker(record.get("hostname", ""), record.get("username", ""),
                                   int(record.get("port", 22)), password, Path(key_path),
                                   self.key_passphrase.text())
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.log.connect(self._log)
        self.worker.host_key_request.connect(self._host_key_request)
        self.worker.finished.connect(self._revoke_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _revoke_finished(self, removed, message):
        self.start_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.key_passphrase.clear()
        if removed:
            QMessageBox.information(self, "撤销完成", message)
        else:
            QMessageBox.warning(self, "未完成", message)
        self.worker = None
        self.thread = None
        self.statusBar().showMessage("就绪")

    def _delete_local_host(self):
        row = self.vm_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "提示", "请先选择一台 VM。")
            return
        alias_item = self.vm_table.item(row, 0)
        alias = alias_item.text() if alias_item else ""
        if QMessageBox.question(self, "删除本地配置", f"删除 {alias} 的 Windows SSH Host 配置？\n不会删除服务器上的公钥。",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        removed = self.config_manager.remove(alias)
        self.registry.remove(alias)
        if self.editing_record and self.editing_record.get("host_alias") == alias:
            self.editing_record = None
            self.alias.setEnabled(True)
            self.save_local_btn.setVisible(False)
        self._refresh_vms()
        self._log(f"已删除本地 Host {alias}。服务器公钥未改动。" if removed else f"已清理 {alias} 的登记记录；Config 中未找到对应 Host。")
