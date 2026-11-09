# VM SSH Manager v1.0.0 — 构建与验收状态

## 当前工作区状态

| 项目 | 状态 | 说明 |
|---|---|---|
| CLI 源码 | 已完成 | 交互式菜单、密钥管理、VM 管理、本地 Host 删除、公钥撤销 |
| GUI 源码 | 已完成 | PySide6 桌面界面、后台线程、主机指纹确认、VM 管理 |
| 共享核心 | 已完成 | 密钥、SSH、SFTP 公钥部署、sudoers、SSH Config、报告 |
| 安全审查修正 | 已完成 | sudo 清缓存验证、Host/Match 顺序、远端文件所有权与符号链接检查 |
| 单元测试 | 29 项通过 | Linux 当前环境执行 `pytest -q` |
| Python 语法检查 | 已通过 | `python -m compileall -q src tests 04-Build` |
| CLI 源码 ZIP | 已生成并校验 | ZIP CRC 检查通过；仅含 CLI + 共享核心 |
| GUI 源码 ZIP | 已生成并校验 | ZIP CRC 检查通过；仅含 GUI + 共享核心 |
| 完整源码/构建 ZIP | 已生成并校验 | ZIP CRC 检查通过；未包含伪造 EXE |
| Paramiko 远程集成 | 未执行 | 当前容器未安装 Paramiko，且没有可用的 VMware Linux VM |
| Windows CLI EXE | 未构建 | 当前执行环境为 Linux，不伪造 EXE |
| Windows GUI EXE | 未构建 | 当前执行环境为 Linux，不伪造 EXE |
| Windows EXE 启动验收 | 未执行 | 需由 Windows x64 Runner 构建后 smoke test |

## Windows x64 构建

1. 使用 Windows 11 x64 + Python 3.12 x64。
2. 在项目根目录执行 `04-Build/build_cli.bat` 和 `04-Build/build_gui.bat`。
3. 或将项目推送到自己的 GitHub 仓库，手动运行 `.github/workflows/build-windows.yml`。
4. GitHub Actions 会运行测试、构建两个 EXE，并执行 CLI `--version` 与 GUI 启动 smoke test。
5. CI 验收通过后会生成 `VM-SSH-Manager-v1.0.0-Complete.zip` 及独立源码 ZIP。

**重要：** 当前工作区尚未包含经 Windows 构建和启动验证的 EXE。任何后续交付都必须以 Windows Runner 实际产物为准。
