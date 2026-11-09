# VM SSH Manager v1.0.0

Windows 11 x64 本地 Linux VM SSH 自动化初始化工具，提供 CLI 和 GUI 两个独立入口，共享同一套核心业务逻辑。

## 快速开始

- 如果交付目录中已有 `01-CLI/VM-SSH-CLI.exe` 和 `02-GUI/VM-SSH-GUI.exe`，可直接运行，无需单独安装 Python。
- 如果当前包尚未包含 Windows EXE，请查看 `BUILD_STATUS.md`，并在 Windows 11 x64 环境运行 `04-Build/build_cli.bat`、`04-Build/build_gui.bat`，或使用 `.github/workflows/build-windows.yml` 的 Windows Runner 构建。
- 用户手册、安全说明和技术架构见 `03-Documentation/`。

## 安全提醒

- 私钥始终保留在 Windows；只有公钥会上传到 Linux。
- Linux 登录密码、sudo 密码和私钥口令不写入配置文件或日志。
- 首次连接必须通过 VMware 控制台或可信渠道核对 SSH 主机指纹。
- `NOPASSWD: ALL` 会让目标用户无需密码取得完整 root 权限，只建议用于自己的实验虚拟机。
- 删除 Windows SSH Host 配置不会撤销服务器公钥；撤销公钥需要单独执行。

## 目录

- `01-CLI/`：CLI 使用说明、Windows EXE（构建后）和 CLI 源码 ZIP
- `02-GUI/`：GUI 使用说明、Windows EXE（构建后）和 GUI 源码 ZIP
- `03-Documentation/`：中文用户手册、架构、配置和安全说明
- `04-Build/`：Windows 构建脚本和交付打包脚本
- `src/`：共享核心、CLI、GUI 源码
- `tests/`：单元测试
- `.github/workflows/`：Windows x64 CI 构建与启动 smoke test

## 开发环境

Python 3.11+。完整依赖安装：

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r 04-Build\requirements.txt
python -m pytest -q
```

构建两个 EXE：

```powershell
cmd /c 04-Build\build_cli.bat
cmd /c 04-Build\build_gui.bat
python 04-Build\package_release.py
```

最终构建和验收状态以 `BUILD_STATUS.md` 与各客户端目录下的 `WINDOWS_EXE_STATUS.md` 为准。
