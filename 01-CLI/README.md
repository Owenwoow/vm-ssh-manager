# VM SSH Manager CLI v1.0.0

Windows 11 x64 交互式命令行客户端。运行 `VM-SSH-CLI.exe`，按菜单操作即可。

- 首次连接会显示 SSH 主机指纹，务必通过 VMware 控制台或其他可信渠道核对后再确认。
- Linux 登录密码、sudo 密码和私钥口令仅在本次运行期间使用，不写入配置或日志。
- 默认复用 `%USERPROFILE%\.ssh\id_ed25519_vm`；不会覆盖已有密钥。
- `NOPASSWD: ALL` 会赋予该用户完整 root 能力，请只在自己的实验 VM 使用。

源码包：`VM-SSH-CLI-Source.zip`。构建方式见 `04-Build/build_cli.bat`。
