# VM SSH Manager GUI v1.0.0

Windows 11 x64 桌面客户端，基于 PySide6。运行 `VM-SSH-GUI.exe`，在界面填写 Linux VM 连接信息并启动初始化。

- 首次连接会弹出 SSH 主机指纹确认窗口。
- 密码字段使用密码模式，任务结束后清空；密码不写入本地 VM 登记文件。
- GUI 任务运行于后台线程，不会因 SSH 连接阻塞主窗口。
- 支持编辑/删除本地 Host 配置；本地编辑不会连接或修改 Linux VM。删除 VM 记录只删除 Windows 本地 Host 配置，不会撤销服务器公钥。
- 支持对所选 VM 撤销对应公钥；需要输入该 VM 的 Linux 登录密码，服务器端会保留 `authorized_keys` 备份。

源码包：`VM-SSH-GUI-Source.zip`。构建方式见 `04-Build/build_gui.bat`。
