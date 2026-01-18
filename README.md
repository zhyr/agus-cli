# 拉取cli包
https://github.com/zhyr/agus-cli/releases
# 解压
tar -xzf agus-cli-0.1.6-macos-aarch64.tar.gz

# 进入目录
cd agus-cli-0.1.6-macos-aarch64

# 查看安装脚本
cat install_cli.sh

# 执行安装（可能需要管理员权限）
bash install_cli.sh

CLI安装成功！🎉

**正确的使用方式：**

```bash
# 查看版本
agus host --help

# 查看子命令帮助
agus exec --help

# 查看主机列表
agus host list

# 连接主机
agus host connect <host-id>

# 执行命令
agus exec <host-id> "uptime"

# 查看日志
agus logs <host-id>

# 查看监控
agus monitor <host-id>
```

**常用命令速查：**

| 功能 | 命令 |
|-----|------|
| 帮助 | `agus --help` 或 `agus <command> --help` |
| 主机管理 | `agus host list/connect/status` |
| 执行命令 | `agus exec <host-id> "命令"` |
| 查看日志 | `agus logs <host-id>` |
| 监控 | `agus monitor <host-id>` |
