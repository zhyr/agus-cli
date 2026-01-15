# agus-cli
# 方式一：直接下载
curl -L https://github.com/zhyr/agus-cli/releases/download/v0.1.3/agus-cli-0.1.3-macos-aarch64.tar.gz | tar -xz
sudo mv agus-cli-*/bin/agus /usr/local/bin/
sudo mv agus-cli-*/bin/asda /usr/local/bin/

# 方式二（未来）：一键安装
curl -sL https://raw.githubusercontent.com/zhyr/agus-cli/main/install.sh | bash -s 0.1.3
