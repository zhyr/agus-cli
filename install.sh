#!/bin/bash
# agus-cli 安装脚本

set -e

VERSION="${1:-0.1.3}"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64) ARCH_TAG="aarch64" ;;
  x86_64) ARCH_TAG="x86_64" ;;
  *) ARCH_TAG="$ARCH" ;;
esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
FILENAME="agus-cli-${VERSION}-macos-${ARCH_TAG}.tar.gz"
URL="https://github.com/zhyr/agus-cli/releases/download/v${VERSION}/${FILENAME}"

echo "Downloading agus-cli ${VERSION} for macOS ${ARCH_TAG}..."
curl -fSL "$URL" -o "$FILENAME"
tar -xzf "$FILENAME"
cd "agus-cli-${VERSION}-macos-${ARCH_TAG}"

echo "Installing to /usr/local/bin..."
sudo mv bin/agus /usr/local/bin/
sudo mv bin/asda /usr/local/bin/
sudo chmod +x /usr/local/bin/agus /usr/local/bin/asda

echo "Cleaning up..."
rm -rf "$FILENAME"

echo "✅ agus-cli installed successfully!"
agus --version
