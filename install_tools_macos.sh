#!/bin/bash

echo "[+] Checking and installing missing tools..."

# Hàm kiểm tra và cài đặt công cụ nếu chưa có
install_if_missing() {
    if ! command -v "$1" &> /dev/null; then
        echo "[+] Installing $1..."
        brew install "$2"
    else
        echo "[✓] $1 already installed."
    fi
}

# Cập nhật Homebrew
brew update

# Kiểm tra và cài đặt từng công cụ
install_if_missing "curl" "curl"
install_if_missing "jq" "jq"
install_if_missing "subfinder" "subfinder"
install_if_missing "assetfinder" "assetfinder"
install_if_missing "naabu" "naabu"
install_if_missing "nmap" "nmap"
install_if_missing "httpx" "projectdiscovery/httpx"
install_if_missing "ffuf" "ffuf"

echo "[+] All necessary tools are installed!"
