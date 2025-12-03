#!/bin/sh
set -e

# otoroshictl installer
# Usage: curl -fsSL https://raw.githubusercontent.com/cloud-apim/otoroshictl/main/install.sh | sh

REPO="cloud-apim/otoroshictl"
BINARY_NAME="otoroshictl"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

step() { printf "${CYAN}> %s${NC}" "$1"; }
ok() { printf " ${GREEN}OK${NC}\n"; }
result() { printf " ${GREEN}%s${NC}\n" "$1"; }

err() {
    printf " ${RED}FAILED${NC}\n"
    printf "${RED}error: %s${NC}\n" "$1" >&2
    exit 1
}

check_cmd() { command -v "$1" >/dev/null 2>&1; }

get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

detect_platform() {
    OS=$(uname -s)
    ARCH=$(uname -m)

    case "$OS" in
        Darwin)
            case "$ARCH" in
                x86_64) PLATFORM="darwin-amd64" ;;
                arm64|aarch64) PLATFORM="darwin-arm64" ;;
                *) err "Unsupported architecture: $ARCH" ;;
            esac
            ;;
        Linux)
            case "$ARCH" in
                x86_64) PLATFORM="linux-amd64" ;;
                aarch64) PLATFORM="linux-arm64" ;;
                *) err "Unsupported architecture: $ARCH" ;;
            esac
            ;;
        *) err "Unsupported OS: $OS (use install.ps1 for Windows)" ;;
    esac
}

verify_sha256() {
    if check_cmd shasum; then
        ACTUAL=$(shasum -a 256 "$1" | cut -d ' ' -f 1)
    elif check_cmd sha256sum; then
        ACTUAL=$(sha256sum "$1" | cut -d ' ' -f 1)
    else
        err "Neither shasum nor sha256sum found"
    fi

    if [ "$ACTUAL" != "$2" ]; then
        rm -f "$1"
        err "SHA256 mismatch!\n  Expected: $2\n  Got: $ACTUAL"
    fi
}

# Parse arguments
VERSION=""
while [ $# -gt 0 ]; do
    case "$1" in
        -v|--version) VERSION="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: install.sh [-v|--version VERSION]"
            echo "Options:"
            echo "  -v, --version    Install a specific version (default: latest)"
            echo "  -h, --help       Show this help message"
            exit 0
            ;;
        *) err "Unknown option: $1" ;;
    esac
done

# Header
printf "\n${BOLD}otoroshictl installer${NC}\n\n"

# Check dependencies
check_cmd curl || err "curl is required"

# Detect platform
step "Detecting platform..."
detect_platform
result "$PLATFORM"

# Get version
if [ -z "$VERSION" ]; then
    step "Fetching latest version..."
    VERSION=$(get_latest_version)
    result "$VERSION"
fi

# Set install directory
INSTALL_DIR="${OTOROSHICTL_INSTALL:-/usr/local/bin}"
mkdir -p "$INSTALL_DIR"
DEST="$INSTALL_DIR/$BINARY_NAME"

# URLs
BINARY_FILE="${BINARY_NAME}-${PLATFORM}"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

# Get expected checksum
step "Fetching checksum..."
EXPECTED_SHA256=$(curl -fsSL "${BASE_URL}/${BINARY_FILE}.sha256")
ok

# Download and install binary
step "Downloading ${BINARY_NAME} ${VERSION}..."
curl -fsSL "${BASE_URL}/${BINARY_FILE}" -o "$DEST" && chmod +x "$DEST"
ok

# Verify SHA256
step "Verifying checksum..."
verify_sha256 "$DEST" "$EXPECTED_SHA256"
ok

# Success
printf "\n${GREEN}${BOLD}otoroshictl ${VERSION} installed successfully!${NC}\n"

# PATH hint
if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    printf "\n${CYAN}Add to your PATH:${NC}\n"
    printf "  export PATH=\"%s:\$PATH\"\n" "$INSTALL_DIR"
fi

printf "\n${CYAN}Get started:${NC}\n"
printf "  otoroshictl --help\n\n"
