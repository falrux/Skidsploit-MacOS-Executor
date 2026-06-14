#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CHECK="${GREEN}✔${NC}"
CROSS="${RED}✖${NC}"
INFO="${CYAN}➜${NC}"
WARN="${YELLOW}⚠${NC}"

die()     { echo -e "${CROSS} $*"; exit 1; }
section() { echo; echo -e "${BOLD}${CYAN}==> $1${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DYLIB_PATH="$SCRIPT_DIR/build/skidsploit.dylib"
INSERT_DYLIB="$SCRIPT_DIR/in/insert_dylib"
DEPS="$SCRIPT_DIR/dependencies"

[[ "$(uname -m)" == "arm64" ]] || die "Apple Silicon (ARM64) required."

if [ -w "/Applications" ]; then
    APP_DIR="/Applications"
else
    APP_DIR="$HOME/Applications"
    mkdir -p "$APP_DIR"
    echo -e "${WARN} No write access to /Applications; using $APP_DIR"
fi

TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT

banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "   _____ __   _     ______       __      _ __ "
    echo "  / ___// /__(_)___/ / ___/____  / /___  (_) /_"
    echo "  \__ \/ //_/ / __  /\__ \/ __ \/ / __ \/ / __/"
    echo " ___/ / ,< / / /_/ /___/ / /_/ / / /_/ / / /_  "
    echo "/____/_/|_/_/\__,_//____/ .___/_/\____/_/\__/  "
    echo "                       /_/                     "
    echo -e "${NC}"
    echo -e "${BLUE}=[ SkidSploit (Apple Silicon) Installer ]=${NC}"
    echo ""
}

build_dylib() {
    section "Checking build tools"

    if ! xcode-select -p &>/dev/null; then
        echo -e "${INFO} Installing Xcode CLT..."
        xcode-select --install
        die "Rerun after Xcode CLT finishes installing."
    fi
    echo -e "${CHECK} Xcode CLT"

    if ! command -v cmake &>/dev/null; then
        command -v brew &>/dev/null || die "cmake not found. Install via: brew install cmake"
        echo -e "${INFO} Installing cmake via Homebrew..."
        brew install cmake
    fi
    echo -e "${CHECK} cmake $(cmake --version | head -1 | awk '{print $3}')"

    [[ -f "$DEPS/libs/libLuau.VM.a" ]]       || die "Missing: dependencies/libs/libLuau.VM.a"
    [[ -f "$DEPS/libs/libLuau.Compiler.a" ]] || die "Missing: dependencies/libs/libLuau.Compiler.a"
    [[ -f "$DEPS/tinyhook/libtinyhook.a" ]]  || die "Missing: dependencies/tinyhook/libtinyhook.a"
    [[ -f "$DEPS/luau/VM/include/lua.h" ]]   || die "Missing: dependencies/luau/VM/include/lua.h"
    echo -e "${CHECK} Dependencies present"

    section "Building skidsploit.dylib"
    rm -rf "$SCRIPT_DIR/build"
    mkdir "$SCRIPT_DIR/build"
    cd "$SCRIPT_DIR/build"
    cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -3 || die "cmake configuration failed"
    cmake --build . --target skidsploit -j"$(sysctl -n hw.ncpu)" 2>&1 | tail -5 || die "Build failed — check output above"
    [[ -f skidsploit.dylib ]] || die "Build failed — skidsploit.dylib not found"
    echo -e "${CHECK} Built: build/skidsploit.dylib"
    cd "$SCRIPT_DIR"
}

setup_insert_dylib() {
    section "Setting up insert_dylib"
    if [ ! -x "$INSERT_DYLIB" ]; then
        echo -e "${INFO} Building insert_dylib from source..."
        mkdir -p "$SCRIPT_DIR/in"
        cd /tmp
        rm -rf insert_dylib_src
        git clone --quiet https://github.com/tyilo/insert_dylib.git insert_dylib_src
        clang -o "$INSERT_DYLIB" insert_dylib_src/insert_dylib/main.c -framework Foundation
        rm -rf insert_dylib_src
        cd "$SCRIPT_DIR"
    fi
    echo -e "${CHECK} insert_dylib ready"
}

main() {
    banner

    section "Roblox Version"
    echo -e "${INFO} Choose:"
    echo -e "  ${BOLD}1${NC}) Latest (fetch from API)"
    echo -e "  ${BOLD}2${NC}) Custom version string"
    echo -e "  ${BOLD}3${NC}) Skip (keep current Roblox)"
    echo -n "Choice [1/2/3]: "
    read -r VCHOICE

    local version=""
    local do_install_roblox=true

    case "$VCHOICE" in
        1)
            echo -e "${INFO} Fetching latest version..."
            local json
            json=$(curl -s -L "https://clientsettings.roblox.com/v2/client-version/MacPlayer/channel/LIVE")
            version=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin)['clientVersionUpload'])" 2>/dev/null)
            local ver_str
            ver_str=$(echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin)['version'])" 2>/dev/null)
            echo -e "${CHECK} Latest: ${BOLD}${ver_str}${NC} (${version})"
            ;;
        2)
            echo -n "Enter version (e.g. version-08d2b9589bf14135): "
            read -r version
            ;;
        3)
            do_install_roblox=false
            echo -e "${INFO} Skipping Roblox install"
            ;;
        *) die "Invalid choice" ;;
    esac

    killall -9 RobloxPlayer 2>/dev/null || true

    if $do_install_roblox; then
        [ -n "$version" ] || die "No version provided"

        section "Removing old Roblox"
        for target in "$APP_DIR/Roblox.app" "$APP_DIR/RobloxPlayer.app"; do
            [ -e "$target" ] && rm -rf "$target" && echo -e "${CHECK} Removed $target"
        done

        section "Downloading Roblox ARM64 ($version)"
        local url="https://setup.rbxcdn.com/mac/arm64/$version-RobloxPlayer.zip"
        echo -e "${INFO} $url"
        curl -L --progress-bar "$url" -o "$TEMP/RobloxPlayer.zip"
        [ -s "$TEMP/RobloxPlayer.zip" ] || die "Download failed"

        echo -e "${INFO} Extracting..."
        unzip -oq "$TEMP/RobloxPlayer.zip" -d "$TEMP"

        local extracted_app
        extracted_app=$(find "$TEMP" -maxdepth 2 -name "*.app" -type d | head -1)
        [ -n "$extracted_app" ] || die "No .app found in zip"

        mv "$extracted_app" "$APP_DIR/Roblox.app"
        xattr -cr "$APP_DIR/Roblox.app"
        echo -e "${CHECK} Roblox installed ($(file "$APP_DIR/Roblox.app/Contents/MacOS/RobloxPlayer" | grep -o 'arm64\|x86_64' | head -1))"
    fi

    local ROBLOX_APP="" ROBLOX_BIN=""
    if   [ -f "$APP_DIR/RobloxPlayer.app/Contents/MacOS/RobloxPlayer" ]; then
        ROBLOX_APP="$APP_DIR/RobloxPlayer.app"
    elif [ -f "$APP_DIR/Roblox.app/Contents/MacOS/RobloxPlayer" ]; then
        ROBLOX_APP="$APP_DIR/Roblox.app"
    else
        die "Roblox not found in $APP_DIR"
    fi
    ROBLOX_BIN="$ROBLOX_APP/Contents/MacOS/RobloxPlayer"

    if [ ! -f "$DYLIB_PATH" ]; then
        build_dylib
    else
        echo -e "${CHECK} Using existing build/skidsploit.dylib (run with --rebuild to force)"
    fi
    [ -f "$DYLIB_PATH" ] || die "skidsploit.dylib missing after build"

    setup_insert_dylib

    section "Preparing Roblox binary"
    if [ ! -f "${ROBLOX_BIN}.backup" ]; then
        cp "$ROBLOX_BIN" "${ROBLOX_BIN}.backup"
        echo -e "${CHECK} Backup created"
    else
        cp "${ROBLOX_BIN}.backup" "$ROBLOX_BIN"
        echo -e "${CHECK} Restored clean binary from backup"
    fi

    section "Injecting SkidSploit"
    cp "$DYLIB_PATH" "$ROBLOX_APP/Contents/MacOS/skidsploit.dylib"
    "$INSERT_DYLIB" --strip-codesig --all-yes "@executable_path/skidsploit.dylib" "$ROBLOX_BIN" "$ROBLOX_BIN"

    otool -L "$ROBLOX_BIN" 2>/dev/null | grep -q "skidsploit" \
        || die "Injection failed — skidsploit not in load commands"
    echo -e "${CHECK} Injected and verified"

    section "Signing"
    xattr -cr "$ROBLOX_APP"
    codesign -f -s - --deep --preserve-metadata=entitlements "$ROBLOX_APP"
    xattr -cr "$ROBLOX_APP"
    echo -e "${CHECK} Signed"

    section "Disabling auto-updater"
    rm -rf "$ROBLOX_APP/Contents/MacOS/RobloxPlayerInstaller.app" 2>/dev/null || true
    defaults write com.Roblox.RobloxPlayer AppUpdateStatus -string "NotAvailable" 2>/dev/null || true
    echo -e "${CHECK} Auto-updater disabled"

    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
        -f "$ROBLOX_APP" 2>/dev/null || true
    echo -e "${CHECK} Registered roblox-player:// URL scheme"

    mkdir -p ~/Documents/SkidSploit/workspace

    echo
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  SkidSploit — Installation complete!${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${WARN}  Use an alt account."
    echo -e "${INFO}  Join a game, then run: python3 client.py"
    echo -e "${INFO}  Log: ~/Documents/SkidSploit/skidsploit.log"
    echo

    echo -e "${INFO} Launching Roblox..."
    "$ROBLOX_APP/Contents/MacOS/RobloxPlayer" &
}

[[ "${1:-}" == "--rebuild" ]] && rm -f "$DYLIB_PATH"

main
