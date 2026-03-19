#!/bin/sh
set -eu

# --- Global Configurations ---
REPO="${REPO:-telemt/telemt}"
BIN_NAME="${BIN_NAME:-telemt}"
INSTALL_DIR="${INSTALL_DIR:-/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/telemt}"
CONFIG_FILE="${CONFIG_FILE:-${CONFIG_DIR}/telemt.toml}"
WORK_DIR="${WORK_DIR:-/opt/telemt}"
SERVICE_NAME="telemt"
TEMP_DIR=""
SUDO=""

# --- Argument Parsing ---
ACTION="install"
TARGET_VERSION="${VERSION:-latest}"

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            ACTION="help"
            shift
            ;;
        uninstall|--uninstall)
            [ "$ACTION" != "purge" ] && ACTION="uninstall"
            shift
            ;;
        --purge)
            ACTION="purge"
            shift
            ;;
        install|--install)
            ACTION="install"
            shift
            ;;
        -*)
            printf '[ERROR] Unknown option: %s\n' "$1" >&2
            exit 1
            ;;
        *)
            if [ "$ACTION" = "install" ]; then
                TARGET_VERSION="$1"
            fi
            shift
            ;;
    esac
done

# --- Core Functions ---
say() { printf '[INFO] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

cleanup() {
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf -- "$TEMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

show_help() {
    say "Usage: $0 [version | install | uninstall | --purge | --help]"
    say "  version      Install specific version (e.g. 1.0.0, default: latest)"
    say "  uninstall    Remove the binary and service (keeps config)"
    say "  --purge      Remove everything including configuration"
    exit 0
}

user_exists() {
    if command -v getent >/dev/null 2>&1; then
        getent passwd "$1" >/dev/null 2>&1
    else
        grep -q "^${1}:" /etc/passwd 2>/dev/null
    fi
}

group_exists() {
    if command -v getent >/dev/null 2>&1; then
        getent group "$1" >/dev/null 2>&1
    else
        grep -q "^${1}:" /etc/group 2>/dev/null
    fi
}

verify_common() {
    [ -z "$BIN_NAME" ] && die "BIN_NAME cannot be empty."
    [ -z "$INSTALL_DIR" ] && die "INSTALL_DIR cannot be empty."
    [ -z "$CONFIG_DIR" ] && die "CONFIG_DIR cannot be empty."

    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    else
        if ! command -v sudo >/dev/null 2>&1; then
            die "This script requires root or sudo. Neither found."
        fi
        SUDO="sudo"
        say "sudo is available. Caching credentials..."
        if ! sudo -v; then
            die "Failed to cache sudo credentials"
        fi
    fi

    case "${INSTALL_DIR}${CONFIG_DIR}${WORK_DIR}" in
        *[!a-zA-Z0-9_./-]*)
            die "Invalid characters in path variables. Only alphanumeric, _, ., -, and / are allowed."
            ;;
    esac

    case "$BIN_NAME" in
        *[!a-zA-Z0-9_-]*) die "Invalid characters in BIN_NAME: $BIN_NAME" ;;
    esac

    for path in "$CONFIG_DIR" "$WORK_DIR"; do
        check_path="$path"

        while [ "$check_path" != "/" ] && [ "${check_path%"/"}" != "$check_path" ]; do
            check_path="${check_path%"/"}"
        done
        [ -z "$check_path" ] && check_path="/"

        case "$check_path" in
            /|/bin|/sbin|/usr|/usr/bin|/usr/local|/etc|/opt|/var|/home|/root|/tmp)
                die "Safety check failed: '$path' is a critical system directory."
                ;;
        esac
    done

    for cmd in uname grep find rm chown chmod mv head mktemp; do
        command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
    done
}

verify_install_deps() {
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        die "Neither curl nor wget is installed."
    fi
    command -v tar >/dev/null 2>&1 || die "Required command not found: tar"
    command -v gzip >/dev/null 2>&1 || die "Required command not found: gzip"
    command -v cp >/dev/null 2>&1 || command -v install >/dev/null 2>&1 || die "Need cp or install"

    if ! command -v setcap >/dev/null 2>&1; then
        say "setcap is missing. Installing required capability tools..."
        if command -v apk >/dev/null 2>&1; then
            $SUDO apk add --no-cache libcap || die "Failed to install libcap"
        elif command -v apt-get >/dev/null 2>&1; then
            $SUDO apt-get update -qq && $SUDO apt-get install -y -qq libcap2-bin || die "Failed to install libcap2-bin"
        elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
            $SUDO ${YUM_CMD:-yum} install -y -q libcap || die "Failed to install libcap"
        else
            die "Cannot install 'setcap'. Package manager not found. Please install libcap manually."
        fi
    fi
}

detect_arch() {
    sys_arch="$(uname -m)"
    case "$sys_arch" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) die "Unsupported architecture: $sys_arch" ;;
    esac
}

detect_libc() {
    if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
        echo "musl"; return 0
    fi

    if grep -q '^ID=alpine' /etc/os-release 2>/dev/null || grep -q '^ID="alpine"' /etc/os-release 2>/dev/null; then
        echo "musl"; return 0
    fi
    for f in /lib/ld-musl-*.so.* /lib64/ld-musl-*.so.*; do
        if [ -e "$f" ]; then
            echo "musl"; return 0
        fi
    done
    echo "gnu"
}

fetch_file() {
    fetch_url="$1"
    fetch_out="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$fetch_url" -o "$fetch_out" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$fetch_out" "$fetch_url" || return 1
    else
        die "curl or wget required"
    fi
}

ensure_user_group() {
    nologin_bin="/bin/false"

    cmd_nologin="$(command -v nologin 2>/dev/null || true)"
    if [ -n "$cmd_nologin" ] && [ -x "$cmd_nologin" ]; then
        nologin_bin="$cmd_nologin"
    else
        for bin in /sbin/nologin /usr/sbin/nologin; do
            if [ -x "$bin" ]; then
                nologin_bin="$bin"
                break
            fi
        done
    fi

    if ! group_exists telemt; then
        if command -v groupadd >/dev/null 2>&1; then
            $SUDO groupadd -r telemt || die "Failed to create group via groupadd"
        elif command -v addgroup >/dev/null 2>&1; then
            $SUDO addgroup -S telemt || die "Failed to create group via addgroup"
        else
            die "Cannot create group: neither groupadd nor addgroup found"
        fi
    fi

    if ! user_exists telemt; then
        if command -v useradd >/dev/null 2>&1; then
            $SUDO useradd -r -g telemt -d "$WORK_DIR" -s "$nologin_bin" -c "Telemt Proxy" telemt || die "Failed to create user via useradd"
        elif command -v adduser >/dev/null 2>&1; then
            $SUDO adduser -S -D -H -h "$WORK_DIR" -s "$nologin_bin" -G telemt telemt || die "Failed to create user via adduser"
        else
            die "Cannot create user: neither useradd nor adduser found"
        fi
    fi
}

setup_dirs() {
    say "Setting up directories..."
    $SUDO mkdir -p "$WORK_DIR" "$CONFIG_DIR" || die "Failed to create directories"
    $SUDO chown telemt:telemt "$WORK_DIR" || die "Failed to set owner on WORK_DIR"
    $SUDO chmod 750 "$WORK_DIR" || die "Failed to set permissions on WORK_DIR"
}

stop_service() {
    say "Stopping service if running..."
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        $SUDO systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        $SUDO rc-service "$SERVICE_NAME" stop 2>/dev/null || true
    fi
}

install_binary() {
    bin_src="$1"
    bin_dst="$2"

    $SUDO mkdir -p "$INSTALL_DIR" || die "Failed to create install directory"
    if command -v install >/dev/null 2>&1; then
        $SUDO install -m 0755 "$bin_src" "$bin_dst" || die "Failed to install binary"
    else
        $SUDO rm -f "$bin_dst"
        $SUDO cp "$bin_src" "$bin_dst" || die "Failed to copy binary"
        $SUDO chmod 0755 "$bin_dst" || die "Failed to set permissions"
    fi

    if [ ! -x "$bin_dst" ]; then
        die "Failed to install binary or it is not executable: $bin_dst"
    fi

    say "Granting network bind capabilities to bind port 443..."
    if ! $SUDO setcap cap_net_bind_service=+ep "$bin_dst" 2>/dev/null; then
        say "[WARNING] Failed to apply setcap. The service will NOT be able to open port 443!"
        say "[WARNING] This usually happens inside unprivileged Docker/LXC containers."
    fi
}

generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        secret="$(openssl rand -hex 16 2>/dev/null)" && [ -n "$secret" ] && { echo "$secret"; return 0; }
    fi
    if command -v xxd >/dev/null 2>&1; then
        secret="$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | xxd -p | tr -d '\n')" && [ -n "$secret" ] && { echo "$secret"; return 0; }
    fi
    secret="$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | od -An -tx1 | tr -d ' \n')" && [ -n "$secret" ] && { echo "$secret"; return 0; }
    return 1
}

generate_config_content() {
    cat <<EOF
[general]
use_middle_proxy = false

[general.modes]
classic = false
secure = false
tls = true

[server]
port = 443

[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.1/32"]

[censorship]
tls_domain = "petrovich.ru"

[access.users]
hello = "$1"
EOF
}

install_config() {
    config_exists=0

    if [ -n "$SUDO" ]; then
        $SUDO sh -c "[ -f '$CONFIG_FILE' ]" 2>/dev/null && config_exists=1 || true
    else
        [ -f "$CONFIG_FILE" ] && config_exists=1 || true
    fi

    if [ "$config_exists" -eq 1 ]; then
        say "Config already exists, skipping generation."
        return 0
    fi

    toml_secret="$(generate_secret)" || die "Failed to generate secret"
    say "Creating config at $CONFIG_FILE..."

    tmp_conf="$(mktemp "${TEMP_DIR:-/tmp}/telemt_conf.XXXXXX")" || die "Failed to create temp config"
    generate_config_content "$toml_secret" > "$tmp_conf" || die "Failed to write temp config"

    $SUDO mv "$tmp_conf" "$CONFIG_FILE" || die "Failed to install config file"
    $SUDO chown root:telemt "$CONFIG_FILE" || die "Failed to set owner"
    $SUDO chmod 640 "$CONFIG_FILE" || die "Failed to set config permissions"

    say "Secret for user 'hello': $toml_secret"
}

generate_systemd_content() {
    cat <<EOF
[Unit]
Description=Telemt Proxy Service
After=network-online.target

[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=$WORK_DIR
ExecStart=${INSTALL_DIR}/${BIN_NAME} ${CONFIG_FILE}
Restart=on-failure
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
}

generate_openrc_content() {
    cat <<EOF
#!/sbin/openrc-run
name="$SERVICE_NAME"
description="Telemt Proxy Service"
command="${INSTALL_DIR}/${BIN_NAME}"
command_args="${CONFIG_FILE}"
command_background=true
command_user="telemt:telemt"
pidfile="/run/\${RC_SVCNAME}.pid"
directory="${WORK_DIR}"
rc_ulimit="-n 65536"
depend() { need net; use logger; }
EOF
}

install_service() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        say "Installing systemd service..."
        tmp_svc="$(mktemp "${TEMP_DIR:-/tmp}/${SERVICE_NAME}.service.XXXXXX")" || die "Failed to create temp service"
        generate_systemd_content > "$tmp_svc" || die "Failed to generate service content"

        $SUDO mv "$tmp_svc" "/etc/systemd/system/${SERVICE_NAME}.service" || die "Failed to move service file"
        $SUDO chown root:root "/etc/systemd/system/${SERVICE_NAME}.service"
        $SUDO chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"

        $SUDO systemctl daemon-reload || die "Failed to reload systemd"
        $SUDO systemctl enable "$SERVICE_NAME" || die "Failed to enable service"
        $SUDO systemctl start "$SERVICE_NAME" || die "Failed to start service"

    elif command -v rc-update >/dev/null 2>&1; then
        say "Installing OpenRC service..."
        tmp_svc="$(mktemp "${TEMP_DIR:-/tmp}/${SERVICE_NAME}.init.XXXXXX")" || die "Failed to create temp file"
        generate_openrc_content > "$tmp_svc" || die "Failed to generate init content"

        $SUDO mv "$tmp_svc" "/etc/init.d/${SERVICE_NAME}" || die "Failed to move service file"
        $SUDO chown root:root "/etc/init.d/${SERVICE_NAME}"
        $SUDO chmod 0755 "/etc/init.d/${SERVICE_NAME}"

        $SUDO rc-update add "$SERVICE_NAME" default 2>/dev/null || die "Failed to register service"
        $SUDO rc-service "$SERVICE_NAME" start 2>/dev/null || die "Failed to start OpenRC service"
    else
        say "No service manager found. You can start it manually with:"
        if [ -n "$SUDO" ]; then
            say "  sudo -u telemt ${INSTALL_DIR}/${BIN_NAME} ${CONFIG_FILE}"
        else
            say "  su -s /bin/sh telemt -c '${INSTALL_DIR}/${BIN_NAME} ${CONFIG_FILE}'"
        fi
    fi
}

kill_user_procs() {
    say "Ensuring $BIN_NAME processes are killed..."

    if pkill_cmd="$(command -v pkill 2>/dev/null)"; then
        $SUDO "$pkill_cmd" -u telemt "$BIN_NAME" 2>/dev/null || true
        sleep 1
        $SUDO "$pkill_cmd" -9 -u telemt "$BIN_NAME" 2>/dev/null || true
    elif killall_cmd="$(command -v killall 2>/dev/null)"; then
        $SUDO "$killall_cmd" "$BIN_NAME" 2>/dev/null || true
        sleep 1
        $SUDO "$killall_cmd" -9 "$BIN_NAME" 2>/dev/null || true
    fi
}

uninstall() {
    purge_data=0
    [ "$ACTION" = "purge" ] && purge_data=1

    say "Uninstalling $BIN_NAME..."
    stop_service

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        $SUDO systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        $SUDO rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        $SUDO systemctl daemon-reload || true
    elif command -v rc-update >/dev/null 2>&1; then
        $SUDO rc-update del "$SERVICE_NAME" 2>/dev/null || true
        $SUDO rm -f "/etc/init.d/${SERVICE_NAME}"
    fi

    kill_user_procs

    $SUDO rm -f "${INSTALL_DIR}/${BIN_NAME}"

    $SUDO userdel telemt 2>/dev/null || $SUDO deluser telemt 2>/dev/null || true
    $SUDO groupdel telemt 2>/dev/null || $SUDO delgroup telemt 2>/dev/null || true

    if [ "$purge_data" -eq 1 ]; then
        say "Purging configuration and data..."
        $SUDO rm -rf "$CONFIG_DIR" "$WORK_DIR"
    else
        say "Note: Configuration in $CONFIG_DIR was kept. Run with '--purge' to remove it."
    fi

    say "Uninstallation complete."
    exit 0
}

# ============================================================================
# Main Entry Point
# ============================================================================

case "$ACTION" in
    help)
        show_help
        ;;
    uninstall|purge)
        verify_common
        uninstall
        ;;
    install)
        say "Starting installation..."
        verify_common
        verify_install_deps

        ARCH="$(detect_arch)"
        LIBC="$(detect_libc)"
        say "Detected system: $ARCH-linux-$LIBC"

        FILE_NAME="${BIN_NAME}-${ARCH}-linux-${LIBC}.tar.gz"
        FILE_NAME="$(printf '%s' "$FILE_NAME" | tr -d ' \t\n\r')"

        if [ "$TARGET_VERSION" = "latest" ]; then
            DL_URL="https://github.com/${REPO}/releases/latest/download/${FILE_NAME}"
        else
            DL_URL="https://github.com/${REPO}/releases/download/${TARGET_VERSION}/${FILE_NAME}"
        fi

        TEMP_DIR="$(mktemp -d)" || die "Failed to create temp directory"
        if [ -z "$TEMP_DIR" ] || [ ! -d "$TEMP_DIR" ]; then
            die "Temp directory creation failed"
        fi

        say "Downloading from $DL_URL..."
        fetch_file "$DL_URL" "${TEMP_DIR}/archive.tar.gz" || die "Download failed (check version or network)"

        gzip -dc "${TEMP_DIR}/archive.tar.gz" | tar -xf - -C "$TEMP_DIR" || die "Extraction failed"

        EXTRACTED_BIN="$(find "$TEMP_DIR" -type f -name "$BIN_NAME" -print 2>/dev/null | head -n 1)"
        [ -z "$EXTRACTED_BIN" ] && die "Binary '$BIN_NAME' not found in archive"

        ensure_user_group
        setup_dirs
        stop_service

        say "Installing binary..."
        install_binary "$EXTRACTED_BIN" "${INSTALL_DIR}/${BIN_NAME}"

        install_config
        install_service

        say ""
        say "============================================="
        say "Installation complete!"
        say "============================================="
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            say "To check the logs, run:"
            say "  journalctl -u $SERVICE_NAME -f"
            say ""
        fi
        say "To get user connection links, run:"
        if command -v jq >/dev/null 2>&1; then
            say "  curl -s http://127.0.0.1:9091/v1/users | jq -r '.data[] | \"User: \\(.username)\\n\\(.links.tls[0] // empty)\"'"
        else
            say "  curl -s http://127.0.0.1:9091/v1/users"
            say "  (Note: Install 'jq' package to see the links nicely formatted)"
        fi
        ;;
esac
