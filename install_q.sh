#!/usr/bin/env bash
set -euo pipefail

MODE="user"
BIN_DIR=""
COPY_SETTINGS=0
WITH_VENV=0
SETTINGS_SRC="Settings.json"
SETTINGS_MODE="0600"
SETTINGS_GROUP=""
SHARED_VENV="/usr/local/lib/basic_scan/q-venv"
VENV_DIR=""
PYTHON_FOR_VENV="${PYTHON_BIN:-}"

usage() {
  cat <<'USAGE'
Usage:
  ./install_q.sh [--user] [--with-venv]
  sudo ./install_q.sh --global [--with-venv]
  ./install_q.sh --bin-dir /shared/bin [--with-venv]
  ./install_q.sh --user --copy-settings --settings ./Settings.json

Options:
  --user                  Install q to ~/.local/bin/q. Default. No sudo required.
  --global, --system      Install q to /usr/local/bin/q. Requires root/sudo.
  --bin-dir DIR           Install q to a custom directory.
  --with-venv, --install-deps
                          Create a Python venv and install mysql-connector-python.
                          User mode: ~/.local/share/basic_scan/q-venv.
                          Global mode: /usr/local/lib/basic_scan/q-venv.
  --venv-dir DIR          Custom venv path for --with-venv.
  --python PATH           Python interpreter used to create the venv. Default: python3.12 then python3.
  --copy-settings         Copy Settings.json to the matching config directory.
  --settings PATH         Source Settings.json for --copy-settings. Default: ./Settings.json.
  --settings-group GROUP  chgrp copied Settings.json to GROUP. Useful for shared access.
  --settings-mode MODE    chmod copied Settings.json. Default: 0600. Use 0640 with --settings-group.
  -h, --help              Show this help.

Examples:
  # Current user, no sudo. Installs q and Python dependency into the user's home.
  ./install_q.sh --user --with-venv

  # Global q and shared Python dependency for all users. Requires sudo once.
  sudo ./install_q.sh --global --with-venv

  # Shared Settings.json for selected users:
  sudo groupadd -f basic_scan
  sudo usermod -aG basic_scan alice
  sudo ./install_q.sh --global --with-venv --copy-settings --settings ./Settings.json \
    --settings-group basic_scan --settings-mode 0640
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      MODE="user"
      shift
      ;;
    --global|--system)
      MODE="global"
      shift
      ;;
    --bin-dir)
      BIN_DIR="${2:-}"
      if [[ -z "$BIN_DIR" ]]; then
        echo "--bin-dir requires a path" >&2
        exit 2
      fi
      MODE="custom"
      shift 2
      ;;
    --with-venv|--install-deps)
      WITH_VENV=1
      shift
      ;;
    --venv-dir)
      VENV_DIR="${2:-}"
      if [[ -z "$VENV_DIR" ]]; then
        echo "--venv-dir requires a path" >&2
        exit 2
      fi
      shift 2
      ;;
    --python)
      PYTHON_FOR_VENV="${2:-}"
      if [[ -z "$PYTHON_FOR_VENV" ]]; then
        echo "--python requires a path" >&2
        exit 2
      fi
      shift 2
      ;;
    --copy-settings)
      COPY_SETTINGS=1
      shift
      ;;
    --settings)
      SETTINGS_SRC="${2:-}"
      if [[ -z "$SETTINGS_SRC" ]]; then
        echo "--settings requires a path" >&2
        exit 2
      fi
      shift 2
      ;;
    --settings-group)
      SETTINGS_GROUP="${2:-}"
      if [[ -z "$SETTINGS_GROUP" ]]; then
        echo "--settings-group requires a group" >&2
        exit 2
      fi
      shift 2
      ;;
    --settings-mode)
      SETTINGS_MODE="${2:-}"
      if [[ -z "$SETTINGS_MODE" ]]; then
        echo "--settings-mode requires a chmod mode" >&2
        exit 2
      fi
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Q_SRC="$SCRIPT_DIR/q"
if [[ ! -f "$Q_SRC" ]]; then
  echo "Cannot find q in $SCRIPT_DIR" >&2
  exit 2
fi

case "$MODE" in
  user)
    BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
    CONFIG_DIR="$HOME/.config/basic_scan"
    VENV_DIR="${VENV_DIR:-$HOME/.local/share/basic_scan/q-venv}"
    ;;
  global)
    BIN_DIR="${BIN_DIR:-/usr/local/bin}"
    CONFIG_DIR="/usr/local/etc/basic_scan"
    VENV_DIR="${VENV_DIR:-$SHARED_VENV}"
    ;;
  custom)
    CONFIG_DIR="${CHECK_HOSTNAME_CONFIG_DIR:-$HOME/.config/basic_scan}"
    VENV_DIR="${VENV_DIR:-$HOME/.local/share/basic_scan/q-venv}"
    ;;
  *)
    echo "Invalid mode: $MODE" >&2
    exit 2
    ;;
esac

find_python_for_venv() {
  if [[ -n "$PYTHON_FOR_VENV" ]]; then
    printf '%s\n' "$PYTHON_FOR_VENV"
  elif command -v python3.12 >/dev/null 2>&1; then
    command -v python3.12
  elif command -v python3 >/dev/null 2>&1; then
    command -v python3
  else
    return 1
  fi
}

install_mysql_connector_venv() {
  local venv_dir="$1"
  local py="$2"
  mkdir -p "$(dirname "$venv_dir")"
  if [[ ! -x "$venv_dir/bin/python3" ]]; then
    echo "Creating Python venv: $venv_dir"
    "$py" -m venv "$venv_dir" || {
      cat >&2 <<EOF
Failed to create Python venv with:
  $py -m venv $venv_dir

On Ubuntu/Debian, ask an admin to install the venv package once, for example:
  sudo apt-get install python3.12-venv
EOF
      exit 2
    }
  fi
  echo "Installing mysql-connector-python into: $venv_dir"
  "$venv_dir/bin/python3" -m pip install --upgrade pip >/dev/null 2>&1 || true
  "$venv_dir/bin/python3" -m pip install mysql-connector-python
  chmod -R a+rX "$venv_dir" 2>/dev/null || true
}

mkdir -p "$BIN_DIR"
install -m 0755 "$Q_SRC" "$BIN_DIR/q"

if [[ "$WITH_VENV" -eq 1 ]]; then
  PY_FOR_VENV="$(find_python_for_venv)" || {
    echo "Cannot find python3.12 or python3 for venv creation. Use --python /path/to/python." >&2
    exit 2
  }
  install_mysql_connector_venv "$VENV_DIR" "$PY_FOR_VENV"
fi

if [[ "$COPY_SETTINGS" -eq 1 ]]; then
  if [[ ! -r "$SETTINGS_SRC" ]]; then
    echo "Cannot read settings file: $SETTINGS_SRC" >&2
    exit 2
  fi
  mkdir -p "$CONFIG_DIR"
  install -m 0600 "$SETTINGS_SRC" "$CONFIG_DIR/Settings.json"
  if [[ -n "$SETTINGS_GROUP" ]]; then
    chgrp "$SETTINGS_GROUP" "$CONFIG_DIR/Settings.json"
  fi
  chmod "$SETTINGS_MODE" "$CONFIG_DIR/Settings.json"
fi

cat <<EOF2
Installed q:
  $BIN_DIR/q
EOF2

if [[ "$WITH_VENV" -eq 1 ]]; then
  cat <<EOF2
Installed Python dependency venv:
  $VENV_DIR
EOF2
fi

if [[ "$COPY_SETTINGS" -eq 1 ]]; then
  cat <<EOF2
Installed Settings.json:
  $CONFIG_DIR/Settings.json
EOF2
else
  cat <<EOF2

Settings.json was not copied. q will look in this order and skip unreadable paths:
  CHECK_HOSTNAME_SETTINGS
  ./Settings.json
  ~/.config/basic_scan/Settings.json
  ~/.local/etc/basic_scan/Settings.json
  ~/.local/share/basic_scan/Settings.json
  /etc/basic_scan/Settings.json
  /usr/local/etc/basic_scan/Settings.json
  /usr/local/share/basic_scan/Settings.json
  /usr/local/lib/basic_scan/Settings.json
  /opt/basic_scan/Settings.json
  /home/ops/net-bot-sa/Settings.json
  /root/script/basic_scan/Settings.json
EOF2
fi

cat <<EOF2

Test:
  $BIN_DIR/q --help
  $BIN_DIR/q R017
EOF2

case ":${PATH}:" in
  *":$BIN_DIR:"*) ;;
  *)
    cat <<EOF2

Note: $BIN_DIR is not in PATH for this shell.
Add it temporarily:
  export PATH="$BIN_DIR:\$PATH"
EOF2
    ;;
esac

