#!/usr/bin/env bash
set -Eeuo pipefail

C='\033[96m'; G='\033[92m'; R='\033[91m'; N='\033[0m'
info(){ echo -e "${C}[*]${N} $*"; }
ok(){ echo -e "${G}[+]${N} $*"; }
fail(){ echo -e "${R}[!]${N} $*" >&2; exit 1; }

if [[ "${EUID}" -eq 0 ]]; then SUDO=""; else
  command -v sudo >/dev/null 2>&1 || fail "Execute como root ou instale sudo."
  SUDO="sudo"
fi

if ! command -v python3 >/dev/null 2>&1 || ! command -v pip3 >/dev/null 2>&1; then
  info "Instalando Python 3 e pip..."
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update
    $SUDO apt-get install -y python3 python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -Sy --needed --noconfirm python python-pip
  elif command -v zypper >/dev/null 2>&1; then
    $SUDO zypper --non-interactive install python3 python3-pip
  else
    fail "Gerenciador não suportado. Instale python3 e pip3 manualmente."
  fi
fi

info "Python: $(python3 --version)"
info "Instalando dependências globais (sem venv)..."
pip3 install --break-system-packages -r requirements.txt
chmod +x main.py
ok "CrowService instalado."
echo -e "Execute: ${C}python3 main.py${N}"
