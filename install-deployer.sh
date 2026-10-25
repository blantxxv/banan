#!/usr/bin/env bash
set -e

REPO="https://raw.githubusercontent.com/mahmudali1337-lab/torrent-blocker/master"
DEPLOY_DIR="/opt/torrent-deployer"
GO_VERSION="1.22.3"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}   $*"; }
info() { echo -e "${CYAN}[*]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║     Torrent Deployer — Installer             ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

[ "$(id -u)" -ne 0 ] && echo -e "${RED}[ERROR]${NC} Запускай от root" && exit 1

info "Установка зависимостей (curl, git)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>&1 | tail -1
apt-get install -y -qq curl git 2>&1 | tail -2
ok "curl, git установлены"

if command -v go &>/dev/null; then
    ok "Go уже установлен: $(go version)"
else
    info "Установка Go ${GO_VERSION}..."
    cd /tmp
    curl -fsSL "${GO_URL}" -o "${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${GO_TAR}"
    rm -f "${GO_TAR}"
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/golang.sh
    chmod +x /etc/profile.d/golang.sh
    export PATH=$PATH:/usr/local/go/bin
    ok "Go установлен: $(go version)"
fi

export PATH=$PATH:/usr/local/go/bin

info "Скачивание исходников деплоера в ${DEPLOY_DIR}..."
rm -rf "${DEPLOY_DIR}"
mkdir -p "${DEPLOY_DIR}"

curl -fsSL "${REPO}/deployer/main.go" -o "${DEPLOY_DIR}/main.go"
curl -fsSL "${REPO}/deployer/go.mod"  -o "${DEPLOY_DIR}/go.mod"
curl -fsSL "${REPO}/deployer/go.sum"  -o "${DEPLOY_DIR}/go.sum"
curl -fsSL "${REPO}/ssh.txt.example"  -o "${DEPLOY_DIR}/ssh.txt.example"
ok "Исходники скачаны"

info "Сборка деплоера..."
cd "${DEPLOY_DIR}"
go build -o deployer main.go
chmod +x deployer
ok "Деплоер собран: ${DEPLOY_DIR}/deployer"

echo
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Деплоер установлен!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo
echo -e "  Папка:    ${CYAN}${DEPLOY_DIR}${NC}"
echo -e "  Бинарник: ${CYAN}${DEPLOY_DIR}/deployer${NC}"
echo
echo -e "  ${YELLOW}Следующий шаг — создать список серверов:${NC}"
echo -e "  ${CYAN}nano ${DEPLOY_DIR}/ssh.txt${NC}"
echo -e "  Формат: ${CYAN}ip:user:password${NC}  (один сервер на строку)"
echo
echo -e "  ${YELLOW}Запуск деплоя:${NC}"
echo -e "  ${CYAN}cd ${DEPLOY_DIR} && ./deployer${NC}"
echo
