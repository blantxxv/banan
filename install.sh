#!/usr/bin/env bash
set -e

REPO="https://raw.githubusercontent.com/blantxxv/banan/main"
BINARY="/usr/local/bin/torrent-blocker"
SERVICE="torrent-blocker"
SERVICE_FILE="/etc/systemd/system/${SERVICE}.service"
START_CMD="${BINARY} --log /var/log/remnanode/access.log --tag TORRENT --no-finwait-ban --ban-duration 10 --conn-thresh 300 --sendq-thresh 10 --finwait-thresh 30"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║       Torrent Blocker — Auto Installer       ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

[ "$(id -u)" -ne 0 ] && fail "Запускай от root (sudo bash install.sh)"

info "Обновление пакетов..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>&1 | tail -2

info "Установка зависимостей (curl, iptables, ipset, conntrack, net-tools)..."
apt-get install -y -qq curl iptables ipset conntrack net-tools iproute2 2>&1 | tail -5
ok "Зависимости установлены"

info "Загрузка модуля xt_string..."
modprobe xt_string 2>/dev/null && ok "xt_string загружен" || warn "xt_string недоступен (DPI может не работать)"

if command -v go >/dev/null 2>&1; then
    ok "Go уже установлен: $(go version)"
else
    info "Установка Go через apt..."
    apt-get install -y -qq golang-go
    command -v go >/dev/null 2>&1 || fail "Не удалось установить Go"
    ok "Go установлен: $(go version)"
fi

info "Загрузка исходного кода..."
TMPDIR=$(mktemp -d)
curl -fsSL "${REPO}/main.go" -o "${TMPDIR}/main.go"
ok "main.go скачан в ${TMPDIR}/main.go"

info "Сборка бинарника (linux/amd64)..."
cd "${TMPDIR}"
go mod init torrent-blocker 2>/dev/null || true
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o torrent-blocker main.go
ok "Бинарник собран: $(du -sh torrent-blocker | cut -f1)"

info "Установка бинарника в ${BINARY}..."
systemctl stop "${SERVICE}" 2>/dev/null || true
cp torrent-blocker "${BINARY}"
chmod +x "${BINARY}"
ok "Установлен: ${BINARY}"

info "Создание директории состояния..."
mkdir -p /var/lib/torrent-blocker
chmod 750 /var/lib/torrent-blocker
rm -f /var/lib/torrent-blocker/blocked.json
ok "/var/lib/torrent-blocker создан (старое состояние очищено)"

info "Запись systemd unit-файла..."
cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=Torrent Blocker
After=network.target

[Service]
Type=simple
ExecStart=${START_CMD}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
ok "Записан ${SERVICE_FILE}"

info "systemctl daemon-reload..."
systemctl daemon-reload

info "Включение автозапуска..."
systemctl enable "${SERVICE}"
ok "systemctl enable ${SERVICE}"

info "Запуск службы..."
systemctl restart "${SERVICE}"
sleep 2

STATUS=$(systemctl is-active "${SERVICE}" 2>/dev/null)
if [ "${STATUS}" = "active" ]; then
    ok "Служба активна (active)"
else
    warn "Статус: ${STATUS}"
    echo "--- Журнал ---"
    journalctl -u "${SERVICE}" -n 20 --no-pager 2>/dev/null
fi

info "Проверка iptables цепочек..."
iptables -L TORRENT_DPI --line-numbers -n 2>/dev/null | head -8 || warn "Цепочка TORRENT_DPI ещё не создана"
iptables -t raw -L TORRENT_BAN -n 2>/dev/null | head -5 || true

cd /
rm -rf "${TMPDIR}"

echo
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Установка завершена успешно!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo
echo -e "  Статус:   ${CYAN}systemctl status ${SERVICE}${NC}"
echo -e "  Журнал:   ${CYAN}journalctl -u ${SERVICE} -f${NC}"
echo -e "  Стоп:     ${CYAN}${BINARY} stop${NC}"
echo -e "  Статистика: ${CYAN}${BINARY} status${NC}"
echo
