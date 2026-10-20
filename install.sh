#!/usr/bin/env bash
set -e

REPO="https://raw.githubusercontent.com/blantxxv/banan/main"
BINARY="/usr/local/bin/torrent-blocker"
SERVICE="torrent-blocker"
SERVICE_FILE="/etc/systemd/system/${SERVICE}.service"
BYPASS_FILE="/etc/torrent-blocker/bypass.txt"
# START_CMD собирается ниже, после того как определим реальный путь к access.log.
# netstat-эвристики НЕ включаем: они банят мосты/релеи (см. bypass.txt).

# --with-ndpi: дополнительно поставить слой A (ядровый xt_ndpi). По умолчанию
# ставится только слой B (Go). Слой A требует сборки модуля ядра (не на всех).
WITH_NDPI=0
for _a in "$@"; do [ "$_a" = "--with-ndpi" ] && WITH_NDPI=1; done

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

# TB_BIN=<путь>: поставить готовый бинарь (флот-раскатка одной проверенной
# сборкой) — без Go и сборки на ноде.
if [ -n "${TB_BIN:-}" ]; then
    [ -x "${TB_BIN}" ] || fail "TB_BIN=${TB_BIN} не найден или не исполняемый"
    TMPDIR=$(mktemp -d); cp "${TB_BIN}" "${TMPDIR}/torrent-blocker"; cd "${TMPDIR}"
    ok "Готовый бинарник: ${TB_BIN} ($(sha256sum "${TB_BIN}" | cut -c1-12))"
elif command -v go >/dev/null 2>&1; then
    ok "Go уже установлен: $(go version)"
else
    info "Установка Go через apt..."
    apt-get install -y -qq golang-go
    command -v go >/dev/null 2>&1 || fail "Не удалось установить Go"
    ok "Go установлен: $(go version)"
fi

if [ -z "${TB_BIN:-}" ]; then
    info "Загрузка исходного кода..."
    TMPDIR=$(mktemp -d)
    curl -fsSL "${REPO}/main.go" -o "${TMPDIR}/main.go"
    ok "main.go скачан в ${TMPDIR}/main.go"

    info "Сборка бинарника (linux/amd64)..."
    cd "${TMPDIR}"
    go mod init torrent-blocker 2>/dev/null || true
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o torrent-blocker main.go
    ok "Бинарник собран: $(du -sh torrent-blocker | cut -f1)"
fi

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

# ── Белый список: чтобы блокер НИКОГДА не отрезал наши мосты/релеи/панель ────
info "Настройка белого списка ${BYPASS_FILE}..."
mkdir -p "$(dirname "${BYPASS_FILE}")"
if [ ! -f "${BYPASS_FILE}" ]; then
    cat > "${BYPASS_FILE}" << 'EOB'
# torrent-blocker: белый список. По одному IP или CIDR на строку, '#' — комментарий.
# Сюда вносим ВСЁ своё, что не должно попасть под бан:
#   - haproxy-мосты и sing-box мосты
#   - релеи (напр. 89.223.124.211) и DNAT-воронки (напр. 201.10.79.0/24)
#   - адреса панели
# Приватные диапазоны (10/8, 172.16/12, 192.168/16, 100.64/10), loopback,
# link-local и адреса самой ноды защищены в коде и сюда добавлять не нужно.
# После правок: systemctl reload torrent-blocker (перечитает без простоя).
EOB
    chmod 600 "${BYPASS_FILE}"
    ok "Создан шаблон ${BYPASS_FILE}"
else
    ok "Белый список уже существует, не трогаю: ${BYPASS_FILE}"
fi

# Автоматически добавляем IP того, кто сейчас по SSH — чтобы деплой не отрезал админа.
SSH_IP="$(echo "${SSH_CONNECTION}" | awk '{print $1}')"
if [ -n "${SSH_IP}" ] && ! grep -qxF "${SSH_IP}" "${BYPASS_FILE}" 2>/dev/null; then
    echo "${SSH_IP}    # SSH-клиент (добавлено установщиком)" >> "${BYPASS_FILE}"
    ok "В белый список добавлен SSH-клиент: ${SSH_IP}"
fi

# ── Определяем реальный путь к access.log xray ──────────────────────────────
# Вендорский дефолт /var/log/remnanode/access.log — это путь ВНУТРИ контейнера;
# на хосте лог лежит в <папке ноды>/logs/access.log (compose монтирует ./logs).
# С неверным путём блокер слеп. Ищем реально существующий файл.
info "Поиск access.log xray на хосте..."
LOGPATH=""
LOGARGS=""
# На одной машине бывает несколько нод (host-net + bridge-контейнеры со своим
# SNAT-адресом, как на starry .186–.190) — следим за логом КАЖДОГО запущенного
# remnanode-контейнера, иначе остальные выходы слепы.
if command -v docker >/dev/null 2>&1; then
    for c in $(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null | awk 'tolower($0) ~ /remnanode|remnawave\/node/ {print $1}'); do
        src="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/log/remnanode"}}{{.Source}}{{end}}{{end}}' "$c" 2>/dev/null)"
        [ -n "$src" ] && [ -f "$src/access.log" ] || continue
        case " $LOGARGS " in *" --log $src/access.log "*) continue ;; esac
        LOGARGS="$LOGARGS --log $src/access.log"; LOGPATH="${LOGPATH:-$src/access.log}"
        ok "access.log ($c): $src/access.log"
    done
fi
[ -z "${LOGPATH}" ] && for cand in \
    /var/log/remnanode/access.log \
    /opt/remnanode/logs/access.log \
    /root/remnanode/logs/access.log \
    /home/ubuntu/remnanode/logs/access.log \
    /home/*/remnanode/logs/access.log ; do
    if [ -f "${cand}" ]; then LOGPATH="${cand}"; break; fi
done
if [ -z "${LOGPATH}" ]; then
    FOUND="$(find /opt /root /home /var/log -maxdepth 4 -type f -name access.log -path '*remnanode*' 2>/dev/null | head -1)"
    [ -n "${FOUND}" ] && LOGPATH="${FOUND}"
fi
if [ -z "${LOGPATH}" ]; then
    LOGPATH="/var/log/remnanode/access.log"
    warn "access.log не найден на хосте — ставлю дефолт ${LOGPATH}."
    warn "Проверь, что в конфиге ноды включён лог доступа, и поправь ExecStart при необходимости."
elif [ -z "${LOGARGS}" ]; then
    ok "access.log: ${LOGPATH}"
fi
[ -z "${LOGARGS}" ] && LOGARGS="--log ${LOGPATH}"

START_CMD="${BINARY} ${LOGARGS# } --tag TORRENT --no-netstat --no-finwait-ban --ban-duration 10 --bypass-file ${BYPASS_FILE}"
# TB_ARGS="<флаги>": дописать в ExecStart (напр. TB_ARGS=--fanout-dry-run для обкатки).
[ -n "${TB_ARGS:-}" ] && START_CMD="${START_CMD} ${TB_ARGS}"

info "Запись systemd unit-файла..."
cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=Torrent Blocker
After=network.target

[Service]
Type=simple
ExecStart=${START_CMD}
ExecReload=/bin/kill -HUP \$MAINPID
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

# ── Слой A (nDPI), опционально ──────────────────────────────────────────────
if [ "${WITH_NDPI}" = "1" ]; then
    echo
    info "Ставлю слой A (nDPI, ядровый DROP bittorrent)..."
    NDPI_TMP="$(mktemp)"
    if curl -fsSL "${REPO}/install-ndpi.sh" -o "${NDPI_TMP}"; then
        # не валим весь установщик, если модуль ядра не собрался (слой B уже стоит)
        if bash "${NDPI_TMP}"; then ok "Слой A (nDPI) установлен"; else warn "Слой A (nDPI) не встал на этом ядре — работает только слой B (это нормально для LXC/части ядер)"; fi
    else
        warn "Не смог скачать install-ndpi.sh — слой A пропущен"
    fi
    rm -f "${NDPI_TMP}"
fi

echo
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Установка завершена успешно!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════${NC}"
echo
echo -e "  Слой B (Go):"
echo -e "    Статус:     ${CYAN}systemctl status ${SERVICE}${NC}"
echo -e "    Журнал:     ${CYAN}journalctl -u ${SERVICE} -f${NC}"
echo -e "    Стоп:       ${CYAN}${BINARY} stop${NC}"
echo -e "    Статистика: ${CYAN}${BINARY} status${NC}"
echo -e "    Белый список: ${CYAN}${BYPASS_FILE}${NC}  (правка → ${CYAN}systemctl reload ${SERVICE}${NC})"
if [ "${WITH_NDPI}" = "1" ]; then
    echo -e "  Слой A (nDPI):"
    echo -e "    Статус:     ${CYAN}bash install-ndpi.sh --status${NC}  (или ${CYAN}systemctl status tb-ndpi.timer${NC})"
fi
echo
