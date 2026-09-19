#!/usr/bin/env bash
# ============================================================================
# Torrent Blocker — слой A (nDPI, xt_ndpi): ядровый inline-DROP bittorrent.
#
# Ставит модуль ядра xt_ndpi (из vel21ripn/nDPI), регистрирует его в DKMS
# (пересборка при обновлении ядра) и держит правило
#     iptables -o <WAN> -m ndpi --proto bittorrent -j DROP
# на вершине OUTPUT через systemd-таймер (self-heal после ufw/docker reload).
#
# Это ДОПОЛНЕНИЕ к слою B (Go torrent-blocker): слой A глушит торрент прямо в
# ядре по всему egress, слой B банит клиента по логам xray + свой DPI/порты.
# Отдельный namespace имён (tb-ndpi-*), чтобы сосуществовать со старым ds-guard.
#
# Использование:  bash install-ndpi.sh          (ставит/пересобирает)
#                 bash install-ndpi.sh --status  (статус)
#                 bash install-ndpi.sh --uninstall
#
# ⚠️ Модуль ядра собирается НЕ везде: LXC/OpenVZ без своего ядра — нельзя;
# clang-ядра (XanMod) требуют ту же версию clang; на очень старых ядрах может
# не собраться. Скрипт это определяет и честно выходит с кодом != 0, не трогая
# уже работающий слой B.
# ============================================================================
set -u
export DEBIAN_FRONTEND=noninteractive

VERSION="1.0"
LOG=/var/log/torrent-ndpi-install.log
NDPI_REPO="https://github.com/vel21ripn/nDPI.git"
NDPI_BRANCH="flow_info-4"
STATE_DIR=/etc/torrent-blocker
SBIN=/usr/local/sbin
KREL="$(uname -r)"
KMAKE=""
IPT="iptables -w"

c_g="\033[32m"; c_y="\033[33m"; c_r="\033[31m"; c_0="\033[0m"
log(){ printf '%s %b\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG"; }
ok(){  log "${c_g}[ OK ]${c_0} $*"; }
warn(){ log "${c_y}[WARN]${c_0} $*"; }
err(){ log "${c_r}[FAIL]${c_0} $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
retry(){ local n=$1; shift; local i=1; until "$@"; do [ "$i" -ge "$n" ] && return 1; warn "retry $i/$n"; sleep $((i*3)); i=$((i+1)); done; }
APT_NET_OPTS="-o Acquire::ForceIPv4=true -o Acquire::Retries=3 -o Acquire::http::Timeout=25 -o Acquire::https::Timeout=25"
apt_install(){ retry 3 apt-get $APT_NET_OPTS -o DPkg::Lock::Timeout=300 -y -q install "$@" >>"$LOG" 2>&1; }

[ "$(id -u)" -eq 0 ] || { err "Запускай от root"; exit 1; }
mkdir -p "$STATE_DIR"
: > "$LOG" 2>/dev/null || true

# ── контейнер? модули ядра не загрузить ─────────────────────────────────────
VIRT="$(systemd-detect-virt 2>/dev/null || echo none)"
case "$VIRT" in
  openvz|lxc|lxc-libvirt|docker|podman|wsl)
    err "virt=$VIRT — контейнер без своего ядра: xt_ndpi поставить нельзя."
    err "Слой A недоступен на этой площадке. Слой B (Go) работает и без него."
    exit 2;;
esac

status(){
  echo "== torrent-blocker слой A (nDPI) =="
  echo "WAN: $(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')"
  echo "xt_ndpi: loaded=$(lsmod 2>/dev/null | grep -c '^xt_ndpi')  bt_hash=$(cat /sys/module/xt_ndpi/parameters/bt_hash_size 2>/dev/null)"
  echo "tb-ndpi.timer: $(systemctl is-active tb-ndpi.timer 2>/dev/null)"
  echo "OUTPUT rule:"; $IPT -S OUTPUT 2>/dev/null | grep -i 'ndpi --proto bittorrent' | sed 's/^/  /' || echo "  (нет)"
}

uninstall(){
  systemctl disable --now tb-ndpi.timer tb-ndpi.service >/dev/null 2>&1 || true
  local NIC; NIC="$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')"
  [ -n "${NIC:-}" ] && while $IPT -C OUTPUT -o "$NIC" -m ndpi --proto bittorrent -j DROP 2>/dev/null; do
    $IPT -D OUTPUT -o "$NIC" -m ndpi --proto bittorrent -j DROP; done
  rm -f /etc/systemd/system/tb-ndpi.service /etc/systemd/system/tb-ndpi.timer \
        "$SBIN/tb-ndpi-apply.sh" "$SBIN/tb-ndpi-ensure.sh" \
        /etc/modules-load.d/xt_ndpi.conf /etc/modprobe.d/xt_ndpi.conf
  dkms remove -m ndpi -v 1.0 --all >/dev/null 2>&1 || true
  systemctl daemon-reload
  ok "слой A (nDPI) удалён (слой B не тронут)"
}

case "${1:-}" in
  --status)    status; exit 0;;
  --uninstall) uninstall; exit 0;;
esac

log "--- слой A (nDPI) v$VERSION: установка/пересборка на ядре $KREL ---"

# был ли НАШ модуль уже рабочим — чтобы неудачная пересборка не сломала ноду
had_ndpi=0
if modprobe xt_ndpi 2>/dev/null && $IPT -m ndpi --help >/dev/null 2>&1; then had_ndpi=1; fi

# ── toolchain: clang-ядра (XanMod) требуют ту же версию clang ────────────────
if grep -qs 'CONFIG_CC_IS_CLANG=y' "/boot/config-$KREL" 2>/dev/null || grep -qi clang /proc/version 2>/dev/null; then
  kcc="$(grep -s '^CONFIG_CC_VERSION_TEXT=' "/boot/config-$KREL" 2>/dev/null | sed 's/^[^=]*=//; s/"//g')"
  [ -n "$kcc" ] || kcc="$(cat /proc/version 2>/dev/null)"
  kmaj="$(printf '%s' "$kcc" | sed -nE 's/.*clang version ([0-9]+).*/\1/p')"
  log "clang-ядро: ${kcc:-?}"
  if [ -n "$kmaj" ] && apt_install "clang-$kmaj" "lld-$kmaj" "llvm-$kmaj"; then
    KMAKE="LLVM=-$kmaj"; ok "toolchain: clang-$kmaj (LLVM=-$kmaj)"
  else
    apt_install clang lld llvm || warn "clang/lld/llvm install failed"
    KMAKE="LLVM=1"; [ -n "$kmaj" ] && warn "clang-$kmaj в apt нет — системный clang"
  fi
fi

# ── заголовки ядра ──────────────────────────────────────────────────────────
apt_install "linux-headers-$KREL" || true
if [ ! -d "/lib/modules/$KREL/build" ]; then
  da="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
  for hp in linux-headers-generic "linux-headers-$da" "linux-headers-cloud-$da"; do
    apt_install "$hp" && break
  done
fi
[ -d "/lib/modules/$KREL/build" ] || { err "нет заголовков ядра для $KREL — слой A пропущен"; exit 2; }

apt_install build-essential git autoconf automake libtool pkg-config libpcap-dev libgcrypt20-dev flex bison libxtables-dev dkms \
  || warn "часть зависимостей не встала"
miss=""; for b in gcc make dkms pkg-config git; do have "$b" || miss="$miss $b"; done
[ -n "$miss" ] && { err "нет инструментов сборки:$miss — слой A пропущен"; exit 1; }

# ── клон + сборка ───────────────────────────────────────────────────────────
cd /opt || exit 1; rm -rf ndpi-build
log "клонирую nDPI ($NDPI_BRANCH)…"
retry 2 git clone --depth 1 -b "$NDPI_BRANCH" "$NDPI_REPO" ndpi-build >>"$LOG" 2>&1 || { err "git clone nDPI не удался"; exit 1; }

# gcc-only флаг ломает сборку на clang (см. память по флоту) — вырезаем.
mk=/opt/ndpi-build/ndpi-netfilter/src/Makefile
if [ -n "$KMAKE" ] && grep -q 'femit-struct-debug-detailed' "$mk" 2>/dev/null; then
  sed -i '/-femit-struct-debug-detailed=any/d' "$mk" \
    && ok "вырезан gcc-only флаг -femit-struct-debug-detailed=any" \
    || warn "не смог поправить Makefile — сборка на clang может упасть"
fi

log "собираю libnDPI (самый долгий шаг, несколько минут)…"
( cd /opt/ndpi-build && ./autogen.sh && ./configure && make -j"$(nproc)" ) >>"$LOG" 2>&1 \
  || { err "сборка libnDPI не удалась (см. $LOG)"; exit 1; }
log "собираю модуль xt_ndpi…"
( cd /opt/ndpi-build/ndpi-netfilter && make -j"$(nproc)" $KMAKE ) >>"$LOG" 2>&1 || true

KO="$(find /opt/ndpi-build -name xt_ndpi.ko | head -1)"
SO="$(find /opt/ndpi-build -name libxt_ndpi.so | head -1)"
if [ -z "$KO" ] || [ -z "$SO" ]; then
  tail -30 "$LOG" | sed 's/^/    /'
  if [ "$had_ndpi" = 1 ]; then warn "пересборка не завершилась — оставляю уже работавший модуль"; else err "xt_ndpi не собрался на этом ядре"; exit 1; fi
else
  # ── DKMS: пережить обновление ядра ──
  rm -rf /usr/src/ndpi-1.0; cp -a /opt/ndpi-build /usr/src/ndpi-1.0
  cat > /usr/src/ndpi-1.0/dkms.conf <<DK
PACKAGE_NAME="ndpi"
PACKAGE_VERSION="1.0"
BUILT_MODULE_NAME[0]="xt_ndpi"
BUILT_MODULE_LOCATION[0]="ndpi-netfilter/src"
DEST_MODULE_LOCATION[0]="/updates/dkms"
MAKE[0]="make -C ndpi-netfilter/src KERNEL_DIR=/lib/modules/\${kernelver}/build modules $KMAKE"
CLEAN="make -C ndpi-netfilter/src KERNEL_DIR=/lib/modules/\${kernelver}/build clean"
AUTOINSTALL="yes"
DK
  dkms add -m ndpi -v 1.0 >>"$LOG" 2>&1 || true
  dkms build -m ndpi -v 1.0 >>"$LOG" 2>&1 || true
  dkms install -m ndpi -v 1.0 --force >>"$LOG" 2>&1 || true
  modinfo xt_ndpi >/dev/null 2>&1 || { mkdir -p "/lib/modules/$KREL/updates/dkms"; cp "$KO" "/lib/modules/$KREL/updates/dkms/"; depmod -a; }
  XTDIR="$(pkg-config --variable=xtlibdir xtables 2>/dev/null || echo /usr/lib/$(uname -m)-linux-gnu/xtables)"
  cp "$SO" "$XTDIR/libxt_ndpi.so" 2>/dev/null || true
fi

echo 'options xt_ndpi bt_hash_size=32 bt_hash_timeout=1200' > /etc/modprobe.d/xt_ndpi.conf
echo 'xt_ndpi' > /etc/modules-load.d/xt_ndpi.conf

# ── enforcer + self-heal (правило переживает ufw/docker reload и ребут) ──────
cat > "$SBIN/tb-ndpi-ensure.sh" <<'ENS'
#!/usr/bin/env bash
set -u
modprobe -q xt_ndpi 2>/dev/null && exit 0
command -v dkms >/dev/null 2>&1 && dkms autoinstall -k "$(uname -r)" >/dev/null 2>&1
modprobe -q xt_ndpi 2>/dev/null; exit 0
ENS
cat > "$SBIN/tb-ndpi-apply.sh" <<'APPLY'
#!/usr/bin/env bash
# Держит правило nDPI-DROP bittorrent на вершине OUTPUT. Идемпотентно.
set -u
IPT="iptables -w"
NIC="$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')"
[ -n "$NIC" ] || exit 0
modprobe -q xt_ndpi 2>/dev/null || true
R="-o $NIC -m ndpi --proto bittorrent -j DROP"
# ждём, пока match подхватится после свежей сборки
for _i in 1 2 3 4 5; do $IPT -m ndpi --help >/dev/null 2>&1 && break; modprobe -q xt_ndpi 2>/dev/null; sleep 1; done
if $IPT -m ndpi --help >/dev/null 2>&1; then
  while $IPT -C OUTPUT $R 2>/dev/null; do $IPT -D OUTPUT $R; done
  $IPT -I OUTPUT 1 $R
fi
exit 0
APPLY
chmod +x "$SBIN/tb-ndpi-ensure.sh" "$SBIN/tb-ndpi-apply.sh"

cat > /etc/systemd/system/tb-ndpi.service <<'SVC'
[Unit]
Description=Torrent Blocker слой A (nDPI) - egress bittorrent DROP
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=600
ExecStartPre=-/usr/local/sbin/tb-ndpi-ensure.sh
ExecStart=/usr/local/sbin/tb-ndpi-apply.sh
[Install]
WantedBy=multi-user.target
SVC
cat > /etc/systemd/system/tb-ndpi.timer <<'TMR'
[Unit]
Description=Torrent Blocker слой A (nDPI) - periodic re-assert (self-heal)
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Unit=tb-ndpi.service
[Install]
WantedBy=timers.target
TMR
systemctl daemon-reload
systemctl enable --now tb-ndpi.service >>"$LOG" 2>&1 || true
systemctl enable --now tb-ndpi.timer   >>"$LOG" 2>&1 || true

sleep 1
if $IPT -S OUTPUT 2>/dev/null | grep -q 'ndpi --proto bittorrent'; then
  ok "слой A активен: xt_ndpi загружен, правило DROP bittorrent на OUTPUT, DKMS + self-heal"
  exit 0
fi
warn "модуль собран, но правило ещё не встало — таймер доставит его в течение минуты"
exit 0
