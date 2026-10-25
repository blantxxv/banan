#!/bin/sh
# Логи на ноде живут не дольше 3 суток — гарантированно .
# Ротация (log-rotate.sh) режет по размеру, но на тихой ноде access.log
# месяцами не дорастает до порога и копит историю. Здесь — возраст:
#  - ротированные копии и архивы (*.log.N, *.log-ДАТА, *.gz) старше MAX_MIN — удалить;
#  - живой *.log, если его ПЕРВАЯ строка старше MAX_MIN (или файл не менялся
#    дольше MAX_MIN) — обнулить: xray пишет с O_APPEND, обнуление безопасно,
#    блокер сам переоткроет файл;
#  - docker json-логи контейнеров (stdout xray там же) — так же по первой строке;
#  - журнал systemd — MaxRetentionSec=3day + vacuum.
# Ставится install.sh как /usr/local/sbin/tb-log-purge + таймер tb-log-purge.timer (раз в час).
# DRY=1 — только показать, что было бы удалено/обнулено.
set -u
MAX_MIN=${MAX_MIN:-4320}
DRY=${DRY:-0}
act_rm()    { if [ "$DRY" = 1 ]; then echo "would rm $1"; else rm -f "$1"; fi; }
act_trunc() { if [ "$DRY" = 1 ]; then echo "would truncate $1 ($(du -h "$1" | cut -f1))"; else : > "$1"; fi; }
MAX_SEC=$((MAX_MIN * 60))
NOW=$(date +%s)
n_del=0; n_trunc=0

# Возраст первой строки: xray «2026/10/25 19:17:01.343053 …», docker json «"time":"2026-10-25T19:17:01…"».
first_ts() {
    l=$(head -c 400 "$1" 2>/dev/null | head -n 1)
    case "$l" in
        [0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]\ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]*)
            date -u -d "$(echo "$l" | cut -c1-19 | tr / -)" +%s 2>/dev/null ;;
        *'"time":"'*)
            date -u -d "$(echo "$l" | sed -n 's/.*"time":"\([0-9T:-]*\).*/\1/p' | tr T ' ')" +%s 2>/dev/null ;;
    esac
}

too_old() {  # файл: первая строка или mtime старше MAX
    ts=$(first_ts "$1")
    [ -n "$ts" ] && [ $((NOW - ts)) -gt $MAX_SEC ] && return 0
    [ -n "$(find "$1" -maxdepth 0 -mmin +$MAX_MIN 2>/dev/null)" ]
}

DIRS="/var/log/remnanode /opt/remnanode/logs /opt/ee-node/logs /var/log/xray"
for d in /opt/*/logs; do DIRS="$DIRS $d"; done
if command -v docker >/dev/null 2>&1; then
    for c in $(docker ps -q 2>/dev/null); do
        DIRS="$DIRS $(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/log/remnanode"}}{{.Source}}{{end}}{{end}}' "$c" 2>/dev/null)"
    done
fi
seen=" "
for d in $DIRS; do
    [ -d "$d" ] || continue
    r=$(readlink -f "$d"); case "$seen" in *" $r "*) continue ;; esac; seen="$seen$r "
    for f in $(find "$r" -maxdepth 1 -type f \( -name '*.gz' -o -name '*.log.*' -o -name '*.log-*' -o -name '*.[0-9]' \) -mmin +$MAX_MIN 2>/dev/null); do
        act_rm "$f" && n_del=$((n_del + 1))
    done
    for f in "$r"/*.log; do
        [ -s "$f" ] || continue
        if too_old "$f"; then act_trunc "$f" && n_trunc=$((n_trunc + 1)); fi
    done
done

for f in /var/lib/docker/containers/*/*-json.log; do
    [ -s "$f" ] || continue
    if too_old "$f"; then act_trunc "$f" && n_trunc=$((n_trunc + 1)); fi
done

if [ -d /etc/systemd ] && [ "$DRY" != 1 ]; then
    mkdir -p /etc/systemd/journald.conf.d
    want='[Journal]
MaxRetentionSec=3day
SystemMaxUse=500M'
    if [ "$(cat /etc/systemd/journald.conf.d/90-tb-retention.conf 2>/dev/null)" != "$want" ]; then
        printf '%s\n' "$want" > /etc/systemd/journald.conf.d/90-tb-retention.conf
        systemctl restart systemd-journald 2>/dev/null
    fi
    journalctl --vacuum-time=3d >/dev/null 2>&1
fi
echo "tb-log-purge: удалено $n_del, обнулено $n_trunc (порог ${MAX_MIN} мин)"
