#!/bin/sh
# Ротация access/error логов remnanode по размеру + удаление старых архивов.
# access.log нужен блокеру (детектор читает его), но без ротации он растёт до
# десятков ГБ (на флоте видели 1.2, 3.1 и 20.6 ГБ). Схема: size 200M, 3 архива,
# copytruncate, архивы старой схемы (*.log-ДАТА) старше 3 дней удаляются;
# запуск каждые 10 мин — cron, а где cron нет — systemd-таймер.
# Папка логов берётся из docker-монтирования remnanode; D=<папка> — вручную.
set -u
command -v logrotate >/dev/null 2>&1 || \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq logrotate >/dev/null 2>&1
if [ -z "${D:-}" ] && command -v docker >/dev/null 2>&1; then
    for c in $(docker ps --format '{{.Names}} {{.Image}}' | awk 'tolower($0) ~ /remnanode|remnawave\/node/ {print $1}'); do
        D=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/var/log/remnanode"}}{{.Source}}{{end}}{{end}}' "$c")
        [ -n "$D" ] && break
    done
fi
D=${D:-/opt/remnanode/logs}
for f in $(grep -lsE "remnanode|access.log" /etc/logrotate.d/* 2>/dev/null); do
    [ "$f" = /etc/logrotate.d/remnanode-access ] && continue
    grep -q "$D" "$f" && mv "$f" "/root/$(basename "$f").disabled-dup"
done
cat > /etc/logrotate.d/remnanode-access <<EOF
$D/*.log {
    size 200M
    rotate 3
    compress
    missingok
    notifempty
    copytruncate
}
EOF
CMD="/usr/sbin/logrotate /etc/logrotate.d/remnanode-access; find $D -name '*.log-*' -mtime +3 -delete"
if systemctl is-active -q cron; then
    echo "*/10 * * * * root $CMD" > /etc/cron.d/remnanode-log-maxsize
    chmod 644 /etc/cron.d/remnanode-log-maxsize
    mode=cron
else
    rm -f /etc/cron.d/remnanode-log-maxsize
    cat > /etc/systemd/system/remnanode-logrotate.service <<EOF
[Unit]
Description=Rotate remnanode logs by size
[Service]
Type=oneshot
ExecStart=/bin/sh -c "$CMD"
EOF
    cat > /etc/systemd/system/remnanode-logrotate.timer <<EOF
[Unit]
Description=Rotate remnanode logs every 10 min
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now remnanode-logrotate.timer >/dev/null 2>&1
    mode="timer:$(systemctl is-active remnanode-logrotate.timer)"
fi
sh -c "$CMD"
echo "rot=$mode logs=$(du -sh $D | cut -f1) files=$(ls $D | tr '\n' ' ')"
