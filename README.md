# Torrent Blocker

Блокировщик торрент-трафика для Linux на базе iptables/ipset/DPI.  
Работает совместно с [Xray](https://github.com/XTLS/Xray-core) / [Remnawave](https://github.com/remnawave/remnanode).

## Структура

```
main.go          — демон блокировки (запускается на серверах)
deployer/
  main.go        — скрипт массового деплоя на серверы по SSH
  go.mod / go.sum
ssh.txt.example  — пример файла серверов
```

## Запуск блокировщика вручную

```bash
go build -o main main.go
./main --log /var/log/remnanode/access.log --tag TORRENT
```

Параметры:

| Флаг | Описание |
|------|----------|
| `--log <path>` | Путь к access.log Xray |
| `--tag <tag>` | Тег аутбаунда для отслеживания (default: `TORRENT`) |
| `--ban-duration <мин>` | Длительность бана в минутах (default: 60) |
| `--bypass <ip1,ip2>` | IP которые не блокировать |
| `--no-netstat` | Отключить netstat-мониторинг |
| `--finwait-thresh <n>` | Порог FIN_WAIT-соединений (default: 8) |

Команды:

```bash
./main status          # текущее состояние
./main stop            # снять все правила
./main ban 1.2.3.4     # ручной бан
./main unban 1.2.3.4   # снять бан
```

## Деплой на несколько серверов

1. Создай `deployer/ssh.txt` (на основе `ssh.txt.example`):

```
ip1:root:password1
ip2:root:password2
```

2. Запусти деплоер:

```bash
cd deployer
go run main.go
```

Деплоер автоматически:
- Кросс-компилирует бинарник для `linux/amd64`
- Подключается к каждому серверу по SSH
- Устанавливает зависимости (`iptables`, `ipset`, `conntrack`, `net-tools`)
- Загружает бинарник в `/usr/local/bin/torrent-blocker`
- Создаёт и запускает systemd-службу `torrent-blocker`

## Требования на сервере

- Ubuntu / Debian (apt)
- iptables + ipset + conntrack
- Загруженный модуль ядра `xt_string` (для DPI)

## Управление службой

```bash
systemctl status torrent-blocker
systemctl restart torrent-blocker
journalctl -u torrent-blocker -f
```
