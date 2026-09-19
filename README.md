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
| `--log <path>` | Путь к access.log Xray (реальный путь на **хосте**, не внутри контейнера) |
| `--tag <tag>` | Тег аутбаунда для отслеживания (default: `TORRENT`) |
| `--ban-duration <мин>` | Длительность бана в минутах (default: 10) |
| `--bypass <ip/cidr,...>` | Белый список: одиночные IP и CIDR-подсети |
| `--bypass-net <cidr,...>` | То же, только подсети (алиас) |
| `--bypass-file <path>` | Файл белого списка (default: `/etc/torrent-blocker/bypass.txt`), перечитывается по `SIGHUP` / `systemctl reload` |
| `--vpn-port <p,...>` | Доп. порты, которые НЕ трогать (в дополнение к встроенным VPN/TLS) |
| `--netstat` | ⚠️ Включить эвристики по числу соединений (**по умолчанию ВЫКЛ** — банят мосты) |
| `--finwait-ban` | ⚠️ Включить бан по шторму FIN_WAIT (по умолчанию выкл) |
| `--no-netstat` / `--no-finwait-ban` | Явно выключить (оставлены для совместимости) |
| `--finwait-thresh / --conn-thresh / --sendq-thresh <n>` | Пороги эвристик (действуют только при `--netstat`) |

Команды:

```bash
./main status          # текущее состояние
./main stop            # снять все правила
./main ban 1.2.3.4     # ручной бан
./main unban 1.2.3.4   # снять бан
```

## ⚠️ Защита своей инфраструктуры (мосты, релеи, панель)

Блокер по умолчанию банит **только реальный торрент**: клиента с тегом
`TORRENT` в access.log xray, плюс совпадения DPI по сигнатурам протокола.
Количественные эвристики (`--netstat`, `--finwait-ban`) **выключены**, потому
что они не отличают торрент от моста/релея и легко банят свою же инфраструктуру.

Дополнительно код **никогда** не банит:

- приватные и служебные диапазоны: `10/8`, `172.16/12`, `192.168/16`,
  `100.64/10` (CGNAT), loopback, link-local, ULA `fc00::/7`;
- все адреса интерфейсов самой ноды (собираются на старте автоматически);
- всё, что перечислено в `bypass.txt` (IP или CIDR).

Порты нод/мостов (`443, 3443, 8443, 2096, 4443, 2053, 2083, 2087, 8080, 22,
853` и VPN-порты) исключены и из DPI, и из блокировки портов.

**Мосты/релеи/воронки заносим в `bypass.txt`** — по одному IP или CIDR на строку,
затем `systemctl reload torrent-blocker` (перечитает без простоя). Пример:

```
89.223.124.211        # релей RU
201.10.79.0/24        # DNAT-воронки EE
5.175.178.0/24        # чистые мосты
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
