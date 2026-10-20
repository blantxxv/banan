# Torrent Blocker

Блокировщик торрент-трафика для Linux на базе iptables/ipset/DPI.  
Работает совместно с [Xray](https://github.com/XTLS/Xray-core) / [Remnawave](https://github.com/remnawave/remnanode).

## Слои защиты

Торрент нельзя надёжно вырезать одним методом (есть шифрованный BT/uTP на 443).
Поэтому — эшелонированно, каждый слой затыкает дыру другого:

| Слой | Что | Механизм | Ставится |
|------|-----|----------|----------|
| **0** | правило роутинга xray | `sniffing` protocol `bittorrent` → **blackhole**/тег TORRENT | в панели Remnawave (не тут) |
| **A** | nDPI (`xt_ndpi`) | ядровый inline-DROP bittorrent на egress | `install.sh --with-ndpi` / `install-ndpi.sh` |
| **B** | Go-демон (`main.go`) | бан клиента по тегу TORRENT в access.log + свой DPI (`-m string`) + порты трекеров/пиров | `install.sh` (по умолчанию) |

Слой 0 — самый надёжный (бьёт сам P2P на любом порту), но живёт в конфиге профиля.
Если у профиля `bittorrent → direct/freedom`, торрент **разрешён** — сначала чинить это.

## Структура

```
main.go            — демон слоя B (запускается на серверах)
install.sh         — установщик слоя B (сборка на ноде); --with-ndpi добавляет слой A
install-ndpi.sh    — установщик слоя A (xt_ndpi + DKMS + self-heal)
log-rotate.sh      — ротация access/error логов remnanode (ставит install.sh)
deployer/
  main.go          — массовый деплой по SSH (запускает install.sh)
  go.mod / go.sum
ssh.txt.example    — пример файла серверов
```

## Установка (одна командой на ноде)

```bash
# только слой B (Go):
curl -fsSL https://raw.githubusercontent.com/blantxxv/banan/main/install.sh | bash
# слой B + слой A (nDPI):
curl -fsSL https://raw.githubusercontent.com/blantxxv/banan/main/install.sh | bash -s -- --with-ndpi
# обкатка: детектор только пишет «DRY-RUN забанил бы» в журнал, без банов
curl -fsSL https://raw.githubusercontent.com/blantxxv/banan/main/install.sh | TB_ARGS=--fanout-dry-run bash
```

Переменные установщика:

| Переменная | Что делает |
|---|---|
| `TB_ARGS="<флаги>"` | Дописать флаги в ExecStart (напр. `--fanout-dry-run`, лишний `--log <путь>`) |
| `TB_BIN=<путь>` | Поставить готовый бинарь без Go и сборки (флот-раскатка одной сборкой) |
| `TB_ROTATE=0` | Не настраивать ротацию логов (по умолчанию настраивается) |

**Ротация логов** (`log-rotate.sh`, ставится установщиком): блокеру нужен
access.log xray, но без ротации он растёт до десятков ГБ (на флоте видели
1.2, 3.1 и 20.6 ГБ). Схема: 200 МБ × 3 архива, `copytruncate`, архивы старой
схемы старше 3 дней удаляются; запуск каждые 10 мин через cron, а где cron нет —
systemd-таймер `remnanode-logrotate.timer`. Папка логов берётся из
docker-монтирования remnanode; вручную — `D=/opt/<нода>/logs sh log-rotate.sh`.

Боевой режим после обкатки: убрать `--fanout-dry-run` из ExecStart
(`systemctl edit --full torrent-blocker`) и `systemctl restart torrent-blocker`.
Смотреть, кого детектор забанил бы: `journalctl -u torrent-blocker | grep DRY-RUN`.

## Запуск слоя B вручную

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
| `--fanout <n>` | Разлёт: ≥n разных голых IP на портах >1024 у одного **email** за окно (default: 30, `0` — выкл) |
| `--fanout-ports <n>` | …и ≥n разных портов (default: 20) |
| `--fanout-window <мин>` | Окно разлёта (default: 5) |
| `--confirm-peers <n>` | Бан сразу при n подтверждённых торрент-пирах (default: 3, `0` — без сверки с ipset) |
| `--fanout-dry-run` | Детектор юзеров только логирует `PEER_FANOUT DRY-RUN забанил бы …`, не банит (тег TORRENT, домены и DPI работают как обычно) |

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

DPI-ловушки `CATCH_PEER`/`CATCH_TRACKER` тоже не заносят в ipset локальные и
приватные адреса: на входящем пакете пир→нода `dst` — это сама нода или
контейнер за DNAT (так в 2026 году падала EE-нода, `172.30.44.2` в `auto_peers_v4`).

Порты нод/мостов (`443, 3443, 8443, 2096, 4443, 2053, 2083, 2087, 8080, 22,
853` и VPN-порты) исключены и из DPI, и из блокировки портов. Исключение одно:
открытый HTTP на `:80` проверяется HTTP-сигнатурами (announce, `info_hash=`,
User-Agent клиентов, веб-сид `BTWebClient`) — только DROP пакета, без ipset.

### Проверено на живом захвате (uTorrent 3.6.0, 20 окт 2026)

| Что на проводе | Чем ловится |
|---|---|
| `\x13BitTorrent protocol`, peer_id `-UT360W-` | hex-сигнатура хендшейка |
| расширенный хендшейк `12:complete_ago…11:ut_metadata` | `12:complete_ago`, `11:ut_metadata`, `upload_only`… |
| PEX `5:added…7:added.f…7:dropped` | `7:added.f` |
| uTP ST_SYN, 20 байт, первый байт `0x41` | u32-правило, IP-пакет 48 байт |
| DHT `find_node`, `1:v4:UT` | `d1:ad2:id20:`, `1:q9:find_node` |
| UDP-трекер connect `0x41727101980` | hex-сигнатура BEP15 |
| веб-сид `GET … Range:` с `User-Agent: BTWebClient/360S` на `:80` | `User-Agent: BTWebClient` по `--dport 80` |
| HTTPS-трекеры `tracker.se7en.ws`, `tracker.7launcher.*`, `ledger.bt.co` | домен в access.log (`isTrackerHost`, `bt.co`) |

### Шифрованный BT через VPN-ноду (qBittorrent 5.3, нода [EE] #29, 20 окт 2026)

libtorrent шифрует пиров (MSE/PE): на ноде весь объём — случайные байты,
sniffing xray **не распознал ни одного** соединения (`bittorrent → BLOCK` в
профиле был, всё ушло в `DIRECT`), DPI-сигнатурам тоже нечего ловить. Открытым
остаётся только DHT (`get_peers`/`info_hash`) — его режет DPI, но клиента это
не банит: на ноде его IP скрыт за xray.

Клиента выдаёт поведение в access.log: за 4.5 мин у торрент-юзера **75** разных
IP на высоких портах, у остальных 10 юзеров ноды — 0–2. uFiler и MediaGet
качают по uTP, а UDP в access.log почти не попадает. Поэтому детектор юзеров
собирает несколько признаков (идеи fsnt-torrent-blocker, Ezhik Torrent Guard,
Karagiannis et al. IMC'04):

| Признак | Условие | Бан |
|---|---|---|
| Разлёт | за `--fanout-window` ≥`--fanout` разных голых IP **и** ≥`--fanout-ports` разных портов (порты >1024, без STUN/TURN, 7680 Windows DO, пушей, Zoom, Steam) | по **второму** разлёту за 15 мин |
| Разлёт + подтверждение | разлёт и хотя бы 1 подтверждённый пир | сразу |
| Подтверждённые пиры | ≥`--confirm-peers` пиров: xray отправил в blackhole (`-> BLOCK` на голый IP:порт>1024), DPI поймал (ipset `auto_peers`), или пир и по TCP, и по UDP | сразу |

Счёт **по email** (не по IP — так банились мосты). Источник, за которым видно
≥3 юзеров (мост/релей/NAT), не банится — только лог `PEER_FANOUT`. Наказание —
бан IP клиента на `--ban-duration` (10 мин).

Прогон живых логов ноды: шифрованный qBittorrent — бан через 2 с после старта
(второй разлёт), раздача MediaGet — через 1 с (три пира в `BLOCK`); остальных
10 юзеров не задело. ⚠️ Нужен включённый access.log в профиле ноды.

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
