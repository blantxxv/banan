package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	dpiChain    = "TORRENT_DPI"
	banChain    = "TORRENT_BAN"
	peerChain   = "TORRENT_PEERS"
	banTable    = "raw"
	banHook     = "PREROUTING"
	storageFile = "/var/lib/torrent-blocker/blocked.json"
)

var dpiHooks = []string{"OUTPUT", "FORWARD", "INPUT"}
var banHooks = []string{"PREROUTING", "OUTPUT"}

var (
	banDuration = 10 * time.Minute
	peerBanDur  = 24 * time.Hour
	logFiles    []string // --log можно повторять: на ноде бывает несколько xray (host-net + bridge-контейнеры)
	torrentTag  = "TORRENT"
	// ⚠️ netstat-эвристики (шторм FIN_WAIT / много ESTABLISHED с большой
	// send-queue) НЕ отличают торрент от моста/релея и банят свою же
	// инфраструктуру. Поэтому по умолчанию ВЫКЛЮЧЕНЫ. Включать осознанно
	// флагами --netstat / --finwait-ban только на нодах, через которые не
	// ходят haproxy/sing-box мосты и релеи.
	enableNetstat = false
	enableFinWait = false
	finWaitThresh = 30
	connThresh    = 300
	sendQThresh   = 10
	bypassFile    = "/etc/torrent-blocker/bypass.txt"
	// Порты, которые НИКОГДА не трогаем: и DPI-цепочка их пропускает (RETURN),
	// и блок портов их не блокирует. Сюда входят VPN-протоколы и все TLS-порты,
	// на которых живут наши ноды/мосты/фронты/релеи (Reality, Hysteria2,
	// haproxy, Cloudflare-совместимые). Торрент на этих портах почти не
	// встречается — сохранность мостов важнее.
	vpnPorts = map[string]bool{
		"22":    true, // SSH — чтобы DPI никогда не отрезал управление
		"53":    true, // DNS (домены-трекеры ловим отдельными правилами по dport 53)
		"80":    true,
		"443":   true,
		"853":   true, // DoT
		"500":   true,
		"1194":  true,
		"4500":  true,
		"51820": true, // WireGuard
		// TLS-порты нод/мостов/фронтов (см. haproxy/Reality/Hysteria2 на флоте)
		"2053": true,
		"2083": true,
		"2087": true,
		"2096": true,
		"3443": true,
		"4443": true,
		"8080": true,
		"8443": true,
	}
)

var (
	blockedMu  sync.Mutex
	blockedIPs = map[string]*blockInfo{}
)

var (
	peerMu  sync.Mutex
	peerIPs = map[string]*blockInfo{}
)

var (
	finWaitMu  sync.Mutex
	finWaitHit = map[string]int{}
)

type blockInfo struct {
	IP      string    `json:"ip"`
	Blocked time.Time `json:"blocked"`
	Until   time.Time `json:"until"`
	Reason  string    `json:"reason,omitempty"`
}

type signature struct {
	proto   string
	pattern string
	hex     string
	dport   int
	action  string
	// http: открытый HTTP-запрос (трекер/веб-сид). Порт 80 стоит в vpnPorts,
	// поэтому такие сигнатуры дополнительно проверяются по --dport 80 ДО
	// общего RETURN — см. httpSigRules().
	http bool
}

var signatures = []signature{
	{proto: "tcp", hex: "|13426974546f7272656e742070726f746f636f6c|", action: "PEER"},
	// Тот же хендшейк внутри uTP (UDP, сразу за 20-байтным заголовком): живой
	// uFiler/libtorrent (-LT1140-) на [EE] #29, 20 окт 2026 — основной объём шёл по uTP.
	{proto: "udp", hex: "|13426974546f7272656e742070726f746f636f6c|", action: "PEER"},
	{proto: "udp", pattern: "d1:ad2:id20:", action: "PEER"},
	{proto: "udp", pattern: "d1:rd2:id20:", action: "PEER"},
	{proto: "udp", pattern: "1:q9:get_peers", action: "PEER"},
	{proto: "udp", pattern: "1:q13:announce_peer", action: "PEER"},
	{proto: "udp", pattern: "1:q9:find_node", action: "PEER"},
	{proto: "udp", pattern: "1:q4:ping", action: "PEER"},
	{proto: "udp", pattern: "1:q4:vote", action: "PEER"},
	{proto: "udp", pattern: "1:q17:sample_infohashes", action: "PEER"},
	{proto: "udp", pattern: "1:q3:put", action: "PEER"},       // BEP44 DHT store
	{proto: "udp", pattern: "1:q3:get", action: "PEER"},       // BEP44 DHT read
	{proto: "udp", pattern: "9:info_hash20:", action: "PEER"}, // аргумент get_peers/announce_peer
	{proto: "udp", pattern: "1:y1:q", action: "PEER"},         // KRPC query
	{proto: "udp", pattern: "1:y1:r", action: "PEER"},         // KRPC response
	{proto: "udp", pattern: "1:y1:e", action: "PEER"},         // KRPC error
	// Peer wire / extension protocol (BEP9/BEP10/BEP11) — .torrent-метаданные,
	// PEX, обмен кусками. Проявляется на исходящем плече нода→пир открытым текстом.
	{proto: "tcp", pattern: "13:piece length", action: "PEER"},
	{proto: "tcp", pattern: "4:infod", action: "PEER"},
	{proto: "tcp", pattern: "11:ut_metadata", action: "PEER"},
	{proto: "tcp", pattern: "13:metadata_size", action: "PEER"},
	{proto: "tcp", pattern: "5:ut_pex", action: "PEER"},
	{proto: "tcp", pattern: "12:ut_holepunch", action: "PEER"},
	{proto: "tcp", pattern: "upload_only", action: "PEER"},
	{proto: "tcp", pattern: "lt_donthave", action: "PEER"},
	// Сняты с живого uTorrent 3.6 (20 окт 2026): ключ расширенного хендшейка
	// uTorrent/libtorrent и PEX-сообщение (BEP11), идущее и посреди потока.
	{proto: "tcp", pattern: "12:complete_ago", action: "PEER"},
	{proto: "tcp", pattern: "7:added.f", action: "PEER"},
	// UDP-трекер (BEP15): connect-запрос всегда начинается с protocol_id 0x41727101980.
	{proto: "udp", hex: "|0000041727101980|", action: "TRACKER"},
	{proto: "tcp", pattern: "info_hash=", action: "TRACKER", http: true},
	{proto: "tcp", pattern: "peer_id=", action: "TRACKER", http: true},
	{proto: "tcp", pattern: "announce?", action: "TRACKER", http: true},
	{proto: "tcp", pattern: "scrape?", action: "TRACKER", http: true},
	{proto: "tcp", pattern: "event=started", action: "TRACKER", http: true},
	{proto: "tcp", pattern: "event=stopped", action: "TRACKER", http: true},
	{proto: "tcp", pattern: "event=completed", action: "TRACKER", http: true},
	{proto: "tcp", pattern: "d8:announce", action: "TRACKER"},
	{proto: "tcp", pattern: "d13:announce-list", action: "TRACKER"},
	{proto: "tcp", pattern: "/announce HTTP", action: "TRACKER", http: true},
	{proto: "tcp", pattern: "/scrape HTTP", action: "TRACKER", http: true},
	// magnet-ссылки и info-hash в открытом HTTP (btih = BitTorrent Info Hash).
	{proto: "tcp", pattern: "xt=urn:btih:", action: "DROP", http: true},
	{proto: "tcp", pattern: "urn:btih:", action: "DROP", http: true},
	{proto: "tcp", pattern: "urn:btmh:", action: "DROP", http: true}, // BitTorrent v2 multihash
	// Local Service Discovery (BEP14) — мультикаст-анонс пиров в локальной сети.
	{proto: "udp", pattern: "BT-SEARCH * HTTP/1.1", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: uTorrent", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: BitTorrent", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: qBittorrent", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: Transmission", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: libtorrent", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: Deluge", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: Vuze", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: Azureus", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: Aria2", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: WebTorrent", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: Tixati", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: BiglyBT", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: BitComet", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: BitLord", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: KTorrent", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: rtorrent", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: Folx", action: "DROP", http: true},
	{proto: "tcp", pattern: "User-Agent: FrostWire", action: "DROP", http: true},
	// Веб-сид (BEP19/url-list) uTorrent/BitTorrent: файлы раздачи качаются
	// обычным HTTP GET с Range на :80 — без BT-хендшейка, xray не тегирует
	// это как bittorrent. В живом захвате это был заметный объём загрузки.
	{proto: "tcp", pattern: "User-Agent: BTWebClient", action: "DROP", http: true},
	{proto: "udp", dport: 53, pattern: "router.bittorrent.com", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "router.utorrent.com", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "dht.transmissionbt.com", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "opentrackr", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "nyaa", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "rutracker", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "rutor", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "thepiratebay", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "1337x", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "dht.libtorrent.org", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "router.bitcomet.com", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "dht.aelitis.com", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "router.bittorrent.com", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "router.utorrent.com", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "dht.transmissionbt.com", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "dht.libtorrent.org", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "router.bitcomet.com", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "dht.aelitis.com", action: "DROP"},
}

// Порты трекеров и служебные P2P-порты. Блокируются на OUTPUT/FORWARD/INPUT,
// но НЕ трогаются, если попали в vpnPorts. Все значения — заведомо ниже
// эфемерного диапазона Linux (32768–60999), поэтому блок по --sport не задевает
// исходящие соединения нод/мостов.
var trackerPorts = []string{
	"6969", "2710", "1337", // popular UDP/HTTP tracker ports
	"6771",                         // Local Service Discovery (BEP14)
	"4662", "4661", "4672", "4665", // eDonkey/eMule
	"411", "412", "1214", "4242",
	"8999", "3659",
}

// Стандартные порты BitTorrent-клиентов (диапазон входящих подключений пиров).
var clientPorts = []string{
	"6881:6999", "6880", "51413", // BitTorrent mainline / Transmission
}

var torrentDestDomains = []string{
	"rutracker.org", "rutor.info", "thepiratebay.org",
	"1337x.to", "nyaa.si", "opentrackr.org",
	"tracker.openbittorrent.com", "tracker.opentrackr.org",
	"tracker.leechers-paradise.org", "tracker.coppersurfer.tk",
	"explodie.org", "tracker.pirateparty.gr",
	"tracker.internetwarriors.net", "tracker.tiny-vps.com",
	"open.tracker.cl", "open.stealth.si",
	"tracker.torrent.eu.org", "tracker.dler.org",
	"router.bittorrent.com", "router.utorrent.com",
	"dht.transmissionbt.com",
	"bt.co", // BitTorrent Inc: ledger.bt.co дёргает сам uTorrent (живой захват)
}

var torrentDestKeywords = []string{
	"torrent", "bittorrent", "magnet", "rutracker", "rutor", "piratebay", "thepiratebay",
	"opentrackr", "1337x", "nyaa", "rarbg", "demonoid", "yggtorrent",
	"limetorrents", "torrentgalaxy", "eztv", "zooqle", "torlock",
	"skytorrents", "torrentz", "btdigg", "nnmclub", "tapochek", "kinozal",
	"fast-torrent", "qbittorrent", "utorrent", "webtorrent",
	"announce", "opentracker", "publictracker", "retracker",
	"btih", "infohash",
	"openbittorrent.com", "opentrackr.org", "coppersurfer.tk", "leechers-paradise.org",
	"internetwarriors.net", "torrent.eu.org", "moeking.me", "bt-hash.com",
	"dutchtracking.com", "justseed.it", "zer0day.to", "cyberia.is", "explodie.org",
	"bittor.pw", "theoks.net", "wepzone.net", "files.fm", "lilithraws.cf",
	"tamersunion.org", "noobsubs.net", "nitrix.me", "qu.ax",
	"btdigg.org", "bt4g.com", "torrentz2.eu", "kickasstorrents",
	"archive.org/download", "i2p.rocks", "zerobytes.xyz",
	"vulnix.sh", "publictracker.xyz", "skynetcloud.site", "altrosky.nl",
	"dpiui.reedlan.com", "zum.bi", "dler.org", "nyaatracker.com",
	"trakx.nibba.trade", "itzmx.com", "sakurato.xyz", "leech.ie",
	"animereactor.ru", "kamigami.org", "shkinev.me",
}

var bypassDomains = []string{
	"vk.com", "vk.ru", "vk.me",
	"vk-analytics.ru",
	"userapi.com",
	"vkuseraudio.net", "vkuseraudio.com",
	"vkvideo.ru",
	"tracker-api.my.com",
	"my.com",
	"announcekit.co",
	"maticooads.com",
	"wildberries.ru",
	"googleapis.com", "google.com", "googleusercontent.com", "gstatic.com",
	"firebase.google.com", "crashlytics.com",
	"yandex.ru", "yandex.net", "yandex.com",
	"appmetrica.yandex.net", "appmetrica.yandex.com",
	"yango.com",
	"facebook.com", "fb.com", "instagram.com", "fbcdn.net",
	"qq.com", "tencent.com", "weixin.qq.com",
	"dbankcloud.ru", "dbankcloud.com", "hicloud.com",
	"honkaiimpact3.com", "mihoyo.com", "hoyoverse.com",
	"appsflyer.com", "adjust.com", "amplitude.com",
	"ekatox.com", "ekatox-ru.com",
	"smartcallback.ru",
}

// ── Белый список (защита своей инфраструктуры) ──────────────────────────────
//
// bypassIPs   — точные адреса (мосты, релеи, панель, свой egress, SSH-клиент).
// bypassNets  — CIDR-подсети из --bypass-net и файла bypass.txt.
// Плюс к ним isProtectedIP всегда пропускает приватные/служебные диапазоны
// (RFC1918, CGNAT 100.64/10, loopback, link-local, ULA), чтобы блокер никогда
// не банил docker-мост, внутренний релей или собственные адреса ноды.
var (
	bypassMu   sync.RWMutex
	bypassIPs  = map[string]bool{"127.0.0.1": true, "::1": true}
	bypassNets []*net.IPNet
)

func addBypassIP(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	if _, cidr, err := net.ParseCIDR(ip); err == nil {
		bypassMu.Lock()
		bypassNets = append(bypassNets, cidr)
		bypassMu.Unlock()
		return
	}
	bypassMu.Lock()
	bypassIPs[ip] = true
	bypassMu.Unlock()
}

// isProtectedIP — единственная точка решения «можно ли банить этот IP».
// Возвращает true, если адрес трогать НЕЛЬЗЯ.
func isProtectedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // не смогли распарсить — на всякий случай не баним
	}
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10,
			ip4[0] == 172 && ip4[1]&0xf0 == 16, // 172.16.0.0/12
			ip4[0] == 192 && ip4[1] == 168,     // 192.168.0.0/16
			ip4[0] == 100 && ip4[1]&0xc0 == 64, // 100.64.0.0/10 (CGNAT)
			ip4[0] == 169 && ip4[1] == 254,     // link-local
			ip4[0] == 127:
			return true
		}
	} else if ip[0]&0xfe == 0xfc { // fc00::/7 (ULA)
		return true
	}
	bypassMu.RLock()
	defer bypassMu.RUnlock()
	if bypassIPs[ipStr] {
		return true
	}
	for _, n := range bypassNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// addLocalIPs заносит все адреса интерфейсов ноды в белый список, чтобы блокер
// никогда не забанил собственный egress/relay-адрес сервера.
func addLocalIPs() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	n := 0
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			addBypassIP(ipn.IP.String())
			n++
		}
	}
	if n > 0 {
		log.Printf("bypass: добавлено %d локальных адресов ноды", n)
	}
}

// loadBypassFile читает bypass.txt (по одному IP или CIDR на строку, '#' —
// комментарий). Вызывается на старте и по SIGHUP — можно дописать мост/релей
// без перезапуска сервиса.
func loadBypassFile(path string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	// Пользовательские CIDR пересобираем заново (для чистого перечтения по SIGHUP).
	bypassMu.Lock()
	bypassNets = nil
	bypassMu.Unlock()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		addBypassIP(line)
		n++
	}
	log.Printf("bypass: из %s загружено записей: %d", path, n)
}

func iptcmd(ip string) string {
	if strings.Contains(ip, ":") {
		return "ip6tables"
	}
	return "iptables"
}

func ipsetSuffix(ip string) string {
	if strings.Contains(ip, ":") {
		return "_v6"
	}
	return "_v4"
}

func ensureDependencies() {
	for _, dep := range []string{"conntrack", "iptables", "ipset", "netstat"} {
		if _, err := exec.LookPath(dep); err != nil {
			exec.Command("apt-get", "update").Run()
			exec.Command("apt-get", "install", "-y", dep).Run()
		}
	}
}

func cleanupDPI() {
	for _, ipt := range []string{"iptables", "ip6tables"} {
		for _, chain := range dpiHooks {
			exec.Command(ipt, "-D", chain, "-j", dpiChain).Run()
		}
		for _, chain := range []string{dpiChain, "CATCH_TRACKER", "CATCH_PEER"} {
			exec.Command(ipt, "-F", chain).Run()
			exec.Command(ipt, "-X", chain).Run()
		}
		for _, proto := range []string{"tcp", "udp"} {
			for _, port := range trackerPorts {
				if vpnPorts[port] {
					continue
				}
				for _, chain := range dpiHooks {
					dir := "--dport"
					if chain == "INPUT" {
						dir = "--sport"
					}
					exec.Command(ipt, "-D", chain, "-p", proto, dir, port, "-j", "DROP").Run()
				}
			}
			for _, port := range clientPorts {
				if vpnPorts[port] {
					continue
				}
				exec.Command(ipt, "-D", "FORWARD", "-p", proto, "--dport", port, "-j", "DROP").Run()
				exec.Command(ipt, "-D", "FORWARD", "-p", proto, "--sport", port, "-j", "DROP").Run()
				exec.Command(ipt, "-D", "INPUT", "-p", proto, "--sport", port, "-j", "DROP").Run()
			}
		}
	}
}

func cleanupBan() {
	for _, ipt := range []string{"iptables", "ip6tables"} {
		for _, hook := range banHooks {
			exec.Command(ipt, "-t", banTable, "-D", hook, "-j", banChain).Run()
		}
		exec.Command(ipt, "-t", banTable, "-F", banChain).Run()
		exec.Command(ipt, "-t", banTable, "-X", banChain).Run()
	}
}

func cleanupPeers() {
	for _, ipt := range []string{"iptables", "ip6tables"} {
		exec.Command(ipt, "-D", "OUTPUT", "-j", peerChain).Run()
		exec.Command(ipt, "-D", "FORWARD", "-j", peerChain).Run()
		exec.Command(ipt, "-F", peerChain).Run()
		exec.Command(ipt, "-X", peerChain).Run()
		sfx := "_v4"
		if ipt == "ip6tables" {
			sfx = "_v6"
		}
		for _, chain := range []string{"OUTPUT", "FORWARD"} {
			exec.Command(ipt, "-D", chain, "-m", "set", "--match-set", "auto_trackers"+sfx, "dst", "-j", "DROP").Run()
			exec.Command(ipt, "-D", chain, "-m", "set", "--match-set", "auto_peers"+sfx, "dst", "-j", "DROP").Run()
		}
	}
	for _, name := range []string{"auto_trackers_v4", "auto_trackers_v6", "auto_peers_v4", "auto_peers_v6"} {
		exec.Command("ipset", "destroy", name).Run()
	}
}

func cleanup() {
	cleanupDPI()
	cleanupBan()
	cleanupPeers()
}

func initBanChain() {
	for _, ipt := range []string{"iptables", "ip6tables"} {
		exec.Command(ipt, "-t", banTable, "-N", banChain).Run()
		for _, hook := range banHooks {
			exec.Command(ipt, "-t", banTable, "-I", hook, "1", "-j", banChain).Run()
		}
	}
}

func initPeerChain() {
	exec.Command("ipset", "create", "auto_trackers_v4", "hash:ip", "timeout", "86400", "-exist").Run()
	exec.Command("ipset", "create", "auto_trackers_v6", "hash:ip", "family", "inet6", "timeout", "86400", "-exist").Run()
	exec.Command("ipset", "create", "auto_peers_v4", "hash:ip", "timeout", "86400", "-exist").Run()
	exec.Command("ipset", "create", "auto_peers_v6", "hash:ip", "family", "inet6", "timeout", "86400", "-exist").Run()

	for _, ipt := range []string{"iptables", "ip6tables"} {
		exec.Command(ipt, "-N", peerChain).Run()
		exec.Command(ipt, "-I", "OUTPUT", "1", "-j", peerChain).Run()
		exec.Command(ipt, "-I", "FORWARD", "1", "-j", peerChain).Run()
		sfx := "_v4"
		if ipt == "ip6tables" {
			sfx = "_v6"
		}
		for _, chain := range []string{"OUTPUT", "FORWARD"} {
			exec.Command(ipt, "-I", chain, "1", "-m", "set", "--match-set", "auto_trackers"+sfx, "dst", "-j", "DROP").Run()
			exec.Command(ipt, "-I", chain, "1", "-m", "set", "--match-set", "auto_peers"+sfx, "dst", "-j", "DROP").Run()
		}
	}
}

func blockPeer(ip, reason string) {
	if isProtectedIP(ip) {
		return
	}
	peerMu.Lock()
	if _, exists := peerIPs[ip]; exists {
		peerMu.Unlock()
		return
	}
	peerIPs[ip] = &blockInfo{IP: ip, Until: time.Now().Add(peerBanDur), Reason: reason}
	peerMu.Unlock()

	exec.Command(iptcmd(ip), "-A", peerChain, "-d", ip, "-j", "DROP").Run()
	exec.Command("ipset", "add", "auto_peers"+ipsetSuffix(ip), ip, "-exist").Run()
	conntrackDrop(ip)
	log.Printf("PEER_BLOCK %s (%s)", ip, reason)
}

func banIP(ip, reason string) {
	if isProtectedIP(ip) {
		return
	}
	blockedMu.Lock()
	if _, exists := blockedIPs[ip]; exists {
		blockedMu.Unlock()
		return
	}
	info := &blockInfo{IP: ip, Blocked: time.Now(), Until: time.Now().Add(banDuration), Reason: reason}
	blockedIPs[ip] = info
	blockedMu.Unlock()

	exec.Command(iptcmd(ip), "-t", banTable, "-A", banChain, "-s", ip, "-j", "DROP").Run()
	exec.Command(iptcmd(ip), "-t", banTable, "-A", banChain, "-d", ip, "-j", "DROP").Run()
	conntrackDrop(ip)
	saveStorage()
	log.Printf("BAN %s (%s) for %v", ip, reason, banDuration)
}

func unbanIP(ip string) {
	blockedMu.Lock()
	if _, exists := blockedIPs[ip]; !exists {
		blockedMu.Unlock()
		return
	}
	delete(blockedIPs, ip)
	blockedMu.Unlock()

	exec.Command(iptcmd(ip), "-t", banTable, "-D", banChain, "-s", ip, "-j", "DROP").Run()
	exec.Command(iptcmd(ip), "-t", banTable, "-D", banChain, "-d", ip, "-j", "DROP").Run()
	saveStorage()
	log.Printf("UNBAN %s", ip)
}

func unbanPeer(ip string) {
	peerMu.Lock()
	delete(peerIPs, ip)
	peerMu.Unlock()
	exec.Command(iptcmd(ip), "-D", peerChain, "-d", ip, "-j", "DROP").Run()
}

func conntrackDrop(ip string) {
	exec.Command("conntrack", "-D", "-s", ip).Run()
	exec.Command("conntrack", "-D", "-d", ip).Run()
}

func saveStorage() {
	blockedMu.Lock()
	data, _ := json.Marshal(blockedIPs)
	blockedMu.Unlock()
	os.MkdirAll("/var/lib/torrent-blocker", 0750)
	tmp := storageFile + ".tmp"
	ioutil.WriteFile(tmp, data, 0640)
	os.Rename(tmp, storageFile)
}

func loadStorage() {
	data, err := ioutil.ReadFile(storageFile)
	if err != nil {
		return
	}
	var loaded map[string]*blockInfo
	if json.Unmarshal(data, &loaded) != nil {
		return
	}
	now := time.Now()
	blockedMu.Lock()
	defer blockedMu.Unlock()
	for ip, info := range loaded {
		if now.Before(info.Until) {
			blockedIPs[ip] = info
			exec.Command(iptcmd(ip), "-t", banTable, "-A", banChain, "-s", ip, "-j", "DROP").Run()
			exec.Command(iptcmd(ip), "-t", banTable, "-A", banChain, "-d", ip, "-j", "DROP").Run()
			log.Printf("restored ban: %s (%v left, reason: %s)", ip, info.Until.Sub(now).Truncate(time.Second), info.Reason)
		}
	}
}

func parseXrayLogLine(line, tag string) (clientIP, destAddr, email string, matched bool) {
	tagPatterns := []string{
		">> " + tag + "]",
		"-> " + tag + "]",
		"[" + tag + "]",
		" " + tag + " ",
		"outboundTag: " + tag,
	}
	found := false
	for _, p := range tagPatterns {
		if strings.Contains(line, p) {
			found = true
			break
		}
	}
	if !found {
		return
	}
	matched = true

	parseHostPort := func(s string) string {
		s = strings.TrimPrefix(s, "tcp:")
		s = strings.TrimPrefix(s, "udp:")
		host, _, err := net.SplitHostPort(s)
		if err == nil && net.ParseIP(host) != nil {
			return host
		}
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			return ip.String()
		}
		return ""
	}

	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "from" && i+1 < len(fields) {
			clientIP = parseHostPort(fields[i+1])
		}
		if f == "accepted" && i+1 < len(fields) {
			destAddr = fields[i+1]
		}
		if f == "email:" && i+1 < len(fields) {
			email = fields[i+1]
		}
	}

	if clientIP == "" {
		for _, f := range fields {
			f = strings.TrimPrefix(f, "tcp:")
			f = strings.TrimPrefix(f, "udp:")
			host, _, err := net.SplitHostPort(f)
			if err == nil && net.ParseIP(host) != nil {
				clientIP = host
				break
			}
		}
	}

	return
}

func extractDestFromLine(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "accepted" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func extractClientIPFromLine(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "from" && i+1 < len(fields) {
			s := strings.TrimPrefix(fields[i+1], "tcp:")
			s = strings.TrimPrefix(s, "udp:")
			host, _, err := net.SplitHostPort(s)
			if err == nil && net.ParseIP(host) != nil {
				return host
			}
		}
	}
	for _, f := range fields {
		s := strings.TrimPrefix(f, "tcp:")
		s = strings.TrimPrefix(s, "udp:")
		host, _, err := net.SplitHostPort(s)
		if err == nil && net.ParseIP(host) != nil {
			return host
		}
	}
	return ""
}

func isDomainTorrent(dest string) bool {
	dest = strings.TrimPrefix(dest, "tcp:")
	dest = strings.TrimPrefix(dest, "udp:")
	host, _, _ := net.SplitHostPort(dest)
	if host == "" {
		host = dest
	}
	host = strings.ToLower(host)
	for _, d := range bypassDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return false
		}
	}
	for _, d := range torrentDestDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	if isTrackerHost(host) {
		return true
	}

	for _, kw := range torrentDestKeywords {
		if strings.Contains(host, kw) {
			return true
		}
	}
	return false
}

// ── Детектор торрент-юзеров по access.log ────────────────────────────────────
//
// Живые тесты 20 окт 2026 на [EE] #29 (VLESS): qBittorrent 5.3 шифрует пиров
// (MSE/PE) — sniffing xray и DPI их не видят; uFiler/MediaGet качают по uTP,
// а UDP в access.log почти не попадает. Поэтому юзера выдаёт поведение, и мы
// собираем несколько независимых признаков (идеи fsnt-torrent-blocker,
// Ezhik Torrent Guard, Karagiannis et al. IMC'04):
//
//  1. Разлёт: за окно ≥ fanoutThresh разных голых IP И ≥ fanoutPortThresh
//     разных портов (у P2P у каждого пира свой порт, у веба всё на 443).
//     Порты легального разлёта (STUN/TURN, P2P обновлений Windows, пуши,
//     Zoom, Steam) в счёт не идут.
//  2. Подтверждённые пиры: xray уже распознал bittorrent и отправил в
//     blackhole (строка "-> BLOCK" на голый публичный IP:порт>1024 — реклама
//     идёт по доменам, SMTP на 25, приватные отсечены); IP из auto_peers
//     (DPI поймал DHT/uTP/хендшейк к нему); один и тот же пир по TCP и по UDP.
//  3. Повтор: без подтверждения бан только по второму срабатыванию разлёта
//     за fanoutRepeatWindow — одиночный всплеск не банит.
//
// Счёт ПО EMAIL, а не по IP источника (старые netstat-эвристики считали по IP
// и банили мосты). Если за IP источника видно ≥ fanoutSharedEmails юзеров
// (мост/релей/NAT), IP не баним — только лог. Наказание — banIP на banDuration.
var (
	fanoutThresh       = 30
	fanoutPortThresh   = 20
	fanoutWindow       = 5 * time.Minute
	fanoutRepeatWindow = 15 * time.Minute
	fanoutConfirmNeed  = 3 // столько подтверждённых пиров = торрент без разлёта
	blackholeTags      = []string{"BLOCK", "block", "blackhole", "RW_TB_OUTBOUND_BLOCK"}

	fanoutMu    sync.Mutex
	fanoutUsers = map[string]*fanoutUser{}
	fanoutSrc   = map[string]map[string]time.Time{} // IP источника → email → когда видели
	fanoutCalls int
)

const fanoutSharedEmails = 3

// Порты, которые дают легальный разлёт по голым IP.
var fanoutIgnorePorts = [][2]int{
	{3478, 3497},   // STUN/TURN: звонки, Discord, WebRTC
	{5349, 5349},   // TURN/TLS
	{19302, 19309}, // Google STUN
	{7680, 7680},   // Delivery Optimization — P2P обновлений Windows
	{5222, 5223},   // XMPP/WhatsApp, Apple push
	{5228, 5230},   // Google push
	{8801, 8810},   // Zoom
	{27015, 27050}, // Steam
}

type fanoutUser struct {
	clientIP  string
	peers     map[string]time.Time // IP пира → когда видели
	ports     map[string]time.Time // порт пира → когда видели
	tcpPeers  map[string]time.Time
	udpPeers  map[string]time.Time
	confirmed map[string]time.Time // подтверждённые торрент-пиры
	hits      []time.Time          // срабатывания разлёта
}

// fanoutVerdict — решение по юзеру. Ban=true: банить clientIP (если не Shared).
type fanoutVerdict struct {
	Ban          bool
	Shared       bool
	Protected    bool // источник в bypass/приватный — IP не баним
	Key          string
	ClientIP     string
	Hosts, Ports int
	Confirmed    int
	Reason       string
}

func extractEmailFromLine(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "email:" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// lineOutboundTag: тег аутбаунда из "[inbound >> TAG]" / "[inbound -> TAG]".
func lineOutboundTag(line string) string {
	for _, sep := range []string{" >> ", " -> "} {
		if i := strings.Index(line, sep); i >= 0 {
			rest := line[i+len(sep):]
			if j := strings.IndexByte(rest, ']'); j >= 0 {
				return rest[:j]
			}
		}
	}
	return ""
}

func fanoutPortIgnored(p int) bool {
	for _, r := range fanoutIgnorePorts {
		if p >= r[0] && p <= r[1] {
			return true
		}
	}
	return false
}

// fanoutPeer: назначение — голый публичный IP на порту >1024, не из vpnPorts
// и не из портов легального разлёта. Домены (сайты, CDN) в счёт не идут.
func fanoutPeer(dest string) (proto, ip, port string) {
	proto = "tcp"
	d := dest
	if strings.HasPrefix(d, "udp:") {
		proto = "udp"
	}
	d = strings.TrimPrefix(strings.TrimPrefix(d, "tcp:"), "udp:")
	host, port, err := net.SplitHostPort(d)
	if err != nil || net.ParseIP(host) == nil || vpnPorts[port] {
		return "", "", ""
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 1024 || fanoutPortIgnored(p) || isProtectedIP(host) {
		return "", "", ""
	}
	return proto, host, port
}

func pruneSeen(m map[string]time.Time, cutoff time.Time) {
	for k, t := range m {
		if t.Before(cutoff) {
			delete(m, k)
		}
	}
}

func isBlackholeTag(tag string) bool {
	for _, t := range blackholeTags {
		if tag == t {
			return true
		}
	}
	return false
}

func fanoutUserFor(key, clientIP string) *fanoutUser {
	u := fanoutUsers[key]
	if u == nil {
		u = &fanoutUser{peers: map[string]time.Time{}, ports: map[string]time.Time{},
			tcpPeers: map[string]time.Time{}, udpPeers: map[string]time.Time{},
			confirmed: map[string]time.Time{}}
		fanoutUsers[key] = u
	}
	if clientIP != "" {
		u.clientIP = clientIP
	}
	return u
}

// fanoutEvaluate — под fanoutMu. Сбрасывает счётчики юзера после бана.
func fanoutEvaluate(key string, u *fanoutUser, now time.Time) fanoutVerdict {
	cutoff := now.Add(-fanoutWindow)
	for _, m := range []map[string]time.Time{u.peers, u.ports, u.tcpPeers, u.udpPeers, u.confirmed} {
		pruneSeen(m, cutoff)
	}
	// Karagiannis: один и тот же пир и по TCP, и по UDP — почти всегда P2P.
	for ip, t := range u.tcpPeers {
		if _, ok := u.udpPeers[ip]; ok {
			u.confirmed[ip] = t
		}
	}
	v := fanoutVerdict{Key: key, ClientIP: u.clientIP, Hosts: len(u.peers), Ports: len(u.ports), Confirmed: len(u.confirmed)}

	spread := fanoutThresh > 0 && v.Hosts >= fanoutThresh && v.Ports >= fanoutPortThresh
	if spread {
		u.hits = append(u.hits, now)
		u.peers, u.ports = map[string]time.Time{}, map[string]time.Time{} // копим заново
	}
	rcut := now.Add(-fanoutRepeatWindow)
	var recent []time.Time
	for _, t := range u.hits {
		if !t.Before(rcut) {
			recent = append(recent, t)
		}
	}
	u.hits = recent

	switch {
	case fanoutConfirmNeed > 0 && v.Confirmed >= fanoutConfirmNeed:
		v.Ban, v.Reason = true, fmt.Sprintf("torrent_peers:%d", v.Confirmed)
	case spread && v.Confirmed > 0:
		v.Ban, v.Reason = true, fmt.Sprintf("peer_fanout:%dh/%dp+confirmed:%d", v.Hosts, v.Ports, v.Confirmed)
	case spread && len(u.hits) >= 2:
		v.Ban, v.Reason = true, fmt.Sprintf("peer_fanout:%dh/%dp x%d/%v", v.Hosts, v.Ports, len(u.hits), fanoutRepeatWindow)
	}
	if !v.Ban {
		return v
	}
	if src := fanoutSrc[u.clientIP]; src != nil {
		pruneSeen(src, cutoff)
		v.Shared = len(src) >= fanoutSharedEmails
	}
	// Источник из bypass (наш релей/мост): за ним техпользователь вроде
	// sys_bridge_ru145 — сумма сотен людей, банить IP нельзя (banIP и так
	// откажет, но лог должен говорить правду).
	v.Protected = u.clientIP != "" && isProtectedIP(u.clientIP)
	delete(fanoutUsers, key) // после бана копим с нуля
	return v
}

// fanoutObserve учитывает строку access.log.
func fanoutObserve(clientIP, email, dest, tag string, now time.Time) fanoutVerdict {
	fanoutMu.Lock()
	defer fanoutMu.Unlock()

	fanoutCalls++
	if fanoutCalls%1000 == 0 {
		fanoutGC(now)
	}
	if clientIP != "" && email != "" {
		if fanoutSrc[clientIP] == nil {
			fanoutSrc[clientIP] = map[string]time.Time{}
		}
		fanoutSrc[clientIP][email] = now
	}
	proto, ip, port := fanoutPeer(dest)
	if ip == "" {
		return fanoutVerdict{}
	}
	key := email
	if key == "" {
		key = "ip:" + clientIP
	}
	u := fanoutUserFor(key, clientIP)
	u.peers[ip] = now
	u.ports[port] = now
	if proto == "udp" {
		u.udpPeers[ip] = now
	} else {
		u.tcpPeers[ip] = now
	}
	if isBlackholeTag(tag) {
		u.confirmed[ip] = now // xray сам распознал bittorrent к этому пиру
	}
	return fanoutEvaluate(key, u, now)
}

// fanoutConfirmPeers: IP, на которых DPI поймал торрент (ipset auto_peers),
// подтверждают недавних собеседников этих IP. Возвращает решения на бан.
func fanoutConfirmPeers(caught map[string]bool, now time.Time) []fanoutVerdict {
	fanoutMu.Lock()
	defer fanoutMu.Unlock()
	var out []fanoutVerdict
	for key, u := range fanoutUsers {
		changed := false
		for ip, t := range u.peers {
			if caught[ip] {
				if _, ok := u.confirmed[ip]; !ok {
					u.confirmed[ip] = t
					changed = true
				}
			}
		}
		if changed {
			if v := fanoutEvaluate(key, u, now); v.Ban {
				out = append(out, v)
			}
		}
	}
	return out
}

func fanoutGC(now time.Time) {
	cutoff := now.Add(-fanoutRepeatWindow)
	for k, u := range fanoutUsers {
		last := time.Time{}
		for _, m := range []map[string]time.Time{u.peers, u.confirmed} {
			for _, t := range m {
				if t.After(last) {
					last = t
				}
			}
		}
		for _, t := range u.hits {
			if t.After(last) {
				last = t
			}
		}
		if last.Before(cutoff) {
			delete(fanoutUsers, k)
		}
	}
	for k, m := range fanoutSrc {
		if pruneSeen(m, now.Add(-fanoutWindow)); len(m) == 0 {
			delete(fanoutSrc, k)
		}
	}
}

// fanoutDryRun (--fanout-dry-run): детектор только пишет «DRY-RUN забанил бы»
// в журнал, а банов не делает. Старые пути бана (тег TORRENT, домены) и DPI
// работают как обычно. Для обкатки порогов на живом флоте.
var (
	fanoutDryRun    = false
	fanoutDryLogged = map[string]time.Time{}
)

// fanoutApply: бан по решению детектора (общий источник — только лог).
func fanoutApply(v fanoutVerdict) {
	if !v.Ban {
		return
	}
	if v.Protected {
		log.Printf("PEER_FANOUT %s user=%s %s — источник в bypass (релей/мост), IP не баню", v.ClientIP, v.Key, v.Reason)
		return
	}
	if fanoutDryRun {
		fanoutMu.Lock()
		last, seen := fanoutDryLogged[v.Key]
		if !seen || time.Since(last) > banDuration {
			fanoutDryLogged[v.Key] = time.Now()
			fanoutMu.Unlock()
			log.Printf("PEER_FANOUT DRY-RUN забанил бы %s user=%s %s shared=%v", v.ClientIP, v.Key, v.Reason, v.Shared)
			return
		}
		fanoutMu.Unlock()
		return
	}
	if v.Shared || v.ClientIP == "" {
		log.Printf("PEER_FANOUT %s user=%s %s — источник общий (мост/NAT), IP не баню", v.ClientIP, v.Key, v.Reason)
		return
	}
	banIP(v.ClientIP, v.Reason+" user:"+v.Key)
}

// readCaughtPeers: содержимое ipset auto_peers_v4/v6 (пиры, пойманные DPI).
func readCaughtPeers() map[string]bool {
	caught := map[string]bool{}
	for _, set := range []string{"auto_peers_v4", "auto_peers_v6"} {
		out, err := exec.Command("ipset", "save", set).Output()
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) >= 3 && f[0] == "add" {
				caught[f[2]] = true
			}
		}
	}
	return caught
}

func startPeerConfirmMonitor() {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			if fanoutConfirmNeed <= 0 {
				continue
			}
			for _, v := range fanoutConfirmPeers(readCaughtPeers(), time.Now()) {
				fanoutApply(v)
			}
		}
	}()
}

// isTrackerHost: HTTPS-трекер по имени (tracker.se7en.ws, tracker2.x.org,
// retracker.local.ru). Внутри TLS announce не виден, но xray пишет SNI в
// access.log. Нужна первая метка ровно (re|bt)?tracker\d* и ещё минимум две
// метки — «tracker-api.my.com» и «tracker.gg» сюда не попадают.
func isTrackerHost(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return false
	}
	l := strings.TrimPrefix(strings.TrimPrefix(parts[0], "re"), "bt")
	if !strings.HasPrefix(l, "tracker") {
		return false
	}
	for _, c := range l[len("tracker"):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func monitorLog(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("log open error: %v", err)
		return
	}
	defer f.Close()
	f.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(f)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(200 * time.Millisecond)
				info, serr := os.Stat(path)
				if serr != nil {
					return
				}
				pos, _ := f.Seek(0, io.SeekCurrent)
				if info.Size() < pos {
					return
				}
				continue
			}
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		clientIP, destAddr, email, matched := parseXrayLogLine(line, torrentTag)

		if !matched {
			dest := extractDestFromLine(line)
			if dest != "" && isDomainTorrent(dest) {
				cip := extractClientIPFromLine(line)
				if cip != "" && !isProtectedIP(cip) {
					log.Printf("DOMAIN_TORRENT ban %s (dest=%s)", cip, dest)
					banIP(cip, "domain_torrent:"+dest)
				}
			}
			if dest != "" {
				fanoutApply(fanoutObserve(extractClientIPFromLine(line), extractEmailFromLine(line), dest, lineOutboundTag(line), time.Now()))
			}
			continue
		}

		if clientIP != "" && !isProtectedIP(clientIP) {
			reason := "xray_tag:" + torrentTag
			if email != "" {
				reason += " user:" + email
			}
			if destAddr != "" {
				reason += " dst:" + destAddr
			}
			banIP(clientIP, reason)
		}

		if destAddr != "" {
			d := strings.TrimPrefix(destAddr, "tcp:")
			d = strings.TrimPrefix(d, "udp:")
			destIP, _, err := net.SplitHostPort(d)
			if err == nil && net.ParseIP(destIP) != nil && !isProtectedIP(destIP) {
				blockPeer(destIP, "xray_dest:"+torrentTag)
			}
		}
	}
}

func startLogMonitor() {
	for _, path := range logFiles {
		go func(path string) {
			for {
				monitorLog(path)
				time.Sleep(2 * time.Second)
			}
		}(path)
		log.Printf("log monitor started: %s (tag=%s)", path, torrentTag)
	}
}

type connEntry struct {
	proto      string
	recvQ      int
	sendQ      int
	localAddr  string
	remoteAddr string
	state      string
	process    string
	remoteIP   string
	remotePort int
}

func parseNetstatOutput(out string) []connEntry {
	var entries []connEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Proto") || strings.HasPrefix(line, "Active") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		recvQ, _ := strconv.Atoi(fields[1])
		sendQ, _ := strconv.Atoi(fields[2])
		state := fields[5]
		process := ""
		if len(fields) >= 7 {
			process = fields[6]
		}
		remoteIP, remotePortStr, err := net.SplitHostPort(fields[4])
		if err != nil {
			remoteIP = fields[4]
		}
		remotePort, _ := strconv.Atoi(remotePortStr)
		entries = append(entries, connEntry{
			proto:      fields[0],
			recvQ:      recvQ,
			sendQ:      sendQ,
			localAddr:  fields[3],
			remoteAddr: fields[4],
			state:      state,
			process:    process,
			remoteIP:   remoteIP,
			remotePort: remotePort,
		})
	}
	return entries
}

func analyzeConnections(entries []connEntry) {
	finWaitCount := map[string]int{}
	multiConnCount := map[string]int{}
	largeSendQ := map[string]int{}

	for _, e := range entries {
		if e.remoteIP == "" || isProtectedIP(e.remoteIP) {
			continue
		}
		if e.state == "FIN_WAIT1" || e.state == "FIN_WAIT2" {
			finWaitCount[e.remoteIP]++
		}
		if e.state == "ESTABLISHED" {
			multiConnCount[e.remoteIP]++
			if e.sendQ > 5000 {
				largeSendQ[e.remoteIP]++
			}
		}
	}

	for ip, cnt := range finWaitCount {
		if !enableFinWait {
			break
		}
		if cnt >= finWaitThresh {
			finWaitMu.Lock()
			finWaitHit[ip]++
			hits := finWaitHit[ip]
			finWaitMu.Unlock()
			if hits >= 2 {
				finWaitMu.Lock()
				finWaitHit[ip] = 0
				finWaitMu.Unlock()
				banIP(ip, fmt.Sprintf("fin_wait_storm(%d)", cnt))
			}
		}
	}

	for ip, cnt := range multiConnCount {
		if cnt >= connThresh && largeSendQ[ip] >= sendQThresh {
			banIP(ip, fmt.Sprintf("multi_conn_large_sendq(conns=%d,sendq=%d)", cnt, largeSendQ[ip]))
		}
	}
}

func startNetstatMonitor() {
	if !enableNetstat {
		return
	}
	go func() {
		for {
			out, err := exec.Command("netstat", "-tunp").Output()
			if err == nil {
				analyzeConnections(parseNetstatOutput(string(out)))
			}
			time.Sleep(10 * time.Second)
		}
	}()
	log.Printf("netstat monitor started (finwait_thresh=%d)", finWaitThresh)
}

// sportSafe: правило по --sport (source-порт) можно ставить ТОЛЬКО для портов
// ниже эфемерного диапазона (32768–60999). Иначе легитимный клиент или форвард,
// у которого ОС выбрала случайный исходящий порт (напр. Transmission 51413),
// попал бы под DROP по source-порту. По --dport такие порты блокировать можно.
func sportSafe(port string) bool {
	hi := port
	if i := strings.IndexByte(port, ':'); i >= 0 {
		hi = port[i+1:]
	}
	n, err := strconv.Atoi(hi)
	if err != nil {
		return false
	}
	return n < 32768
}

func applyPortBlock() int {
	count := 0
	for _, ipt := range []string{"iptables", "ip6tables"} {
		for _, proto := range []string{"tcp", "udp"} {
			for _, port := range trackerPorts {
				if vpnPorts[port] {
					continue
				}
				for _, chain := range dpiHooks {
					dir := "--dport"
					if chain == "INPUT" {
						// INPUT ловим по source-порту — только если он не
						// эфемерный (иначе задели бы клиентов).
						if !sportSafe(port) {
							continue
						}
						dir = "--sport"
					}
					if exec.Command(ipt, "-A", chain, "-p", proto, dir, port, "-j", "DROP").Run() == nil {
						count++
					}
				}
			}
			for _, port := range clientPorts {
				if vpnPorts[port] {
					continue
				}
				// --dport безопасен для любых портов: блокируем «хостинг» торрент-порта.
				if exec.Command(ipt, "-A", "FORWARD", "-p", proto, "--dport", port, "-j", "DROP").Run() == nil {
					count++
				}
				// --sport только для неэфемерных портов, иначе рискуем клиентами.
				if sportSafe(port) {
					if exec.Command(ipt, "-A", "FORWARD", "-p", proto, "--sport", port, "-j", "DROP").Run() == nil {
						count++
					}
					if exec.Command(ipt, "-A", "INPUT", "-p", proto, "--sport", port, "-j", "DROP").Run() == nil {
						count++
					}
				}
			}
		}
	}
	return count
}

func applyDPI() int {
	// connbytes без учёта conntrack видит 0 байт → через сигнатуры шёл бы ВЕСЬ трафик.
	exec.Command("sysctl", "-qw", "net.netfilter.nf_conntrack_acct=1").Run()
	os.WriteFile("/etc/sysctl.d/90-torrent-blocker.conf", []byte("net.netfilter.nf_conntrack_acct=1\n"), 0644)
	count := 0
	for _, ipt := range []string{"iptables", "ip6tables"} {
		exec.Command(ipt, "-N", dpiChain).Run()
		exec.Command(ipt, "-N", "CATCH_TRACKER").Run()
		exec.Command(ipt, "-N", "CATCH_PEER").Run()
		sfx := "_v4"
		if ipt == "ip6tables" {
			sfx = "_v6"
		}
		for _, r := range catchChainRules(ipt, "CATCH_TRACKER", "auto_trackers"+sfx) {
			exec.Command(ipt, r...).Run()
		}
		for _, r := range catchChainRules(ipt, "CATCH_PEER", "auto_peers"+sfx) {
			exec.Command(ipt, r...).Run()
		}

		exec.Command(ipt, "-A", dpiChain, "-i", "lo", "-j", "RETURN").Run()
		exec.Command(ipt, "-A", dpiChain, "-o", "lo", "-j", "RETURN").Run()
		// ⚠️ Раньше здесь был RETURN для всего ESTABLISHED — сигнатуры видели только
		// первый пакет потока, а у TCP это пустой SYN: рукопожатие BT, announce и
		// info_hash не матчились НИКОГДА (на starry 0 срабатываний за месяц).
		// Теперь проверяем первые dpiInspectBytes каждого потока (connbytes), дальше
		// RETURN — дёшево и ловит полезную нагрузку TCP. Без connbytes — старый фолбэк.
		if exec.Command(ipt, connbytesSkipArgs()...).Run() != nil {
			log.Printf("%s: connbytes недоступен — DPI видит только первый пакет потока", ipt)
			exec.Command(ipt, "-A", dpiChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN").Run()
		}
		// Порт 80 в vpnPorts, и RETURN ниже отпускал ВСЕ HTTP-сигнатуры:
		// announce/info_hash/User-Agent клиентов на :80 не матчились никогда.
		// Живой uTorrent 3.6 (20 окт 2026) тянул веб-сид чистым HTTP на :80.
		// Поэтому до RETURN — HTTP-сигнатуры по --dport 80, только DROP.
		for _, r := range httpSigRules() {
			if exec.Command(ipt, r...).Run() == nil {
				count++
			}
		}
		for port := range vpnPorts {
			for _, proto := range []string{"tcp", "udp"} {
				exec.Command(ipt, "-A", dpiChain, "-p", proto, "--dport", port, "-j", "RETURN").Run()
				exec.Command(ipt, "-A", dpiChain, "-p", proto, "--sport", port, "-j", "RETURN").Run()
			}
		}
	}

	for _, r := range utpSynRules() {
		if exec.Command(r[0], r[1:]...).Run() == nil {
			count++
		}
	}
	for _, sig := range signatures {
		protos := []string{"tcp", "udp"}
		if sig.proto != "" {
			protos = []string{sig.proto}
		}
		for _, proto := range protos {
			args := []string{"-A", dpiChain, "-p", proto}
			if sig.dport > 0 {
				args = append(args, "--dport", strconv.Itoa(sig.dport))
			}
			args = append(args, "-m", "string", "--algo", "bm", "--to", "1500")
			if sig.hex != "" {
				args = append(args, "--hex-string", sig.hex)
			} else {
				args = append(args, "--string", sig.pattern)
			}
			target := "DROP"
			if sig.action == "TRACKER" {
				target = "CATCH_TRACKER"
			} else if sig.action == "PEER" {
				target = "CATCH_PEER"
			}
			args = append(args, "-j", target)
			for _, ipt := range []string{"iptables", "ip6tables"} {
				if exec.Command(ipt, args...).Run() == nil {
					count++
				}
			}
		}
	}
	ensureDPIHooks()
	return count
}

// httpSigRules: сигнатуры открытого HTTP (трекер, веб-сид, User-Agent клиента)
// по tcp --dport 80. Цель только DROP, без ipset: трекеры и веб-сиды сидят за
// Cloudflare, и занесение их IP в auto_trackers отрезало бы чужие сайты.
func httpSigRules() [][]string {
	var rules [][]string
	for _, sig := range signatures {
		if !sig.http {
			continue
		}
		args := []string{"-A", dpiChain, "-p", "tcp", "--dport", "80",
			"-m", "string", "--algo", "bm", "--to", "1500"}
		if sig.hex != "" {
			args = append(args, "--hex-string", sig.hex)
		} else {
			args = append(args, "--string", sig.pattern)
		}
		rules = append(rules, append(args, "-j", "DROP"))
	}
	return rules
}

// catchChainRules: CATCH_PEER/CATCH_TRACKER заносят dst в ipset и дропают.
// Но сигнатуры матчатся в обе стороны: на ВХОДЯЩЕМ пакете пир→нода dst — это
// адрес самой ноды или docker-контейнера за DNAT. Так 15 и 17 окт 2026 в
// auto_peers_v4 попал 172.30.44.2 (контейнер EE), и DROP в OUTPUT/FORWARD
// положил ноду целиком. Локальные и приватные dst — только DROP пакета, без SET.
func catchChainRules(ipt, chain, set string) [][]string {
	var rules [][]string
	rules = append(rules, []string{"-A", chain, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DROP"})
	nets := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8"}
	if ipt == "ip6tables" {
		nets = []string{"fc00::/7", "fe80::/10", "::1/128"}
	}
	for _, n := range nets {
		rules = append(rules, []string{"-A", chain, "-d", n, "-j", "DROP"})
	}
	rules = append(rules,
		[]string{"-A", chain, "-j", "SET", "--add-set", set, "dst"},
		[]string{"-A", chain, "-j", "DROP"})
	return rules
}

// Сколько байт каждого потока (в обе стороны) прогоняется через сигнатуры.
const dpiInspectBytes = 4096

func connbytesSkipArgs() []string {
	return []string{"-A", dpiChain, "-m", "connbytes", "--connbytes", strconv.Itoa(dpiInspectBytes+1) + ":",
		"--connbytes-dir", "both", "--connbytes-mode", "bytes", "-j", "RETURN"}
}

// uTP (BEP29) идёт поверх UDP, и его 20-байтный заголовок НЕ шифруется даже
// при включённом MSE. ST_SYN без расширений = ровно 20 байт полезной нагрузки
// с первым байтом 0x41 (type 4, ver 1). QUIC short-header (тоже 0x4x) не бывает
// первым пакетом потока, DNS/443 уже отпущены RETURN выше. Режем установку
// uTP-соединения с пиром — без него libtorrent/qBittorrent теряют основной транспорт.
func utpSynRules() [][]string {
	return [][]string{
		{"iptables", "-A", dpiChain, "-p", "udp", "-m", "conntrack", "--ctstate", "NEW",
			"-m", "length", "--length", "48", "-m", "u32", "--u32", "0>>22&0x3C@8>>24=0x41", "-j", "DROP"},
		{"ip6tables", "-A", dpiChain, "-p", "udp", "-m", "conntrack", "--ctstate", "NEW",
			"-m", "length", "--length", "68", "-m", "u32", "--u32", "48>>24=0x41", "-j", "DROP"},
	}
}

// Переход в DPI обязан стоять ПЕРВЫМ правилом хука: ufw (ufw-before-output) и
// docker (DOCKER-FORWARD) принимают трафик раньше, и при -A в конец цепочки DPI
// не видел ни ufw-нод, ни bridge-контейнеров. docker/ufw при перезапуске
// вставляют свои правила наверх — поэтому проверяем и чиним каждую минуту.
func ensureDPIHooks() {
	for _, chain := range dpiHooks {
		for _, ipt := range []string{"iptables", "ip6tables"} {
			out, err := exec.Command(ipt, "-S", chain).Output()
			if err != nil {
				continue
			}
			if dpiHookFirst(string(out), chain) {
				continue
			}
			for exec.Command(ipt, "-D", chain, "-j", dpiChain).Run() == nil {
			}
			exec.Command(ipt, "-I", chain, "1", "-j", dpiChain).Run()
		}
	}
}

// dpiHookFirst: первое правило цепочки (после строки политики -P/-N) — наш переход.
func dpiHookFirst(rules, chain string) bool {
	for _, l := range strings.Split(rules, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "-P ") || strings.HasPrefix(l, "-N ") {
			continue
		}
		return l == "-A "+chain+" -j "+dpiChain
	}
	return false
}

func getDPIDropCount() int64 {
	var total int64
	for _, ipt := range []string{"iptables", "ip6tables"} {
		out, _ := exec.Command(ipt, "-L", dpiChain, "-v", "-n", "-x").Output()
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Chain") || strings.HasPrefix(line, "pkts") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				n, _ := strconv.ParseInt(fields[0], 10, 64)
				total += n
			}
		}
	}
	return total
}

func getBanCount() int {
	blockedMu.Lock()
	defer blockedMu.Unlock()
	return len(blockedIPs)
}

func getPeerCount() int {
	peerMu.Lock()
	defer peerMu.Unlock()
	return len(peerIPs)
}

func startCleanupRoutine() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			now := time.Now()
			ensureDPIHooks()

			blockedMu.Lock()
			var toUnban []string
			for ip, info := range blockedIPs {
				if now.After(info.Until) {
					toUnban = append(toUnban, ip)
				}
			}
			blockedMu.Unlock()
			for _, ip := range toUnban {
				unbanIP(ip)
			}

			peerMu.Lock()
			var toUnpeer []string
			for ip, info := range peerIPs {
				if now.After(info.Until) {
					toUnpeer = append(toUnpeer, ip)
				}
			}
			peerMu.Unlock()
			for _, ip := range toUnpeer {
				unbanPeer(ip)
			}
		}
	}()
}

func printStatus() {
	fmt.Printf("DPI dropped:   %d\n", getDPIDropCount())
	fmt.Printf("banned IPs:    %d\n", getBanCount())
	fmt.Printf("blocked peers: %d\n", getPeerCount())

	blockedMu.Lock()
	if len(blockedIPs) > 0 {
		fmt.Println("\n--- Banned IPs ---")
		for ip, info := range blockedIPs {
			fmt.Printf("  %-20s  until=%-25s  reason=%s\n", ip, info.Until.Format("2006-01-02 15:04:05"), info.Reason)
		}
	}
	blockedMu.Unlock()

	peerMu.Lock()
	if len(peerIPs) > 0 {
		fmt.Println("\n--- Blocked Peers ---")
		for ip, info := range peerIPs {
			fmt.Printf("  %-20s  until=%-25s  reason=%s\n", ip, info.Until.Format("2006-01-02 15:04:05"), info.Reason)
		}
	}
	peerMu.Unlock()

	out2, _ := exec.Command("iptables", "-t", banTable, "-L", banChain, "-v", "-n", "-x").Output()
	if len(out2) > 0 {
		fmt.Printf("\n--- iptables raw/%s ---\n%s\n", banChain, strings.TrimSpace(string(out2)))
	}
	out3, _ := exec.Command("ipset", "list", "auto_peers_v4").Output()
	if len(out3) > 0 {
		fmt.Printf("\n--- ipset auto_peers_v4 ---\n%s\n", strings.TrimSpace(string(out3)))
	}
	out4, _ := exec.Command("ipset", "list", "auto_trackers_v4").Output()
	if len(out4) > 0 {
		fmt.Printf("\n--- ipset auto_trackers_v4 ---\n%s\n", strings.TrimSpace(string(out4)))
	}
}

func main() {
	if os.Getuid() != 0 {
		log.Fatal("run as root")
	}
	ensureDependencies()

	action := "start"
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--log":
			if i+1 < len(os.Args) {
				logFiles = append(logFiles, os.Args[i+1])
				i++
			}
		case "--tag":
			if i+1 < len(os.Args) {
				torrentTag = os.Args[i+1]
				i++
			}
		case "--ban-duration":
			if i+1 < len(os.Args) {
				if m, err := strconv.Atoi(os.Args[i+1]); err == nil {
					banDuration = time.Duration(m) * time.Minute
				}
				i++
			}
		case "--bypass":
			// принимает и одиночные IP, и CIDR-подсети (мосты/релеи/панель)
			if i+1 < len(os.Args) {
				for _, ip := range strings.Split(os.Args[i+1], ",") {
					addBypassIP(ip)
				}
				i++
			}
		case "--bypass-net":
			if i+1 < len(os.Args) {
				for _, n := range strings.Split(os.Args[i+1], ",") {
					addBypassIP(n)
				}
				i++
			}
		case "--bypass-file":
			if i+1 < len(os.Args) {
				bypassFile = os.Args[i+1]
				i++
			}
		case "--vpn-port":
			if i+1 < len(os.Args) {
				for _, p := range strings.Split(os.Args[i+1], ",") {
					p = strings.TrimSpace(p)
					if p != "" {
						vpnPorts[p] = true
					}
				}
				i++
			}
		case "--fanout":
			if i+1 < len(os.Args) {
				if n, err := strconv.Atoi(os.Args[i+1]); err == nil {
					fanoutThresh = n
				}
				i++
			}
		case "--fanout-window":
			if i+1 < len(os.Args) {
				if m, err := strconv.Atoi(os.Args[i+1]); err == nil && m > 0 {
					fanoutWindow = time.Duration(m) * time.Minute
				}
				i++
			}
		case "--fanout-dry-run":
			fanoutDryRun = true
		case "--fanout-ports":
			if i+1 < len(os.Args) {
				if n, err := strconv.Atoi(os.Args[i+1]); err == nil {
					fanoutPortThresh = n
				}
				i++
			}
		case "--confirm-peers":
			if i+1 < len(os.Args) {
				if n, err := strconv.Atoi(os.Args[i+1]); err == nil {
					fanoutConfirmNeed = n
				}
				i++
			}
		case "--netstat":
			// осознанное включение эвристик по числу соединений (см. предупреждение выше)
			enableNetstat = true
		case "--finwait-ban":
			enableFinWait = true
		case "--no-netstat":
			// оставлено для совместимости: netstat и так выключен по умолчанию
			enableNetstat = false
		case "--no-finwait-ban":
			enableFinWait = false
		case "--finwait-thresh":
			if i+1 < len(os.Args) {
				if n, err := strconv.Atoi(os.Args[i+1]); err == nil {
					finWaitThresh = n
				}
				i++
			}
		case "--conn-thresh":
			if i+1 < len(os.Args) {
				if n, err := strconv.Atoi(os.Args[i+1]); err == nil {
					connThresh = n
				}
				i++
			}
		case "--sendq-thresh":
			if i+1 < len(os.Args) {
				if n, err := strconv.Atoi(os.Args[i+1]); err == nil {
					sendQThresh = n
				}
				i++
			}
		case "ban":
			if i+1 < len(os.Args) {
				ip := os.Args[i+1]
				i++
				initBanChain()
				banIP(ip, "manual")
				fmt.Printf("banned %s\n", ip)
				return
			}
		case "unban":
			if i+1 < len(os.Args) {
				ip := os.Args[i+1]
				i++
				loadStorage()
				unbanIP(ip)
				fmt.Printf("unbanned %s\n", ip)
				return
			}
		case "stop", "off", "disable", "start", "status", "stats":
			action = os.Args[i]
		}
	}

	switch action {
	case "stop", "off", "disable":
		cleanup()
		fmt.Println("torrent blocker disabled")
		return
	case "status", "stats":
		loadStorage()
		printStatus()
		return
	}

	// Собираем белый список ДО старта мониторов: свои адреса ноды + постоянный
	// файл мостов/релеев. Без этого netstat-эвристики (если их включат) и даже
	// разбор логов могли бы задеть свою инфраструктуру.
	addLocalIPs()
	loadBypassFile(bypassFile)

	cleanup()
	initBanChain()
	initPeerChain()
	loadStorage()
	portRules := applyPortBlock()
	dpiRules := applyDPI()
	startLogMonitor()
	startPeerConfirmMonitor()
	startNetstatMonitor()
	startCleanupRoutine()

	fmt.Printf("torrent blocker started: %d port + %d DPI rules, ban=%v\n", portRules, dpiRules, banDuration)
	for _, path := range logFiles {
		fmt.Printf("monitoring log: %s (tag=%s)\n", path, torrentTag)
	}
	if enableNetstat {
		fmt.Printf("⚠️  netstat=ON finwait_ban=%v finwait_thresh=%d conn_thresh=%d sendq_thresh=%d — риск ложных банов мостов\n",
			enableFinWait, finWaitThresh, connThresh, sendQThresh)
	} else {
		fmt.Printf("netstat=OFF (банится только реальный торрент: тег %s + DPI); bypass-file=%s\n",
			torrentTag, bypassFile)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case s := <-sig:
			if s == syscall.SIGHUP {
				// перечитать белый список без перезапуска (добавили мост/релей)
				loadBypassFile(bypassFile)
				continue
			}
			cleanup()
			fmt.Println("\ntorrent blocker stopped")
			return
		case <-ticker.C:
			peerMu.Lock()
			pc := len(peerIPs)
			peerMu.Unlock()
			fmt.Printf("[%s] DPI:%d | banned:%d | peers:%d\n",
				time.Now().Format("15:04:05"), getDPIDropCount(), getBanCount(), pc)
		}
	}
}
