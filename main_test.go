package main

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// resetBypass приводит белый список к «чистому» виду перед сценарием.
func resetBypass() {
	bypassMu.Lock()
	bypassIPs = map[string]bool{"127.0.0.1": true, "::1": true}
	bypassNets = nil
	bypassMu.Unlock()
}

// Реальный набор нашей инфраструктуры, какой лежал бы в bypass.txt.
var infraBypass = []string{
	"89.223.124.211",  // релей RU (Timeweb)
	"188.225.43.25",   // DNAT-воронка
	"188.225.43.74",   // DNAT-воронка
	"201.10.79.0/24",  // EE-воронки (VIP .48/.51/.74/.2xx)
	"5.175.178.0/24",  // чистые мосты (.48/.51/.253)
	"5.231.105.0/24",  // запасные мосты
	"2.27.243.0/24",   // мосты t7/t8
	"77.90.185.34",    // адрес самой DE-ноды (пример own-IP)
}

// ── Мосты/релеи/своя инфраструктура НИКОГДА не должны попадать под бан ───────
func TestInfraNeverBanned(t *testing.T) {
	resetBypass()
	for _, e := range infraBypass {
		addBypassIP(e)
	}

	mustProtect := []string{
		// наша инфраструктура из bypass
		"89.223.124.211",
		"188.225.43.25",
		"201.10.79.48", "201.10.79.51", "201.10.79.215", // внутри /24
		"5.175.178.48", "5.175.178.51", "5.175.178.253",
		"5.231.105.191", "5.231.105.248",
		"2.27.243.34", "2.27.243.35",
		"77.90.185.34",
		// приватные / служебные диапазоны — защищены в коде без bypass
		"10.0.0.1", "10.255.255.254",
		"172.16.0.1", "172.31.255.254",
		"192.168.1.1",
		"100.64.0.1", "100.127.255.254", // CGNAT
		"169.254.0.1",                   // link-local
		"127.0.0.1",
		"172.17.0.1", // docker-мост (частая жертва)
		"::1", "fc00::1", "fe80::1",
	}
	for _, ip := range mustProtect {
		if !isProtectedIP(ip) {
			t.Errorf("НЕБЕЗОПАСНО: %s НЕ защищён — блокер мог бы его забанить", ip)
		}
	}
}

// Публичный торрент-пир, которого в bypass нет, защищён быть НЕ должен —
// иначе блокер вообще ничего не ловит.
func TestPublicPeerNotProtected(t *testing.T) {
	resetBypass()
	for _, e := range infraBypass {
		addBypassIP(e)
	}
	for _, ip := range []string{"1.2.3.4", "203.0.113.5", "45.11.22.33"} {
		if isProtectedIP(ip) {
			t.Errorf("%s защищён, хотя это публичный пир — торренты не будут ловиться", ip)
		}
	}
}

// banIP для защищённого адреса обязан выйти РАНЬШЕ любого iptables-вызова
// (проверяем, что в состоянии блокера он не появился).
func TestBanIPShortCircuitsProtected(t *testing.T) {
	resetBypass()
	blockedMu.Lock()
	blockedIPs = map[string]*blockInfo{}
	blockedMu.Unlock()

	for _, ip := range []string{"10.0.0.1", "89.223.124.211", "172.17.0.1"} {
		addBypassIP("89.223.124.211")
		banIP(ip, "test")
		blockedMu.Lock()
		_, exists := blockedIPs[ip]
		blockedMu.Unlock()
		if exists {
			t.Errorf("НЕБЕЗОПАСНО: banIP забанил защищённый %s", ip)
		}
	}
}

// ── Порты мостов/нод не должны блокироваться ────────────────────────────────
func TestBridgePortsExcluded(t *testing.T) {
	bridgePorts := []string{
		"443", "3443", "8443", "2096", "4443",
		"2053", "2083", "2087", "8080",
		"22", "53", "80", "853",
		"500", "1194", "4500", "51820",
	}
	for _, p := range bridgePorts {
		if !vpnPorts[p] {
			t.Errorf("НЕБЕЗОПАСНО: порт моста/ноды %s НЕ в vpnPorts — DPI и блок портов его тронут", p)
		}
	}

	// Ни один торрент-порт не должен совпадать с портом моста.
	for _, tp := range append(append([]string{}, trackerPorts...), clientPorts...) {
		for _, bp := range bridgePorts {
			if portsOverlap(tp, bp) {
				t.Errorf("НЕБЕЗОПАСНО: торрент-порт %s пересекается с портом моста %s", tp, bp)
			}
		}
	}

	// Ни один торрент-порт из эфемерного диапазона (>=32768) не должен
	// блокироваться по --sport — иначе клиент/форвад со случайным исходящим
	// портом попал бы под DROP. sportSafe — это тот самый предохранитель.
	for _, tp := range append(append([]string{}, trackerPorts...), clientPorts...) {
		lo, hi := portRange(tp)
		if hi >= 32768 && sportSafe(tp) {
			t.Errorf("порт %s (%d-%d) блокируется по --sport в эфемерном диапазоне — риск для клиентов", tp, lo, hi)
		}
	}

	// Проверяем сам предохранитель.
	if !sportSafe("6969") || !sportSafe("6881:6999") {
		t.Errorf("sportSafe ошибочно запретил --sport для неэфемерного порта")
	}
	if sportSafe("51413") {
		t.Errorf("sportSafe разрешил --sport для эфемерного 51413 — риск для клиентов")
	}
}

func portRange(p string) (int, int) {
	if i := strings.IndexByte(p, ':'); i >= 0 {
		lo, _ := strconv.Atoi(p[:i])
		hi, _ := strconv.Atoi(p[i+1:])
		return lo, hi
	}
	v, _ := strconv.Atoi(p)
	return v, v
}

func portsOverlap(a, b string) bool {
	al, ah := portRange(a)
	bl, bh := portRange(b)
	return al <= bh && bl <= ah
}

// ── Торренты ДОЛЖНЫ ловиться: ключевые сигнатуры на месте ────────────────────
func TestTorrentSignaturesPresent(t *testing.T) {
	needPattern := []string{
		"d1:ad2:id20:",           // DHT
		"1:q9:get_peers",         // DHT get_peers
		"1:q13:announce_peer",    // DHT announce_peer
		"11:ut_metadata",         // BEP9 метаданные
		"5:ut_pex",               // PEX
		"info_hash=",             // HTTP-трекер
		"urn:btih:",              // magnet / info-hash
		"BT-SEARCH * HTTP/1.1",   // LSD
	}
	needHex := []string{
		"|13426974546f7272656e742070726f746f636f6c|", // "\x13BitTorrent protocol"
		"|0000041727101980|",                          // UDP-трекер connect
	}
	haveP := map[string]bool{}
	haveH := map[string]bool{}
	for _, s := range signatures {
		if s.pattern != "" {
			haveP[s.pattern] = true
		}
		if s.hex != "" {
			haveH[s.hex] = true
		}
	}
	for _, p := range needPattern {
		if !haveP[p] {
			t.Errorf("пропала торрент-сигнатура: %q", p)
		}
	}
	for _, h := range needHex {
		if !haveH[h] {
			t.Errorf("пропала торрент hex-сигнатура: %q", h)
		}
	}
}

// ── Доменный классификатор: торренты ловим, своё не трогаем ──────────────────
func TestDomainClassifier(t *testing.T) {
	torrent := []string{
		"rutracker.org", "1337x.to", "nyaa.si",
		"tracker.opentrackr.org", "router.bittorrent.com",
		"sub.thepiratebay.org",
	}
	for _, d := range torrent {
		if !isDomainTorrent(d) {
			t.Errorf("торрент-домен %s НЕ распознан", d)
		}
	}
	safe := []string{
		"vk.com", "vkvideo.ru", "google.com", "googleapis.com",
		"yandex.ru", "wildberries.ru",
		// наша инфраструктура/SNI/панель — не должны считаться торрентом
		"lavanda.eclipse-cloud.xyz", "polar.safeeclipse.de",
		"panel.boost34.online", "sub.safeeclipse.ru",
	}
	for _, d := range safe {
		if isDomainTorrent(d) {
			t.Errorf("НЕБЕЗОПАСНО: свой/легитимный домен %s ошибочно распознан как торрент", d)
		}
	}
}

// ── Разбор access.log xray ──────────────────────────────────────────────────
func TestXrayLogParse(t *testing.T) {
	tag := "TORRENT"

	line := "2026/09/19 12:00:00 from 203.0.113.5:54321 accepted tcp:1.2.3.4:6881 [vless-443 >> TORRENT] email: user42"
	cip, dst, email, matched := parseXrayLogLine(line, tag)
	if !matched {
		t.Fatalf("строка с тегом TORRENT не распозналась")
	}
	if cip != "203.0.113.5" {
		t.Errorf("client IP = %q, ожидали 203.0.113.5", cip)
	}
	if email != "user42" {
		t.Errorf("email = %q, ожидали user42", email)
	}
	_ = dst

	// Обычный трафик (тег direct) не должен матчиться по тегу...
	normal := "2026/09/19 12:00:01 from 198.51.100.7:443 accepted tcp:example.com:443 [vless-443 >> direct] email: user7"
	if _, _, _, m := parseXrayLogLine(normal, tag); m {
		t.Errorf("обычная строка (direct) ошибочно принята за торрент")
	}
	// ...но если direct-строка идёт на торрент-домен — ловится доменным путём.
	if d := extractDestFromLine("from 198.51.100.7:1 accepted tcp:rutracker.org:443 [>> direct]"); !isDomainTorrent(d) {
		t.Errorf("доменный путь не поймал rutracker.org (dest=%q)", d)
	}
}

// Переход в DPI должен стоять первым: иначе ufw/docker принимают трафик раньше.
func TestDPIHookFirst(t *testing.T) {
	first := "-P OUTPUT ACCEPT\n-A OUTPUT -j TORRENT_DPI\n-A OUTPUT -j ufw-before-output\n"
	if !dpiHookFirst(first, "OUTPUT") {
		t.Error("наш переход первым — должно быть true")
	}
	late := "-P FORWARD ACCEPT\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j TORRENT_DPI\n"
	if dpiHookFirst(late, "FORWARD") {
		t.Error("переход после DOCKER-FORWARD — должно быть false (DPI не видит bridge-контейнеры)")
	}
	if dpiHookFirst("-P INPUT ACCEPT\n", "INPUT") {
		t.Error("пустая цепочка — перехода нет")
	}
}

// Сигнатуры обязаны видеть полезную нагрузку TCP (первые килобайты потока),
// а не только SYN; uTP SYN режется по незашифрованному заголовку.
func TestDPIInspectsPayloadAndUTP(t *testing.T) {
	cb := strings.Join(connbytesSkipArgs(), " ")
	if !strings.Contains(cb, "--connbytes "+strconv.Itoa(dpiInspectBytes+1)+":") || !strings.Contains(cb, "-j RETURN") {
		t.Errorf("connbytes-правило: %s", cb)
	}
	rules := utpSynRules()
	if len(rules) != 2 || rules[0][0] != "iptables" || rules[1][0] != "ip6tables" {
		t.Fatalf("ожидались v4+v6 правила uTP, есть %v", rules)
	}
	v4 := strings.Join(rules[0], " ")
	for _, want := range []string{"--ctstate NEW", "--length 48", "0>>22&0x3C@8>>24=0x41", "-j DROP"} {
		if !strings.Contains(v4, want) {
			t.Errorf("uTP v4 без %q: %s", want, v4)
		}
	}
	if !strings.Contains(strings.Join(rules[1], " "), "--length 68") {
		t.Error("uTP v6: длина 40+8+20=68")
	}
}

// ── Живой захват uTorrent 3.6.0 (20 окт 2026, без VPN, Ethernet) ─────────────
// Байты взяты из pcap как есть. Каждый образец обязан матчиться сигнатурой
// (так же, как -m string --to 1500), а HTTP — ещё и правилом по --dport 80.
func sigMatches(proto string, dport int, payload []byte) []string {
	var hit []string
	for _, s := range signatures {
		if s.proto != proto || (s.dport != 0 && s.dport != dport) {
			continue
		}
		var needle []byte
		if s.hex != "" {
			var err error
			needle, err = hex.DecodeString(strings.Trim(s.hex, "|"))
			if err != nil {
				continue
			}
		} else {
			needle = []byte(s.pattern)
		}
		if bytes.Contains(payload, needle) {
			hit = append(hit, s.pattern+s.hex)
		}
	}
	return hit
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLiveUTorrentCapture(t *testing.T) {
	cases := []struct {
		name    string
		proto   string
		dport   int
		payload []byte
	}{
		{"BT-хендшейк (peer_id -UT360W-)", "tcp", 11720,
			append([]byte("\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x05"), make([]byte, 40)...)},
		{"расширенный хендшейк BEP10", "tcp", 11720,
			[]byte("\x00\x00\x019\x14\x00d1:ei0e4:ipv44:%\xe6\x94p12:complete_agoi23e1:md11:upload_onlyi3e11:lt_donthavei7e12:ut_holepunchi4e11:ut_metadatai2e6:ut_pexi1ee")},
		{"PEX посреди потока", "tcp", 13070,
			[]byte("\x00\x00\x00\xa2\x14\x01d5:added78:)\xb6\xc2\x38*\x1a\xc2\xbb7:added.f13:\x00\x00\x00\x007:dropped0:e")},
		{"DHT find_node (v=UT)", "udp", 64276,
			[]byte("d1:ad2:id20:\x16\xe4\x1e\x93gB\x96\x1b{D!\x0f#\xfa-\x9a\xb1\x06+\xbc6:target20:\x16\xe4\x1e\x93gB\x96\x1b{D!\x0f#\xfa-\x9a\xb1\x06+\xbce1:q9:find_node1:t4:abcd1:v4:UT\x00\x001:y1:qe")},
		{"UDP-трекер connect", "udp", 8086, mustHex(t, "000004172710198000000000101d2f4d")},
		{"веб-сид HTTP GET (BEP19)", "tcp", 80,
			[]byte("GET /c/GTA%20San%20Andreas/Data/data-20.bin HTTP/1.1\r\nHost: vasyan.space\r\nUser-Agent: BTWebClient/360S\r\nConnection: keep-alive\r\nRange: bytes=0-16383\r\n\r\n")},
	}
	for _, c := range cases {
		if len(sigMatches(c.proto, c.dport, c.payload)) == 0 {
			t.Errorf("живой образец НЕ пойман: %s", c.name)
		}
	}

	// Веб-сид идёт на :80, а 80 в vpnPorts → без отдельного правила его бы отпустил RETURN.
	found := false
	for _, r := range httpSigRules() {
		s := strings.Join(r, " ")
		if strings.Contains(s, "--dport 80") && strings.Contains(s, "BTWebClient") && strings.HasSuffix(s, "-j DROP") {
			found = true
		}
		if strings.Contains(s, "CATCH_") {
			t.Errorf("HTTP-правило на :80 не должно заносить IP в ipset (Cloudflare): %s", s)
		}
	}
	if !found {
		t.Error("нет правила --dport 80 для User-Agent: BTWebClient")
	}

	// uTP SYN из захвата: 20 байт, первый байт 0x41 → IP-пакет 48 байт (u32-правило).
	syn := mustHex(t, "410076fa0c4942ce0000000000100000e2830000")
	if len(syn) != 20 || syn[0] != 0x41 {
		t.Fatalf("образец uTP SYN испорчен")
	}
	if !strings.Contains(strings.Join(utpSynRules()[0], " "), "--length 48") {
		t.Error("uTP SYN uTorrent = 20+8+20 = 48 байт, правило должно бить ровно эту длину")
	}
}

// HTTPS-трекеры и телеметрия uTorrent видны только по SNI в access.log.
func TestTrackerHostsFromCapture(t *testing.T) {
	for _, d := range []string{"tracker.se7en.ws", "tracker.7launcher.com", "tracker.7launcher.ru",
		"retracker.local.ru", "tracker2.example.org", "ledger.bt.co", "x-666.b-0.ad.bench.utorrent.com"} {
		if !isDomainTorrent(d) {
			t.Errorf("не распознан: %s", d)
		}
	}
	for _, d := range []string{"tracker-api.my.com", "tracker.gg", "bt.com", "debt.co", "trackerlist.example.com",
		"cdn.tracker-stats.io", "panel.boost34.online"} {
		if isDomainTorrent(d) {
			t.Errorf("НЕБЕЗОПАСНО: %s ошибочно принят за трекер", d)
		}
	}
}

// Входящий пакет пир→нода матчит PEER-сигнатуру с dst = нода/контейнер.
// Такой dst нельзя заносить в ipset (инцидент EE 15/17 окт: 172.30.44.2).
func TestCatchChainNeverPoisonsLocal(t *testing.T) {
	for _, ipt := range []string{"iptables", "ip6tables"} {
		rules := catchChainRules(ipt, "CATCH_PEER", "auto_peers_v4")
		setAt, localAt, privAt := -1, -1, -1
		for i, r := range rules {
			s := strings.Join(r, " ")
			switch {
			case strings.Contains(s, "--add-set"):
				setAt = i
			case strings.Contains(s, "--dst-type LOCAL"):
				localAt = i
			case strings.Contains(s, "-d 172.16.0.0/12") || strings.Contains(s, "-d fc00::/7"):
				privAt = i
			}
		}
		if setAt < 0 || localAt < 0 || privAt < 0 || localAt > setAt || privAt > setAt {
			t.Errorf("%s: защита локальных/приватных dst должна стоять ДО SET: %v", ipt, rules)
		}
		if last := strings.Join(rules[len(rules)-1], " "); last != "-A CATCH_PEER -j DROP" {
			t.Errorf("%s: последним должен быть DROP, есть %q", ipt, last)
		}
	}
}
