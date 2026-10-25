package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
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
	"11.1.124.211",  // релей RU (Timeweb)
	"11.4.43.25",    // DNAT-воронка
	"11.4.43.74",    // DNAT-воронка
	"11.2.79.0/24",  // EE-воронки (VIP .48/.51/.74/.2xx)
	"11.3.178.0/24", // чистые мосты (.48/.51/.253)
	"11.5.105.0/24", // запасные мосты
	"11.6.243.0/24", // мосты t7/t8
	"11.7.185.34",   // адрес самой DE-ноды (пример own-IP)
}

// ── Мосты/релеи/своя инфраструктура НИКОГДА не должны попадать под бан ───────
func TestInfraNeverBanned(t *testing.T) {
	resetBypass()
	for _, e := range infraBypass {
		addBypassIP(e)
	}

	mustProtect := []string{
		// наша инфраструктура из bypass
		"11.1.124.211",
		"11.4.43.25",
		"11.2.79.48", "11.2.79.51", "11.2.79.215", // внутри /24
		"11.3.178.48", "11.3.178.51", "11.3.178.253",
		"11.5.105.191", "11.5.105.248",
		"11.6.243.34", "11.6.243.35",
		"11.7.185.34",
		// приватные / служебные диапазоны — защищены в коде без bypass
		"10.0.0.1", "10.255.255.254",
		"172.16.0.1", "172.31.255.254",
		"192.168.1.1",
		"100.64.0.1", "100.127.255.254", // CGNAT
		"169.254.0.1", // link-local
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

	for _, ip := range []string{"10.0.0.1", "11.1.124.211", "172.17.0.1"} {
		addBypassIP("11.1.124.211")
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
		"d1:ad2:id20:",         // DHT
		"1:q9:get_peers",       // DHT get_peers
		"1:q13:announce_peer",  // DHT announce_peer
		"11:ut_metadata",       // BEP9 метаданные
		"5:ut_pex",             // PEX
		"info_hash=",           // HTTP-трекер
		"urn:btih:",            // magnet / info-hash
		"BT-SEARCH * HTTP/1.1", // LSD
	}
	needHex := []string{
		"|13426974546f7272656e742070726f746f636f6c|", // "\x13BitTorrent protocol"
		"|0000041727101980|",                         // UDP-трекер connect
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
		"lavanda.example-cdn.xyz", "polar.example-vpn.de",
		"panel.example-vpn.net", "sub.example-vpn.ru",
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
		// uFiler (libtorrent -LT1140-) через VLESS на тестовой ноде: 20 байт uTP ST_DATA + хендшейк.
		{"uFiler: BT-хендшейк внутри uTP", "udp", 10786,
			mustHex(t, "01012859f755c19622c7ecd8000fece71ff8145000"+"13426974546f7272656e742070726f746f636f6c"+"0000000000100005"+"2d4c54313134302d")},
		{"uFiler: DHT get_peers (v=LT)", "udp", 13932,
			[]byte("d1:ad2:id20:aaaaaaaaaaaaaaaaaaaa9:info_hash20:bbbbbbbbbbbbbbbbbbbbe1:q9:get_peers1:v4:LT111:y1:qe")},
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
	for _, d := range []string{"tcp:tracker.se7en.ws:443", "tcp:tracker.7launcher.com:443", "tracker.7launcher.ru",
		"udp:retracker.local.ru:6969", "tcp:tracker2.example.org:2710", "tcp:tracker.nanoha.org:443",
		"ledger.bt.co", "x-666.b-0.ad.bench.utorrent.com"} {
		if !isDomainTorrent(d) {
			t.Errorf("не распознан: %s", d)
		}
	}
	// Живые ложные баны 21 окт: аналитика с меткой tracker на 443.
	for _, d := range []string{"tcp:tracker.comagic.ru:443", "tcp:tracker.aviasales.com:443", "tcp:tracker.zmaticoo.com:443",
		"tcp:tracker.example.com:80", "tracker-api.my.com", "tracker.gg", "bt.com", "debt.co", "trackerlist.example.com",
		"cdn.tracker-stats.io", "panel.example-vpn.net"} {
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

// ── Детектор торрент-юзеров: живой access.log тестовой ноде, 20 окт 2026 ──────────
func resetFanout() {
	fanoutMu.Lock()
	fanoutUsers = map[string]*fanoutUser{}
	fanoutSrc = map[string]map[string]time.Time{}
	fanoutMu.Unlock()
}

func feedLine(line string, now time.Time) fanoutVerdict {
	return fanoutObserve(extractClientIPFromLine(line), extractEmailFromLine(line), extractDestFromLine(line), lineOutboundTag(line), now)
}

const pcLine = "2026/10/20 20:09:05.320208 from 11.8.148.112:%d accepted tcp:%s [VLESS_TCP_TLS_EE_443_clone >> DIRECT] email: 4"

// Шифрованный qBittorrent: только DIRECT, без подтверждений → бан по второму разлёту.
func TestFanoutEncryptedNeedsRepeat(t *testing.T) {
	resetBypass()
	resetFanout()
	t0 := time.Date(2026, 10, 20, 20, 9, 5, 0, time.UTC)
	live := []string{"11.9.75.195:24581", "11.10.222.77:33204", "11.11.37.81:7210",
		"11.12.13.140:47335", "11.13.16.130:11720", "11.14.38.128:36709", "11.15.25.249:2279"}
	feed := func(round, n int) (v fanoutVerdict, at int) {
		for i := 0; i < n; i++ {
			p := fmt.Sprintf("81.%d.%d.7:%d", round, i, 10000+round*100+i)
			if round == 0 && i < len(live) {
				p = live[i]
			}
			v = feedLine(fmt.Sprintf(pcLine, 50000+i, p), t0.Add(time.Duration(round*60+i)*time.Second))
			if v.Ban {
				return v, i
			}
		}
		return v, -1
	}
	if v, at := feed(0, fanoutThresh); v.Ban {
		t.Fatalf("первый разлёт без подтверждения не должен банить (сработало на %d): %+v", at, v)
	}
	v, at := feed(1, fanoutThresh)
	if !v.Ban || v.Shared || v.ClientIP != "11.8.148.112" {
		t.Fatalf("второй разлёт за 15 мин должен банить: %+v (at=%d)", v, at)
	}
}

// uFiler/MediaGet: xray сам отправил пиров в BLOCK → 3 подтверждения = бан сразу.
func TestFanoutXrayBlackholeConfirms(t *testing.T) {
	resetBypass()
	resetFanout()
	t0 := time.Now()
	blk := "20:24:10.643204 from 11.8.148.112:%d accepted tcp:%s [VLESS_TCP_TLS_EE_443_clone -> BLOCK] email: 4"
	peers := []string{"11.9.75.195:24581", "11.16.56.119:3879", "11.17.111.162:9999"}
	var v fanoutVerdict
	for i, p := range peers {
		v = feedLine(fmt.Sprintf(blk, 45819+i, p), t0)
	}
	if !v.Ban || v.Confirmed != 3 {
		t.Fatalf("3 пира в BLOCK — бан: %+v", v)
	}
	// BLOCK рекламы (домен), SMTP (25) и приватных — не подтверждение.
	resetFanout()
	for i, d := range []string{"tcp:ads.example.com:443", "tcp:8.8.8.8:25", "tcp:10.1.2.3:40000", "tcp:1.1.1.1:443"} {
		if v := feedLine(fmt.Sprintf("from 9.9.9.9:%d accepted %s [x -> BLOCK] email: 7", i, d), t0); v.Ban || v.Confirmed > 0 {
			t.Fatalf("НЕБЕЗОПАСНО: %s засчитан как торрент: %+v", d, v)
		}
	}
}

// DPI поймал пиров (ipset auto_peers) → их собеседник подтверждён.
func TestFanoutDPIConfirms(t *testing.T) {
	resetBypass()
	resetFanout()
	t0 := time.Now()
	caught := map[string]bool{}
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("83.9.88.%d", 10+i)
		feedLine(fmt.Sprintf(pcLine, 100+i, ip+":13070"), t0)
		if i < 3 {
			caught[ip] = true
		}
	}
	vs := fanoutConfirmPeers(caught, t0.Add(10*time.Second))
	if len(vs) != 1 || !vs[0].Ban || vs[0].ClientIP != "11.8.148.112" {
		t.Fatalf("3 пира из auto_peers должны дать бан: %+v", vs)
	}
}

// Karagiannis: один пир и по TCP, и по UDP.
func TestFanoutTCPUDPPair(t *testing.T) {
	resetBypass()
	resetFanout()
	t0 := time.Now()
	var v fanoutVerdict
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("46.187.88.%d", 30+i)
		feedLine(fmt.Sprintf("from 11.8.148.112:%d accepted tcp:%s:10786 [x >> DIRECT] email: 4", i, ip), t0)
		v = feedLine(fmt.Sprintf("from 11.8.148.112:%d accepted udp:%s:10786 [x >> DIRECT] email: 4", i, ip), t0)
	}
	if !v.Ban {
		t.Fatalf("3 пира TCP+UDP — бан: %+v", v)
	}
}

// Легальное: домены, стандартные порты, звонки/STUN, Windows DO, повтор пира,
// много IP на ОДНОМ порту (нет разлёта по портам).
func TestFanoutLegitNotBanned(t *testing.T) {
	resetBypass()
	resetFanout()
	t0 := time.Now()
	dests := []string{}
	for i := 0; i < 200; i++ {
		dests = append(dests,
			"tcp:v16m.tiktokcdn.com:443",
			fmt.Sprintf("tcp:149.154.162.%d:443", i%250),
			fmt.Sprintf("udp:1.1.%d.1:53", i%250),
			fmt.Sprintf("udp:74.125.%d.127:19302", i%250), // Google STUN
			fmt.Sprintf("udp:162.159.%d.1:3478", i%250),   // TURN/Discord
			fmt.Sprintf("tcp:20.%d.1.1:7680", i%250),      // Windows Delivery Optimization
			fmt.Sprintf("udp:155.133.%d.20:27020", i%250), // Steam
			fmt.Sprintf("tcp:52.%d.3.4:9000", i%250),      // 200 IP, но один порт
			"tcp:11.18.221.81:8888",
		)
	}
	for i, d := range dests {
		l := fmt.Sprintf("from 11.19.79.221:%d accepted %s [x >> DIRECT] email: 13", i, d)
		if v := feedLine(l, t0.Add(time.Duration(i)*time.Millisecond)); v.Ban {
			t.Fatalf("НЕБЕЗОПАСНО: легальный трафик забанен на %s: %+v", d, v)
		}
	}
}

// Мост/релей: за одним IP ≥3 юзеров — IP не баним никогда.
func TestFanoutSharedSourceNotBanned(t *testing.T) {
	resetBypass()
	resetFanout()
	t0 := time.Now()
	bridge := "11.3.178.48"
	for _, e := range []string{"11", "12"} {
		feedLine("from "+bridge+":1 accepted tcp:ya.ru:443 [x >> DIRECT] email: "+e, t0)
	}
	var v fanoutVerdict
	for i := 0; i < 3; i++ {
		v = feedLine(fmt.Sprintf("from %s:%d accepted tcp:83.%d.0.1:%d [x -> BLOCK] email: 10", bridge, i, i, 6881+i), t0)
	}
	if !v.Ban || !v.Shared {
		t.Fatalf("за мостом 3 юзера: ожидали Ban+Shared, есть %+v", v)
	}
}

// --confirm-peers 0 выключает только бан по подтверждениям, а не банит всех.
func TestFanoutConfirmDisabled(t *testing.T) {
	resetBypass()
	resetFanout()
	old := fanoutConfirmNeed
	fanoutConfirmNeed = 0
	defer func() { fanoutConfirmNeed = old }()
	if v := feedLine(fmt.Sprintf(pcLine, 1, "11.20.88.161:13070"), time.Now()); v.Ban {
		t.Fatalf("один пир при --confirm-peers 0 забанен: %+v", v)
	}
}

// Живой мост 21 окт: техпользователь техюзер моста (id 9001) — весь
// трафик RU-ноды, 167 пиров за 1.5 мин. Его источник (наш релей) в bypass →
// Protected, бана нет даже если за IP виден один email.
func TestFanoutTechUserBehindBypassedRelay(t *testing.T) {
	resetBypass()
	resetFanout()
	addBypassIP("11.21.240.0/20")
	defer resetBypass()
	t0 := time.Now()
	var v fanoutVerdict
	for i := 0; i < 3; i++ {
		v = feedLine(fmt.Sprintf("from 11.21.245.184:%d accepted tcp:83.%d.1.1:%d [x -> BLOCK] email: 9001", i, i, 7000+i), t0)
	}
	if !v.Ban || !v.Protected {
		t.Fatalf("ожидали Ban+Protected для техюзера за релеем: %+v", v)
	}
	fanoutApply(v)
	blockedMu.Lock()
	_, banned := blockedIPs["11.21.245.184"]
	blockedMu.Unlock()
	if banned {
		t.Fatal("НЕБЕЗОПАСНО: забанен IP нашего релея")
	}
}

// --fanout-dry-run: решение «бан» только логируется, в blockedIPs ничего не попадает.
func TestFanoutDryRunDoesNotBan(t *testing.T) {
	resetBypass()
	old := fanoutDryRun
	fanoutDryRun = true
	defer func() { fanoutDryRun = old }()
	fanoutApply(fanoutVerdict{Ban: true, ClientIP: "203.0.113.77", Key: "4", Reason: "torrent_peers:3"})
	blockedMu.Lock()
	_, banned := blockedIPs["203.0.113.77"]
	blockedMu.Unlock()
	if banned {
		t.Fatal("dry-run забанил клиента")
	}
}

func TestLineOutboundTag(t *testing.T) {
	for line, want := range map[string]string{
		"from 1.2.3.4:5 accepted tcp:x:1 [VLESS_TCP_TLS_EE_443_clone -> BLOCK] email: 4":  "BLOCK",
		"from 1.2.3.4:5 accepted tcp:x:1 [VLESS_TCP_TLS_EE_443_clone >> DIRECT] email: 4": "DIRECT",
		"from 1.2.3.4:5 accepted tcp:x:1 [vless-443 >> TORRENT] email: user42":            "TORRENT",
	} {
		if got := lineOutboundTag(line); got != want {
			t.Errorf("тег %q, ожидали %q", got, want)
		}
	}
}

// ── Бан юзера на ноде (userban.go) ───────────────────────────────────────────

func withUserBanSpy(t *testing.T) *[]string {
	t.Helper()
	var got []string
	old := banUserFn
	banUserFn = func(email, reason string) bool {
		if !banableUser(email) {
			return false
		}
		got = append(got, email)
		return true
	}
	t.Cleanup(func() { banUserFn = old })
	return &got
}

func setProtectedUsers(ids ...string) {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	protectedUsersMu.Lock()
	protectedUsers = m
	protectedUsersMu.Unlock()
}

// Случай 24 окт 2026: юзер 1001 за L4-релеем 11.21.240.74 на мосту мост.
// IP релея не трогаем, юзера баним на ноде.
func TestFanoutRealUserBehindRelayBannedByUser(t *testing.T) {
	resetBypass()
	resetFanout()
	addBypassIP("11.21.240.0/20")
	defer resetBypass()
	setProtectedUsers("9001")
	defer setProtectedUsers()
	spy := withUserBanSpy(t)
	t0 := time.Now()
	var v fanoutVerdict
	for i := 0; i < 3; i++ {
		v = feedLine(fmt.Sprintf("from 11.21.240.74:%d accepted tcp:83.%d.1.1:%d [vless-in-443 -> BLOCK] email: 1001", i, i, 7000+i), t0)
	}
	if !v.Ban || !v.Protected {
		t.Fatalf("ожидали Ban+Protected: %+v", v)
	}
	fanoutApply(v)
	blockedMu.Lock()
	_, banned := blockedIPs["11.21.240.74"]
	blockedMu.Unlock()
	if banned {
		t.Fatal("НЕБЕЗОПАСНО: забанен IP нашего релея")
	}
	if len(*spy) != 1 || (*spy)[0] != "1001" {
		t.Fatalf("юзер 1001 не забанен на ноде: %v", *spy)
	}
}

// Техюзер моста (техюзер моста = 9001) — никогда.
func TestProtectedTechUserNeverBanned(t *testing.T) {
	resetBypass()
	resetFanout()
	addBypassIP("11.21.240.0/20")
	defer resetBypass()
	setProtectedUsers("9001")
	defer setProtectedUsers()
	spy := withUserBanSpy(t)
	fanoutApply(fanoutVerdict{Ban: true, Protected: true, ClientIP: "11.21.250.208", Key: "9001", Reason: "peer_fanout"})
	punish("11.21.250.208", "9001", "xray_tag:TORRENT", true)
	if len(*spy) != 0 {
		t.Fatalf("забанен техюзер: %v", *spy)
	}
	if banableUser("ip:1.2.3.4") || banableUser("") {
		t.Fatal("ключ ip:… / пустой email не должен баниться как юзер")
	}
}

func TestParseAPISocket(t *testing.T) {
	proc := "Num       RefCount Protocol Flags    Type St Inode Path\n" +
		"0000000000000000: 00000002 00000000 00010000 0001 01 2210 @rwnode-lock\n" +
		"0000000000000000: 00000002 00000000 00010000 0001 01 2211 @xtls-api-UasARBq3kr\n"
	if got := parseAPISocket(proc); got != "xtls-api-UasARBq3kr" {
		t.Fatalf("сокет %q", got)
	}
	if parseAPISocket("nothing here") != "" {
		t.Fatal("ложный сокет")
	}
}

// Формат inbounduser — снят с живого мост (xray 26.7.28).
func TestInboundUserAndRestoreConfig(t *testing.T) {
	out := `{
    "users": [
        {
            "account": {
                "_TypedMessage_": "xray.proxy.vless.Account",
                "flow": "xtls-rprx-vision",
                "id": "00000000-1111-4222-8333-444444444444"
            },
            "email": "1001"
        }
    ]
}`
	acc, ok, err := parseInboundUser(out, "1001")
	if err != nil || !ok {
		t.Fatalf("не разобрали: ok=%v err=%v", ok, err)
	}
	proto, c := clientFromAccount(acc, "1001")
	if proto != "vless" || c["id"] != "00000000-1111-4222-8333-444444444444" || c["flow"] != "xtls-rprx-vision" || c["email"] != "1001" {
		t.Fatalf("клиент %s %v", proto, c)
	}
	cfg := aduConfig(userBanEntry{Tag: "vless-in-443", Proto: proto, Client: c})
	for _, want := range []string{`"tag":"vless-in-443"`, `"port":1`, `"listen":"127.0.0.1"`, `"protocol":"vless"`, `"decryption":"none"`, `"flow":"xtls-rprx-vision"`, `"email":"1001"`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("в конфиге adu нет %s: %s", want, cfg)
		}
	}
	// XHTTP-инбаунд: без flow — и в восстановлении flow быть не должно.
	acc2, _, _ := parseInboundUser(`{"users":[{"account":{"_TypedMessage_":"xray.proxy.vless.Account","id":"x"},"email":"1001"}]}`, "1001")
	if _, c2 := clientFromAccount(acc2, "1001"); c2["flow"] != nil {
		t.Fatalf("лишний flow: %v", c2)
	}
	if _, ok, _ := parseInboundUser(`{"users":[]}`, "1001"); ok {
		t.Fatal("пустой ответ — юзера нет")
	}
	// Неизвестный протокол — не восстанавливаем, значит и не убираем.
	if _, c3 := clientFromAccount(map[string]interface{}{"_TypedMessage_": "xray.proxy.hysteria.Account", "auth": "a"}, "1"); c3 != nil {
		t.Fatal("hysteria не проверена на восстановление — убирать нельзя")
	}
}

func TestFilesFmNotTorrent(t *testing.T) {
	if isDomainTorrent("tcp:ru.files.fm:443") {
		t.Fatal("ru.files.fm — файлообменник, ложный бан 25.10")
	}
	if !isDomainTorrent("udp:tracker.files.fm:6969") {
		t.Fatal("tracker.files.fm — трекер")
	}
}

// Техюзер с IP, которого НЕТ в bypass (RU-релей 11.21.250.208 на ноде без
// списка релеев): нельзя банить ни юзера, ни IP источника.
func TestTechUserSourceNotInBypassNeverIPBanned(t *testing.T) {
	resetBypass()
	resetFanout()
	defer resetBypass()
	setProtectedUsers("9001")
	defer setProtectedUsers()
	spy := withUserBanSpy(t)
	t0 := time.Now()
	var v fanoutVerdict
	for i := 0; i < 3; i++ {
		v = feedLine(fmt.Sprintf("from 203.0.113.208:%d accepted tcp:83.%d.1.1:%d [x -> BLOCK] email: 9001", i, i, 7000+i), t0)
	}
	if !v.Ban || v.Protected {
		t.Fatalf("сценарий: бан без Protected, %+v", v)
	}
	fanoutApply(v)
	punish("203.0.113.208", "9001", "xray_tag:TORRENT", true)
	blockedMu.Lock()
	_, banned := blockedIPs["203.0.113.208"]
	blockedMu.Unlock()
	if banned || len(*spy) != 0 {
		t.Fatalf("НЕБЕЗОПАСНО: техюзер наказан (ip=%v users=%v)", banned, *spy)
	}
}

// Релей не в bypass (релей 11.22.32.29, 26.10): за IP три юзера — по домену
// трекера баним только юзера, IP релея не трогаем.
func TestDomainBanSharedSourceNoIPBan(t *testing.T) {
	resetBypass()
	resetFanout()
	defer resetBypass()
	setProtectedUsers()
	spy := withUserBanSpy(t)
	now := time.Now()
	for _, e := range []string{"11", "12", "13"} {
		fanoutObserve("198.51.100.29", e, "tcp:www.google.com:443", "DIRECT", now)
	}
	punish("198.51.100.29", "13", "domain_torrent:tracker.x:5678", true)
	blockedMu.Lock()
	_, banned := blockedIPs["198.51.100.29"]
	blockedMu.Unlock()
	if banned {
		t.Fatal("НЕБЕЗОПАСНО: забанен общий источник (релей)")
	}
	if len(*spy) != 1 || (*spy)[0] != "13" {
		t.Fatalf("юзер не забанен: %v", *spy)
	}
}

// Отчёт о бане: тело и заголовок токена; техюзеров не отправляем.
func TestReportUserBan(t *testing.T) {
	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- r.Header.Get("X-Ingest-Token") + "|" + string(b)
	}))
	defer srv.Close()
	dir := t.TempDir()
	tf := dir + "/tok"
	os.WriteFile(tf, []byte("secret\n"), 0600)
	oldU, oldF := reportURL, reportTokenFile
	reportURL, reportTokenFile = srv.URL, tf
	defer func() { reportURL, reportTokenFile = oldU, oldF }()
	setProtectedUsers("9001")
	defer setProtectedUsers()
	reportUserBan("9001", "x") // техюзер — не шлём
	reportUserBan("1002", "xray_tag:TORRENT")
	select {
	case v := <-got:
		if !strings.HasPrefix(v, "secret|") || !strings.Contains(v, `"user_id":"1002"`) || !strings.Contains(v, `"reason":"xray_tag:TORRENT"`) {
			t.Fatalf("отчёт %q", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("отчёт не пришёл")
	}
	select {
	case v := <-got:
		t.Fatalf("лишний отчёт (техюзер?): %q", v)
	case <-time.After(300 * time.Millisecond):
	}
}

// Служебные домены клиента и сайты трекеров — без бана; DHT, анонсы и пиры — бан.
func TestTorrentBanworthy(t *testing.T) {
	for dest, want := range map[string]bool{
		"tcp:update.utorrent.com:443":     false,
		"tcp:co.bt.co:443":                false,
		"tcp:ledger.bt.co:443":            false,
		"tcp:www.qbittorrent.org:443":     false,
		"tcp:rutracker.org:443":           false,
		"tcp:bench.utorrent.com:443":      false,
		"udp:router.bittorrent.com:6881":  true,
		"udp:router.utorrent.com:6881":    true,
		"udp:dht.transmissionbt.com:6881": true,
		"tcp:bt2.t-ru.org:80":             true,
		"tcp:tracker.se7en.ws:443":        true,
		"udp:tracker.opentrackr.org:1337": true,
		"udp:open.stealth.si:80":          true,
		"udp:82.221.103.244:6881":         true,
	} {
		if got := torrentBanworthy(dest, false); got != want {
			t.Errorf("без тега %s: %v, ожидали %v", dest, got, want)
		}
	}
	// с тегом TORRENT (geosite трекеров) — банить, кроме сайтов и служебных
	if !torrentBanworthy("tcp:tracker.unknown-example.net:443", true) {
		t.Error("тег TORRENT на трекер должен банить")
	}
	if torrentBanworthy("tcp:update.utorrent.com:443", true) {
		t.Error("тег TORRENT на update.utorrent.com не должен банить")
	}
}

// Машина с двумя панелями: ключ «контейнер|email» — техюзер и бан по сырому id,
// отчёт для чужой панели можно выключить.
func TestScopedKeys(t *testing.T) {
	if c, e := splitKey(scopeKey("ee-node", "1001")); c != "ee-node" || e != "1001" {
		t.Fatalf("split %q %q", c, e)
	}
	if scopeKey("", "1001") != "1001" || scopeKey("x", "") != "" {
		t.Fatal("пустой контейнер/email — ключ без префикса")
	}
	setProtectedUsers("9001")
	defer setProtectedUsers()
	if !techUser("ee-node|9001") || banableUser("ee-node|9001") || !banableUser("ee-node|1001") {
		t.Fatal("техюзер должен распознаваться и с префиксом контейнера")
	}
	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- r.URL.Path + "|" + string(b)
	}))
	defer srv.Close()
	oldU, oldC := reportURL, reportURLCtr
	reportURL, reportURLCtr = srv.URL+"/a", map[string]string{"ee-node": srv.URL + "/b", "other": ""}
	defer func() { reportURL, reportURLCtr = oldU, oldC }()
	reportUserBan("other|1001", "x")   // выключено для контейнера
	reportUserBan("ee-node|1001", "x") // на свой приёмник, user_id без префикса
	select {
	case v := <-got:
		if !strings.HasPrefix(v, "/b|") || !strings.Contains(v, `"user_id":"1001"`) {
			t.Fatalf("отчёт %q", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("отчёт не пришёл")
	}
	select {
	case v := <-got:
		t.Fatalf("лишний отчёт: %q", v)
	case <-time.After(300 * time.Millisecond):
	}
}
