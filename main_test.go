package main

import (
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

	// Все торрент-порты ниже эфемерного диапазона (32768) — иначе блок по
	// --sport мог бы задеть исходящие соединения ноды.
	for _, tp := range append(append([]string{}, trackerPorts...), clientPorts...) {
		lo, hi := portRange(tp)
		if hi >= 32768 {
			t.Errorf("порт %s (%d-%d) попадает в эфемерный диапазон — риск для исходящих", tp, lo, hi)
		}
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
