package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Назначения, которые сниффер xray принимает за BitTorrent, хотя это сервис:
// к ним ходят разные юзеры ровно по разу, без трекеров и роя. Тег TORRENT на такое
// назначение не банит, а адрес не уходит ни в разлёт, ни в ipset пиров.
//
// Встроенный список — подтверждённые ложняки; дополнять без сборки можно файлом
// notTorrentFile (строки «CIDR» или «CIDR порт», # — комментарий), перечитывается по SIGHUP.

type notTorrentRule struct {
	net  *net.IPNet
	port int // 0 — любой порт
}

var builtinNotTorrent = []string{
	// 28.10–12.11.2026: 13 юзеров, у каждого по одному TCP-соединению на .212/.215/.217:21413
	// (хостер Pfcloud) — тег TORRENT без единого трекера и пира, предупреждения были ложными.
	"45.135.193.0/24 21413",
}

var (
	notTorrentFile  = "/etc/torrent-blocker/not-torrent.txt"
	notTorrentMu    sync.RWMutex
	notTorrentRules = mustNotTorrent(builtinNotTorrent)
)

func parseNotTorrent(line string) (notTorrentRule, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) == 0 || len(f) > 2 {
		return notTorrentRule{}, false
	}
	cidr := f[0]
	if !strings.Contains(cidr, "/") {
		if ip := net.ParseIP(cidr); ip != nil && ip.To4() != nil {
			cidr += "/32"
		} else if ip != nil {
			cidr += "/128"
		}
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return notTorrentRule{}, false
	}
	r := notTorrentRule{net: n}
	if len(f) == 2 {
		p, err := strconv.Atoi(f[1])
		if err != nil || p < 1 || p > 65535 {
			return notTorrentRule{}, false
		}
		r.port = p
	}
	return r, true
}

func mustNotTorrent(lines []string) []notTorrentRule {
	var out []notTorrentRule
	for _, l := range lines {
		if r, ok := parseNotTorrent(l); ok {
			out = append(out, r)
		}
	}
	return out
}

// loadNotTorrentFile: встроенный список + файл (если есть). Вызывается на старте и по SIGHUP.
func loadNotTorrentFile(path string) {
	rules := mustNotTorrent(builtinNotTorrent)
	extra := 0
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if r, ok := parseNotTorrent(line); ok {
				rules = append(rules, r)
				extra++
			} else {
				log.Printf("not-torrent: не понял строку %q", line)
			}
		}
		f.Close()
	}
	notTorrentMu.Lock()
	notTorrentRules = rules
	notTorrentMu.Unlock()
	log.Printf("not-torrent: %d встроенных + %d из %s", len(rules)-extra, extra, path)
}

// isNotTorrentDst: dest вида «tcp:IP:порт», «udp:IP:порт» или «IP:порт».
func isNotTorrentDst(dest string) bool {
	d := strings.TrimPrefix(strings.TrimPrefix(dest, "tcp:"), "udp:")
	host, port, err := net.SplitHostPort(d)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	p, _ := strconv.Atoi(port)
	notTorrentMu.RLock()
	defer notTorrentMu.RUnlock()
	for _, r := range notTorrentRules {
		if r.net.Contains(ip) && (r.port == 0 || r.port == p) {
			return true
		}
	}
	return false
}
