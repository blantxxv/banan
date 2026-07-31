package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"io/ioutil"
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
	banDuration   = 10 * time.Minute
	peerBanDur    = 24 * time.Hour
	logFile       = ""
	torrentTag    = "TORRENT"
	bypassIPs     = map[string]bool{"127.0.0.1": true, "::1": true}
	enableNetstat = true
	enableFinWait = true
	finWaitThresh = 30
	connThresh    = 300
	sendQThresh   = 10
	vpnPorts      = map[string]bool{
		"1194":  true,
		"51820": true,
		"500":   true,
		"4500":  true,
		"443":   true,
		"80":    true,
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
}

var signatures = []signature{
	{proto: "tcp", hex: "|13426974546f7272656e742070726f746f636f6c|", action: "PEER"},
	{proto: "udp", pattern: "d1:ad2:id20:", action: "PEER"},
	{proto: "udp", pattern: "d1:rd2:id20:", action: "PEER"},
	{proto: "udp", pattern: "1:q9:get_peers", action: "PEER"},
	{proto: "udp", pattern: "1:q13:announce_peer", action: "PEER"},
	{proto: "udp", pattern: "1:q9:find_node", action: "PEER"},
	{proto: "udp", pattern: "1:q4:ping", action: "PEER"},
	{proto: "udp", pattern: "1:q4:vote", action: "PEER"},
	{proto: "udp", pattern: "1:q17:sample_infohashes", action: "PEER"},
	{proto: "udp", pattern: "1:y1:q", action: "PEER"},
	{proto: "udp", pattern: "1:y1:r", action: "PEER"},
	{proto: "tcp", pattern: "13:piece length", action: "PEER"},
	{proto: "tcp", pattern: "4:infod", action: "PEER"},
	{proto: "tcp", pattern: "11:ut_metadata", action: "PEER"},
	{proto: "tcp", pattern: "5:ut_pex", action: "PEER"},
	{proto: "tcp", pattern: "upload_only", action: "PEER"},
	{proto: "tcp", pattern: "lt_donthave", action: "PEER"},
	{proto: "udp", hex: "|0000041727101980|", action: "TRACKER"},
	{proto: "tcp", pattern: "info_hash=", action: "TRACKER"},
	{proto: "tcp", pattern: "peer_id=", action: "TRACKER"},
	{proto: "tcp", pattern: "announce?", action: "TRACKER"},
	{proto: "tcp", pattern: "scrape?", action: "TRACKER"},
	{proto: "tcp", pattern: "event=started", action: "TRACKER"},
	{proto: "tcp", pattern: "event=stopped", action: "TRACKER"},
	{proto: "tcp", pattern: "event=completed", action: "TRACKER"},
	{proto: "tcp", pattern: "d8:announce", action: "TRACKER"},
	{proto: "tcp", pattern: "d13:announce-list", action: "TRACKER"},
	{proto: "tcp", pattern: "/announce HTTP", action: "TRACKER"},
	{proto: "tcp", pattern: "User-Agent: uTorrent", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: BitTorrent", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: qBittorrent", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: Transmission", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: libtorrent", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: Deluge", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: Vuze", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: Azureus", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: Aria2", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: WebTorrent", action: "DROP"},
	{proto: "tcp", pattern: "User-Agent: Tixati", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "router.bittorrent.com", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "router.utorrent.com", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "dht.transmissionbt.com", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "opentrackr", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "nyaa", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "rutracker", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "rutor", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "thepiratebay", action: "DROP"},
	{proto: "udp", dport: 53, pattern: "1337x", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "router.bittorrent.com", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "router.utorrent.com", action: "DROP"},
	{proto: "tcp", dport: 53, pattern: "dht.transmissionbt.com", action: "DROP"},
}

var trackerPorts = []string{
	"6969", "2710", "1337",
	"4662", "4661", "4672", "4665",
	"411", "412", "1214", "4242",
	"8999", "3659",
}

var clientPorts = []string{
	"6881:6999", "6880", "51413",
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
	if bypassIPs[ip] {
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
	if bypassIPs[ip] {
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

	for _, kw := range torrentDestKeywords {
		if strings.Contains(host, kw) {
			return true
		}
	}
	return false
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
				if cip != "" && !bypassIPs[cip] {
					log.Printf("DOMAIN_TORRENT ban %s (dest=%s)", cip, dest)
					banIP(cip, "domain_torrent:"+dest)
				}
			}
			continue
		}

		if clientIP != "" && !bypassIPs[clientIP] {
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
			if err == nil && net.ParseIP(destIP) != nil && !bypassIPs[destIP] {
				blockPeer(destIP, "xray_dest:"+torrentTag)
			}
		}
	}
}

func startLogMonitor() {
	if logFile == "" {
		return
	}
	go func() {
		for {
			monitorLog(logFile)
			time.Sleep(2 * time.Second)
		}
	}()
	log.Printf("log monitor started: %s (tag=%s)", logFile, torrentTag)
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
		if e.remoteIP == "" || bypassIPs[e.remoteIP] {
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
				if exec.Command(ipt, "-A", "FORWARD", "-p", proto, "--dport", port, "-j", "DROP").Run() == nil {
					count++
				}
				if exec.Command(ipt, "-A", "FORWARD", "-p", proto, "--sport", port, "-j", "DROP").Run() == nil {
					count++
				}
				if exec.Command(ipt, "-A", "INPUT", "-p", proto, "--sport", port, "-j", "DROP").Run() == nil {
					count++
				}
			}
		}
	}
	return count
}

func applyDPI() int {
	for _, ipt := range []string{"iptables", "ip6tables"} {
		exec.Command(ipt, "-N", dpiChain).Run()
		exec.Command(ipt, "-N", "CATCH_TRACKER").Run()
		exec.Command(ipt, "-N", "CATCH_PEER").Run()
		sfx := "_v4"
		if ipt == "ip6tables" {
			sfx = "_v6"
		}
		exec.Command(ipt, "-A", "CATCH_TRACKER", "-j", "SET", "--add-set", "auto_trackers"+sfx, "dst").Run()
		exec.Command(ipt, "-A", "CATCH_TRACKER", "-j", "DROP").Run()
		exec.Command(ipt, "-A", "CATCH_PEER", "-j", "SET", "--add-set", "auto_peers"+sfx, "dst").Run()
		exec.Command(ipt, "-A", "CATCH_PEER", "-j", "DROP").Run()

		exec.Command(ipt, "-A", dpiChain, "-i", "lo", "-j", "RETURN").Run()
		exec.Command(ipt, "-A", dpiChain, "-o", "lo", "-j", "RETURN").Run()
		exec.Command(ipt, "-A", dpiChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN").Run()
		for port := range vpnPorts {
			for _, proto := range []string{"tcp", "udp"} {
				exec.Command(ipt, "-A", dpiChain, "-p", proto, "--dport", port, "-j", "RETURN").Run()
				exec.Command(ipt, "-A", dpiChain, "-p", proto, "--sport", port, "-j", "RETURN").Run()
			}
		}
	}

	count := 0
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
	for _, chain := range dpiHooks {
		for _, ipt := range []string{"iptables", "ip6tables"} {
			exec.Command(ipt, "-A", chain, "-j", dpiChain).Run()
		}
	}
	return count
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
				logFile = os.Args[i+1]
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
			if i+1 < len(os.Args) {
				for _, ip := range strings.Split(os.Args[i+1], ",") {
					bypassIPs[strings.TrimSpace(ip)] = true
				}
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
		case "--no-netstat":
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

	cleanup()
	initBanChain()
	initPeerChain()
	loadStorage()
	portRules := applyPortBlock()
	dpiRules := applyDPI()
	startLogMonitor()
	startNetstatMonitor()
	startCleanupRoutine()

	fmt.Printf("torrent blocker started: %d port + %d DPI rules, ban=%v\n", portRules, dpiRules, banDuration)
	if logFile != "" {
		fmt.Printf("monitoring log: %s (tag=%s)\n", logFile, torrentTag)
	}
	fmt.Printf("netstat=%v finwait_thresh=%d conn_thresh=%d sendq_thresh=%d\n",
		enableNetstat, finWaitThresh, connThresh, sendQThresh)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
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
