package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ── Бан юзера на этом сервере (xray API) ─────────────────────────────────────
//
// На мостах клиент приходит через наш L4-релей или общий NAT:
// IP источника банить нельзя, а email (id юзера в панели) в access.log есть.
// Поэтому юзера убираем из всех инбаундов ЭТОЙ ноды через API xray
// (rmu), а через banDuration возвращаем с тем же аккаунтом (adu). Панель не
// трогаем — на других серверах юзер работает.
//
// ⚠️ adrules без -append ЗАМЕНЯЕТ всю маршрутизацию ноды, а с -append правило
// встаёт в конец и не срабатывает — поэтому бан через пользователей, не через
// routing. Аккаунт, который не умеем восстановить (не vless/trojan), из
// инбаунда не убираем вовсе: лучше не забанить, чем потерять юзера.
//
// API remnanode слушает абстрактный unix-сокет @xtls-api-<случайно> внутри
// сетевого пространства контейнера, поэтому всё идёт через docker exec.
var (
	userBanEnabled     = true
	xrayContainer      = "" // пусто — автоопределение (remnanode)
	userBanFile        = "/var/lib/torrent-blocker/userbans.json"
	protectedUsersFile = "/etc/torrent-blocker/protected-users.txt"

	userBanMu sync.Mutex
	userBans  = map[string]*userBan{}

	protectedUsersMu sync.RWMutex
	protectedUsers   = map[string]bool{}

	xrayAPIMu      sync.Mutex
	xrayAPIFailLog time.Time
)

// apiSkipInbounds — служебные инбаунды, где юзеров нет.
var apiSkipInbounds = map[string]bool{"REMNAWAVE_API_INBOUND": true, "api": true}

type userBanEntry struct {
	Ctr    string                 `json:"ctr,omitempty"`
	Tag    string                 `json:"tag"`
	Proto  string                 `json:"proto"`
	Client map[string]interface{} `json:"client"`
}

type userBan struct {
	Email   string         `json:"email"`
	Blocked time.Time      `json:"blocked"`
	Until   time.Time      `json:"until"`
	Reason  string         `json:"reason,omitempty"`
	Entries []userBanEntry `json:"entries"`
}

// banableUser: реальный юзер панели, а не техпользователь моста и не ключ «ip:…».
func banableUser(email string) bool {
	if email == "" || strings.HasPrefix(email, "ip:") {
		return false
	}
	protectedUsersMu.RLock()
	defer protectedUsersMu.RUnlock()
	return !protectedUsers[email]
}

// techUser: email из списка техюзеров (в отличие от !banableUser, пустой
// email и ключ «ip:…» техюзером не считаются).
func techUser(email string) bool {
	if email == "" || strings.HasPrefix(email, "ip:") {
		return false
	}
	protectedUsersMu.RLock()
	defer protectedUsersMu.RUnlock()
	return protectedUsers[email]
}

// loadProtectedUsers: по строке email (id юзера в панели), # — комментарий.
func loadProtectedUsers(path string) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	m := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			m[l] = true
		}
	}
	protectedUsersMu.Lock()
	protectedUsers = m
	protectedUsersMu.Unlock()
	log.Printf("protected users: %d (%s)", len(m), path)
}

// xrayContainers: контейнеры, где есть и бинарь xray, и сокет API. На одной ноде их
// два (remnanode в host-сети и ee-node в своей); ee-caddy делит сеть с ee-node
// и «видит» сокет, но xray в нём нет — по бинарю отсеивается.
func xrayContainers() []string {
	if xrayContainer != "" {
		return strings.Split(xrayContainer, ",")
	}
	out, err := exec.Command("docker", "ps", "--format", "{{.Names}}").Output()
	if err != nil {
		return nil
	}
	var res []string
	for _, c := range strings.Fields(string(out)) {
		o, err := dockerExec(c, "", "sh", "-c", "command -v xray >/dev/null && cat /proc/net/unix")
		if err == nil && parseAPISocket(o) != "" {
			res = append(res, c)
		}
	}
	return res
}

func dockerExec(ctr string, stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	full := []string{"exec"}
	if stdin != "" {
		full = append(full, "-i")
	}
	full = append(append(full, ctr), args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// xrayAPISocket: имя абстрактного сокета API из /proc/net/unix контейнера.
func xrayAPISocket(ctr string) string {
	out, err := dockerExec(ctr, "", "cat", "/proc/net/unix")
	if err != nil {
		return ""
	}
	return parseAPISocket(out)
}

func parseAPISocket(procNetUnix string) string {
	for _, l := range strings.Split(procNetUnix, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		p := f[len(f)-1]
		if strings.HasPrefix(p, "@xtls-api-") {
			return strings.TrimPrefix(p, "@")
		}
	}
	return ""
}

type xrayAPI struct{ ctr, server string }

// newXrayAPI: клиент API контейнера; сокет ищется каждый раз — после рестарта
// xray у него новое имя.
func newXrayAPI(ctr string) (*xrayAPI, error) {
	if ctr == "" {
		return nil, fmt.Errorf("контейнер с xray не найден")
	}
	sock := xrayAPISocket(ctr)
	if sock == "" {
		return nil, fmt.Errorf("сокет @xtls-api-* в %s не найден", ctr)
	}
	return &xrayAPI{ctr: ctr, server: "--server=unix-abstract:" + sock}, nil
}

func (a *xrayAPI) run(stdin string, args ...string) (string, error) {
	full := append([]string{"xray", "api", args[0], a.server}, args[1:]...)
	return dockerExec(a.ctr, stdin, full...)
}

func (a *xrayAPI) inboundTags() ([]string, error) {
	out, err := a.run("", "lsi", "--isOnlyTags=true")
	if err != nil {
		return nil, fmt.Errorf("lsi: %v: %s", err, strings.TrimSpace(out))
	}
	var r struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(jsonPart(out)), &r); err != nil {
		return nil, fmt.Errorf("lsi: %v", err)
	}
	var tags []string
	for _, in := range r.Inbounds {
		if in.Tag != "" && !apiSkipInbounds[in.Tag] {
			tags = append(tags, in.Tag)
		}
	}
	return tags, nil
}

// inboundUser: аккаунт юзера в инбаунде; ok=false — юзера там нет.
func (a *xrayAPI) inboundUser(tag, email string) (map[string]interface{}, bool, error) {
	out, err := a.run("", "inbounduser", "-tag="+tag, "-email="+email)
	if err != nil {
		if strings.Contains(out, "not found") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("inbounduser %s: %v: %s", tag, err, strings.TrimSpace(out))
	}
	return parseInboundUser(out, email)
}

func jsonPart(s string) string {
	if i := strings.IndexByte(s, '{'); i >= 0 {
		return s[i:]
	}
	return s
}

func parseInboundUser(out, email string) (map[string]interface{}, bool, error) {
	var r struct {
		Users []struct {
			Email   string                 `json:"email"`
			Account map[string]interface{} `json:"account"`
		} `json:"users"`
	}
	if err := json.Unmarshal([]byte(jsonPart(out)), &r); err != nil {
		return nil, false, err
	}
	for _, u := range r.Users {
		if u.Email == email && u.Account != nil {
			return u.Account, true, nil
		}
	}
	return nil, false, nil
}

// clientFromAccount: клиент для adu из аккаунта inbounduser. Только протоколы,
// у которых восстановление проверено; остальные — nil (из инбаунда не убираем).
func clientFromAccount(acc map[string]interface{}, email string) (string, map[string]interface{}) {
	typ, _ := acc["_TypedMessage_"].(string) // "xray.proxy.vless.Account"
	parts := strings.Split(typ, ".")
	if len(parts) != 4 || parts[0] != "xray" || parts[1] != "proxy" || parts[3] != "Account" {
		return "", nil
	}
	proto := parts[2]
	c := map[string]interface{}{"email": email}
	switch proto {
	case "vless":
		id, _ := acc["id"].(string)
		if id == "" {
			return "", nil
		}
		c["id"] = id
		if fl, _ := acc["flow"].(string); fl != "" {
			c["flow"] = fl
		}
	case "trojan":
		pw, _ := acc["password"].(string)
		if pw == "" {
			return "", nil
		}
		c["password"] = pw
	default:
		return "", nil
	}
	return proto, c
}

func aduConfig(e userBanEntry) string {
	settings := map[string]interface{}{"clients": []interface{}{e.Client}}
	if e.Proto == "vless" {
		settings["decryption"] = "none"
	}
	// listen/port adu не применяет (берёт только clients), но без них конфиг
	// не собирается: «Listen on AnyIP but no Port(s) set» — живой тестовой ноде, 26.10.
	cfg := map[string]interface{}{"inbounds": []interface{}{map[string]interface{}{
		"tag": e.Tag, "listen": "127.0.0.1", "port": 1, "protocol": e.Proto, "settings": settings,
	}}}
	b, _ := json.Marshal(cfg)
	return string(b)
}

func (a *xrayAPI) removeUser(tag, email string) error {
	out, err := a.run("", "rmu", "-tag="+tag, email)
	if err != nil {
		return fmt.Errorf("rmu %s: %v: %s", tag, err, strings.TrimSpace(out))
	}
	return nil
}

func (a *xrayAPI) addUser(e userBanEntry) error {
	f := fmt.Sprintf("/tmp/tb-adu-%d.json", time.Now().UnixNano())
	if out, err := dockerExec(a.ctr, aduConfig(e), "sh", "-c", "umask 077; cat > "+f); err != nil {
		return fmt.Errorf("adu %s: запись конфига: %v: %s", e.Tag, err, out)
	}
	defer dockerExec(a.ctr, "", "rm", "-f", f)
	out, err := a.run("", "adu", f)
	if err != nil || strings.Contains(strings.ToLower(out), "failed") || !strings.Contains(out, "result: ok") {
		if strings.Contains(out, "already exists") {
			return nil // remnanode успел вернуть сам
		}
		return fmt.Errorf("adu %s: %v: %s", e.Tag, err, strings.TrimSpace(out))
	}
	return nil
}

func saveUserBans() {
	userBanMu.Lock()
	data, _ := json.Marshal(userBans)
	userBanMu.Unlock()
	os.MkdirAll("/var/lib/torrent-blocker", 0750)
	tmp := userBanFile + ".tmp"
	ioutil.WriteFile(tmp, data, 0600)
	os.Rename(tmp, userBanFile)
}

func apiFailed(err error) {
	xrayAPIMu.Lock()
	defer xrayAPIMu.Unlock()
	if time.Since(xrayAPIFailLog) > 10*time.Minute {
		xrayAPIFailLog = time.Now()
		log.Printf("USER_BAN недоступен: %v", err)
	}
}

// banUser убирает юзера из инбаундов ноды на banDuration. true — забанен.
func banUser(email, reason string) bool {
	if !userBanEnabled || !banableUser(email) {
		return false
	}
	userBanMu.Lock()
	if _, ok := userBans[email]; ok {
		userBanMu.Unlock()
		return true
	}
	// резерв под бан, чтобы параллельный детектор не запускал второй
	ub := &userBan{Email: email, Blocked: time.Now(), Until: time.Now().Add(banDuration), Reason: reason}
	userBans[email] = ub
	userBanMu.Unlock()

	ctrs := xrayContainers()
	if len(ctrs) == 0 {
		apiFailed(fmt.Errorf("контейнер с xray API не найден"))
	}
	var skipped []string
	for _, ctr := range ctrs {
		api, err := newXrayAPI(ctr)
		var tags []string
		if err == nil {
			tags, err = api.inboundTags()
		}
		if err != nil {
			apiFailed(err)
			continue
		}
		for _, tag := range tags {
			acc, ok, err := api.inboundUser(tag, email)
			if err != nil || !ok {
				continue
			}
			proto, client := clientFromAccount(acc, email)
			if client == nil {
				skipped = append(skipped, ctr+"/"+tag)
				continue
			}
			e := userBanEntry{Ctr: ctr, Tag: tag, Proto: proto, Client: client}
			if err := api.removeUser(tag, email); err != nil {
				log.Printf("USER_BAN %s: %v", email, err)
				continue
			}
			userBanMu.Lock()
			ub.Entries = append(ub.Entries, e)
			userBanMu.Unlock()
			saveUserBans() // после каждого инбаунда: при падении аккаунт не потеряется
		}
	}
	userBanMu.Lock()
	n := len(ub.Entries)
	if n == 0 {
		delete(userBans, email)
	}
	userBanMu.Unlock()
	saveUserBans()
	if n == 0 {
		log.Printf("USER_BAN %s: юзер не найден в инбаундах ноды (skip=%v) — не забанен (%s)", email, skipped, reason)
		return false
	}
	log.Printf("USER_BAN user=%s на %v: убран из %d инбаундов (%s)%s", email, banDuration, n, reason, skippedNote(skipped))
	reportUserBan(email, reason)
	return true
}

func skippedNote(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return fmt.Sprintf(", не тронуты (протокол без восстановления): %v", s)
}

// unbanUser возвращает юзера во все инбаунды, откуда убрали.
func unbanUser(email string) {
	userBanMu.Lock()
	ub := userBans[email]
	userBanMu.Unlock()
	if ub == nil {
		return
	}
	apis := map[string]*xrayAPI{}
	var left []userBanEntry
	for _, e := range ub.Entries {
		api, err := cachedAPI(apis, e.Ctr)
		if err != nil {
			apiFailed(err)
			left = append(left, e) // повторим на следующем тике, запись сохраняется
			continue
		}
		if _, ok, _ := api.inboundUser(e.Tag, email); ok {
			continue // remnanode уже вернул сам (рестарт/синк)
		}
		if err := api.addUser(e); err != nil {
			log.Printf("USER_UNBAN %s: %v", email, err)
			left = append(left, e)
		}
	}
	userBanMu.Lock()
	if len(left) == 0 {
		delete(userBans, email)
	} else {
		ub.Entries = left
	}
	userBanMu.Unlock()
	saveUserBans()
	if len(left) == 0 {
		log.Printf("USER_UNBAN user=%s", email)
	}
}

// enforceUserBans: истёкшие — вернуть; активные — убрать снова, если remnanode
// вернул юзера раньше срока (рестарт xray, синк с панелью).
func enforceUserBans(now time.Time) {
	userBanMu.Lock()
	var expired []string
	active := map[string][]userBanEntry{}
	for email, ub := range userBans {
		if now.After(ub.Until) {
			expired = append(expired, email)
		} else {
			active[email] = append([]userBanEntry(nil), ub.Entries...)
		}
	}
	userBanMu.Unlock()
	for _, email := range expired {
		unbanUser(email)
	}
	if len(active) == 0 {
		return
	}
	apis := map[string]*xrayAPI{}
	for email, entries := range active {
		for _, e := range entries {
			api, err := cachedAPI(apis, e.Ctr)
			if err != nil {
				apiFailed(err)
				continue
			}
			if _, ok, _ := api.inboundUser(e.Tag, email); ok {
				if api.removeUser(e.Tag, email) == nil {
					log.Printf("USER_BAN user=%s: вернулся в %s раньше срока — убран снова", email, e.Tag)
				}
			}
		}
	}
}

// cachedAPI: один клиент на контейнер за проход; пустой Ctr (записи старого
// формата) — первый найденный контейнер.
func cachedAPI(m map[string]*xrayAPI, ctr string) (*xrayAPI, error) {
	if ctr == "" {
		if c := xrayContainers(); len(c) > 0 {
			ctr = c[0]
		}
	}
	if a := m[ctr]; a != nil {
		return a, nil
	}
	a, err := newXrayAPI(ctr)
	if err == nil {
		m[ctr] = a
	}
	return a, err
}

func loadUserBans() {
	data, err := ioutil.ReadFile(userBanFile)
	if err != nil {
		return
	}
	var loaded map[string]*userBan
	if json.Unmarshal(data, &loaded) != nil {
		return
	}
	userBanMu.Lock()
	for k, v := range loaded {
		if v != nil && len(v.Entries) > 0 {
			userBans[k] = v
		}
	}
	n := len(userBans)
	userBanMu.Unlock()
	if n > 0 {
		log.Printf("restored user bans: %d (истёкшие вернутся на первом тике)", n)
	}
}

func getUserBanCount() int {
	userBanMu.Lock()
	defer userBanMu.Unlock()
	return len(userBans)
}

// sharedSource: за IP за окно разлёта видно ≥ fanoutSharedEmails разных юзеров.
func sharedSource(ip string) bool {
	fanoutMu.Lock()
	defer fanoutMu.Unlock()
	src := fanoutSrc[ip]
	if src == nil {
		return false
	}
	pruneSeen(src, time.Now().Add(-fanoutWindow))
	return len(src) >= fanoutSharedEmails
}

// banUserFn — подменяется в тестах (без docker).
var banUserFn = banUser

// punish: единая точка наказания. IP источника банится, только если это сам
// клиент (не наш релей/мост и не общий NAT); юзер — по email на этой ноде.
func punish(clientIP, email, reason string, ipAllowed bool) {
	if techUser(email) {
		// Сквозная учётка моста/выхода: источник — наш сервер, за ним сотни
		// людей. Не баним ни юзера, ни IP, даже если IP не внесён в bypass.
		log.Printf("TECH_USER %s user=%s %s — техюзер, не баню", clientIP, email, reason)
		return
	}
	if ipAllowed && clientIP != "" && !isProtectedIP(clientIP) {
		if sharedSource(clientIP) {
			// Релей/NAT, которого нет в bypass (релей 11.22.32.29,
			// 26.10: бан по домену трекера срезал весь релей на 2.5 мин).
			log.Printf("SHARED_SOURCE %s: за IP ≥%d юзеров — IP не баню, только юзера (%s)", clientIP, fanoutSharedEmails, reason)
		} else {
			banIP(clientIP, reason)
		}
	}
	if email != "" && banUserFn(email, reason) {
		return
	}
	if !ipAllowed || clientIP == "" || isProtectedIP(clientIP) {
		log.Printf("PEER_FANOUT %s user=%s %s — источник наш/общий, юзера забанить не удалось", clientIP, email, reason)
	}
}
