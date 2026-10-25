package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ── Отчёт о бане юзера на приёмник ────────────────────────────────────────────
//
// С автовыбором юзер после бана переезжает на соседний сервер (1002 — 9
// серверов за час, 26.10), поэтому считаем баны по флоту централизованно:
// приёмник (--report-url) сам решает, что делать с повторами.
// Здесь только отправка.
var (
	reportURL       = "" // --report-url; пусто — не отправлять
	reportTokenFile = "/etc/torrent-blocker/report.token"
	reportHost, _   = os.Hostname()

	reportMu      sync.Mutex
	reportFailLog time.Time
	reportClient  = &http.Client{Timeout: 10 * time.Second}
)

type banReport struct {
	UserID string `json:"user_id"`
	Node   string `json:"node"`
	Reason string `json:"reason"`
	TS     int64  `json:"ts"`
}

func reportToken() string {
	b, err := ioutil.ReadFile(reportTokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// reportUserBan — асинхронно, 3 попытки; блокер от сети приёмника не зависит.
func reportUserBan(email, reason string) {
	if reportURL == "" || !banableUser(email) {
		return
	}
	body, _ := json.Marshal(banReport{UserID: email, Node: reportHost, Reason: reason, TS: time.Now().Unix()})
	go func() {
		tok := reportToken()
		var last error
		for i := 0; i < 3; i++ {
			if i > 0 {
				time.Sleep(time.Duration(i*10) * time.Second)
			}
			req, err := http.NewRequest("POST", reportURL, bytes.NewReader(body))
			if err != nil {
				last = err
				break
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Ingest-Token", tok)
			resp, err := reportClient.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					return
				}
				last = &reportErr{resp.Status}
				if resp.StatusCode == 400 || resp.StatusCode == 401 {
					break // повтор не поможет
				}
				continue
			}
			last = err
		}
		reportMu.Lock()
		defer reportMu.Unlock()
		if time.Since(reportFailLog) > 10*time.Minute {
			reportFailLog = time.Now()
			log.Printf("REPORT не отправлен (%s): %v", email, last)
		}
	}()
}

type reportErr struct{ s string }

func (e *reportErr) Error() string { return e.s }
