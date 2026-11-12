package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNotTorrentBuiltin(t *testing.T) {
	loadNotTorrentFile(filepath.Join(t.TempDir(), "нет-файла"))
	cases := []struct {
		dst string
		not bool
	}{
		{"tcp:45.135.193.217:21413", true},
		{"tcp:45.135.193.212:21413", true},
		{"udp:45.135.193.215:21413", true},
		{"45.135.193.1:21413", true},
		{"tcp:45.135.193.217:51413", false}, // другой порт — обычные правила
		{"tcp:45.135.194.217:21413", false}, // соседняя сеть
		{"tcp:93.158.213.92:1337", false},   // настоящий трекер
		{"tcp:bt4.t-ru.org:80", false},      // домен — не про этот список
		{"", false},
	}
	for _, c := range cases {
		if got := isNotTorrentDst(c.dst); got != c.not {
			t.Errorf("isNotTorrentDst(%q) = %v, ждал %v", c.dst, got, c.not)
		}
	}
}

func TestNotTorrentFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-torrent.txt")
	body := "# комментарий\n11.77.0.0/16 4242\n11.78.1.5   # любой порт\nмусор\n11.79.0.0/16 99999\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	loadNotTorrentFile(p)
	defer loadNotTorrentFile(filepath.Join(t.TempDir(), "нет-файла"))
	for dst, want := range map[string]bool{
		"tcp:11.77.3.4:4242":        true,
		"tcp:11.77.3.4:4243":        false,
		"udp:11.78.1.5:60000":       true,
		"tcp:11.79.1.1:99":          false, // строка с портом 99999 отброшена
		"tcp:45.135.193.217:21413":  true,  // встроенный список остаётся
	} {
		if got := isNotTorrentDst(dst); got != want {
			t.Errorf("%s: %v, ждал %v", dst, got, want)
		}
	}
}

// Разлёт: назначения из списка не считаются пирами, даже если их много.
func TestNotTorrentNotFanoutPeer(t *testing.T) {
	resetBypass()
	resetFanout()
	p := filepath.Join(t.TempDir(), "not-torrent.txt")
	if err := os.WriteFile(p, []byte("11.66.0.0/16\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loadNotTorrentFile(p)
	defer loadNotTorrentFile(filepath.Join(t.TempDir(), "нет-файла"))
	now := time.Now()
	for i := 0; i < 4*fanoutThresh; i++ {
		line := fmt.Sprintf("from 11.8.1.9:%d accepted udp:11.66.%d.%d:%d [x >> DIRECT] email: 3001", i, i%200, i/200+1, 20000+i*7)
		if v := feedLine(line, now.Add(time.Duration(i)*time.Second)); v.Ban {
			t.Fatalf("назначения из списка «не торрент» засчитаны как рой: %+v", v)
		}
	}
}
