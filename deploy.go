//go:build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	binaryName  = "torrent-blocker"
	remoteBin   = "/usr/local/bin/torrent-blocker"
	serviceName = "torrent-blocker"
	serviceFile = "/etc/systemd/system/torrent-blocker.service"
	startCmd    = "/usr/local/bin/torrent-blocker --log /var/log/remnanode/access.log --tag TORRENT"
)

var serviceUnit = `[Unit]
Description=Torrent Blocker
After=network.target

[Service]
Type=simple
ExecStart=` + startCmd + `
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

type server struct {
	ip   string
	user string
	pass string
}

func main() {
	fmt.Println("=== Torrent Blocker Deployer ===")
	fmt.Println()

	fmt.Println("[*] Компиляция бинарника для Linux amd64...")
	buildEnv := append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	buildCmd := exec.Command("go", "build", "-o", binaryName, "main.go")
	buildCmd.Env = buildEnv
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		fmt.Printf("[ОШИБКА] Компиляция провалилась: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] Бинарник скомпилирован: %s\n\n", binaryName)

	servers := readServers("ssh.txt")
	if len(servers) == 0 {
		fmt.Println("[ОШИБКА] ssh.txt пуст или не найден (формат: ip:user:password)")
		os.Exit(1)
	}
	fmt.Printf("[*] Серверов в очереди: %d\n\n", len(servers))

	success := 0
	failed := 0
	for i, s := range servers {
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("[%d/%d] Деплой на %s (пользователь: %s)\n", i+1, len(servers), s.ip, s.user)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		if err := deploy(s); err != nil {
			fmt.Printf("[ПРОВАЛ] %s: %v\n\n", s.ip, err)
			failed++
		} else {
			fmt.Printf("[УСПЕХ] %s задеплоен\n\n", s.ip)
			success++
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Итог: успешно=%d  провалено=%d  всего=%d\n", success, failed, len(servers))
}

func readServers(path string) []server {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []server
	sc := bufio.NewScanner(f)
	lnum := 0
	for sc.Scan() {
		lnum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			fmt.Printf("[WARN] ssh.txt строка %d пропущена (неверный формат): %s\n", lnum, line)
			continue
		}
		out = append(out, server{
			ip:   strings.TrimSpace(parts[0]),
			user: strings.TrimSpace(parts[1]),
			pass: strings.TrimSpace(parts[2]),
		})
	}
	return out
}

func sshConnect(s server) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{
		User: s.user,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.pass),
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = s.pass
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	addr := s.ip
	if !strings.Contains(addr, ":") {
		addr += ":22"
	}
	fmt.Printf("  [SSH] Подключение к %s...\n", addr)
	return ssh.Dial("tcp", addr, cfg)
}

func runSSH(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	fmt.Printf("  [CMD] %s\n", cmd)
	out, err := sess.CombinedOutput(cmd)
	output := strings.TrimSpace(string(out))
	if output != "" {
		for _, line := range strings.Split(output, "\n") {
			fmt.Printf("        %s\n", line)
		}
	}
	return output, err
}

func uploadFile(client *ssh.Client, localPath, remotePath string) error {
	sftp, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp открыть не удалось: %w", err)
	}
	defer sftp.Close()

	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("локальный файл: %w", err)
	}
	defer src.Close()

	info, _ := src.Stat()
	fmt.Printf("  [UPLOAD] %s -> %s (%d байт)\n", localPath, remotePath, info.Size())

	dst, err := sftp.Create(remotePath)
	if err != nil {
		return fmt.Errorf("создать удалённый файл: %w", err)
	}
	defer dst.Close()

	written, err := dst.ReadFrom(src)
	if err != nil {
		return fmt.Errorf("запись: %w", err)
	}
	fmt.Printf("  [UPLOAD] Записано %d байт\n", written)
	return nil
}

func deploy(s server) error {
	client, err := sshConnect(s)
	if err != nil {
		return fmt.Errorf("SSH не удалось: %w", err)
	}
	defer client.Close()
	fmt.Printf("  [SSH] Соединение установлено\n")

	fmt.Println("  [*] Определение дистрибутива...")
	osOut, _ := runSSH(client, "cat /etc/os-release 2>/dev/null | head -3")
	_ = osOut

	fmt.Println("  [*] Обновление пакетов и установка зависимостей...")
	_, err = runSSH(client, "export DEBIAN_FRONTEND=noninteractive && apt-get update -qq 2>&1 | tail -3")
	if err != nil {
		fmt.Printf("  [WARN] apt-get update: %v\n", err)
	}

	deps := []string{"conntrack", "iptables", "ipset", "net-tools", "iproute2"}
	for _, dep := range deps {
		fmt.Printf("  [*] Установка пакета: %s\n", dep)
		out, err := runSSH(client, fmt.Sprintf("export DEBIAN_FRONTEND=noninteractive && apt-get install -y %s 2>&1 | tail -5", dep))
		if err != nil {
			fmt.Printf("  [WARN] Установка %s: %v (вывод: %s)\n", dep, err, out)
		} else {
			fmt.Printf("  [OK] Пакет %s установлен\n", dep)
		}
	}

	fmt.Println("  [*] Создание директории /var/lib/torrent-blocker...")
	runSSH(client, "mkdir -p /var/lib/torrent-blocker && chmod 750 /var/lib/torrent-blocker")

	fmt.Println("  [*] Остановка старой службы (если есть)...")
	runSSH(client, "systemctl stop "+serviceName+" 2>/dev/null; true")

	fmt.Println("  [*] Загрузка бинарника...")
	if err := uploadFile(client, binaryName, remoteBin); err != nil {
		return fmt.Errorf("загрузка бинарника: %w", err)
	}

	fmt.Println("  [*] Установка прав на исполнение...")
	if _, err := runSSH(client, "chmod +x "+remoteBin); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	fmt.Printf("  [OK] chmod +x %s\n", remoteBin)

	fmt.Println("  [*] Запись systemd unit...")
	escaped := strings.ReplaceAll(serviceUnit, "'", "'\"'\"'")
	_, err = runSSH(client, fmt.Sprintf("cat > %s << 'EOSVC'\n%sEOSVC", serviceFile, serviceUnit))
	if err != nil {
		_, err = runSSH(client, fmt.Sprintf("printf '%%s' '%s' > %s", escaped, serviceFile))
		if err != nil {
			return fmt.Errorf("запись службы: %w", err)
		}
	}
	fmt.Printf("  [OK] Написан файл %s\n", serviceFile)

	fmt.Println("  [*] systemctl daemon-reload...")
	if _, err := runSSH(client, "systemctl daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}

	fmt.Println("  [*] Включение автозапуска...")
	if _, err := runSSH(client, "systemctl enable "+serviceName); err != nil {
		fmt.Printf("  [WARN] enable: %v\n", err)
	} else {
		fmt.Printf("  [OK] systemctl enable %s\n", serviceName)
	}

	fmt.Println("  [*] Запуск службы...")
	if _, err := runSSH(client, "systemctl restart "+serviceName); err != nil {
		return fmt.Errorf("запуск службы: %w", err)
	}

	time.Sleep(2 * time.Second)

	fmt.Println("  [*] Проверка статуса...")
	statusOut, _ := runSSH(client, "systemctl is-active "+serviceName)
	if strings.TrimSpace(statusOut) == "active" {
		fmt.Printf("  [OK] Служба активна (active)\n")
	} else {
		fmt.Printf("  [WARN] Статус службы: %s\n", statusOut)
		journalOut, _ := runSSH(client, "journalctl -u "+serviceName+" -n 20 --no-pager 2>/dev/null")
		fmt.Printf("  [LOG] %s\n", journalOut)
	}

	fmt.Println("  [*] Проверка iptables правил...")
	runSSH(client, "iptables -L TORRENT_DPI --line-numbers -n 2>/dev/null | head -10")

	return nil
}
