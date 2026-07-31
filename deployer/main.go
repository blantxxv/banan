package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	installURL  = "https://raw.githubusercontent.com/mahmudali1337-lab/torrent-blocker/master/install.sh"
	serviceName = "torrent-blocker"
)

type server struct {
	ip   string
	user string
	pass string
}

func main() {
	fmt.Println("=== Torrent Blocker Deployer ===")
	fmt.Printf("[*] install.sh: %s\n\n", installURL)

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

func deploy(s server) error {
	client, err := sshConnect(s)
	if err != nil {
		return fmt.Errorf("SSH не удалось: %w", err)
	}
	defer client.Close()
	fmt.Printf("  [SSH] Соединение установлено\n")

	fmt.Println("  [*] Определение ОС...")
	runSSH(client, "cat /etc/os-release 2>/dev/null | grep -E 'PRETTY_NAME|VERSION'")

	fmt.Println("  [*] Проверка наличия curl...")
	out, err := runSSH(client, "which curl 2>/dev/null || (apt-get install -y -qq curl 2>&1 | tail -2 && which curl)")
	if err != nil || strings.TrimSpace(out) == "" {
		return fmt.Errorf("curl недоступен и не удалось установить: %v", err)
	}
	fmt.Printf("  [OK] curl: %s\n", strings.TrimSpace(out))

	fmt.Println("  [*] Запуск install.sh с GitHub...")
	installCmd := fmt.Sprintf("curl -fsSL '%s' | bash", installURL)
	_, err = runSSH(client, installCmd)
	if err != nil {
		return fmt.Errorf("install.sh завершился с ошибкой: %w", err)
	}

	time.Sleep(2 * time.Second)

	fmt.Println("  [*] Проверка статуса службы...")
	statusOut, _ := runSSH(client, "systemctl is-active "+serviceName)
	if strings.TrimSpace(statusOut) == "active" {
		fmt.Printf("  [OK] Служба активна\n")
	} else {
		fmt.Printf("  [WARN] Статус: %s\n", strings.TrimSpace(statusOut))
		runSSH(client, "journalctl -u "+serviceName+" -n 20 --no-pager 2>/dev/null")
	}

	fmt.Println("  [*] Проверка iptables цепочек...")
	runSSH(client, "iptables -L TORRENT_DPI --line-numbers -n 2>/dev/null | head -8")

	return nil
}
