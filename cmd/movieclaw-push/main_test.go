package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/movieclaw/movieclaw-push/internal/auth"
	"github.com/movieclaw/movieclaw-push/protocol/protocoltest"
)

// TestConformance 编译真实的中继程序，用 static 鉴权起两个进程（一个额度正常、一个当天
// 限额为 0），对它们跑协议一致性测试。
func TestConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("要编译程序、起进程")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "movieclaw-push")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("编译失败：%v\n%s", err, out)
	}
	apns := protocoltest.NewAPNs(t)
	writeFile(t, filepath.Join(dir, "ca.pem"), apns.CertPEM())
	writeFile(t, filepath.Join(dir, "AuthKey.p8"), protocoltest.GenerateP8(t))

	normal, token := startRelay(t, bin, dir, "normal", apns, "day: 1000\n  device_day: 100")
	limitedURL, limitedToken := startRelay(t, bin, dir, "limited", apns, "day: 0\n  device_day: 100")
	protocoltest.Run(t, protocoltest.Target{
		URL: normal, Token: token, LimitedURL: limitedURL, LimitedToken: limitedToken,
		Topic: "io.movieclaw.app", APNs: apns,
	})
}

// startRelay 写配置、建一个静态令牌、启动中继，返回地址和令牌。
func startRelay(t *testing.T, bin, dir, name string, apns *protocoltest.APNs, limits string) (string, string) {
	t.Helper()
	addr := freeAddr(t)
	data := filepath.Join(dir, name)
	config := filepath.Join(dir, name+".yaml")
	writeFile(t, config, fmt.Appendf(nil, `listen: %q
aud: https://push.test
data_dir: %s
apns:
  keys:
    - {team_id: TEAM123456, key_id: KEY1234567, file: AuthKey.p8}
  topics: [io.movieclaw.app]
  types: [alert]
  endpoints: {production: %q, development: %q}
  ca_file: ca.pem
auth:
  mode: static
limits:
  %s
`, addr, data, apns.URL(), apns.URL(), limits))
	token, _, err := auth.CreateStaticToken(filepath.Join(data, "tokens.json"), name, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	logFile, err := os.Create(filepath.Join(dir, name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-config", config, "serve")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		logFile.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logFile.Name())
			t.Logf("%s 中继的日志：\n%s", name, b)
		}
	})

	url := "http://" + addr
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if resp, err := http.Get(url + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return url, token
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s 中继 10 秒内没有就绪", name)
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
