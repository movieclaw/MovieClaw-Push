package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const base = "apns:\n  topics: [io.movieclaw.app]\n  dry_run: true\n"

// 老配置里的 admin（已经去掉的管理接口）仍能加载，免得自建用户升级后起不来。
func TestOldAdminStillLoads(t *testing.T) {
	c, err := Load(write(t, base+"auth:\n  mode: static\nadmin:\n  key_file: ./admin-key\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Admin == nil || c.Limits["day"] != 5000 || c.Limits["device_day"] != 500 {
		t.Fatalf("配置不对：%+v", c)
	}
}

func TestRejectsRemovedIssuerMode(t *testing.T) {
	_, err := Load(write(t, base+"auth:\n  mode: issuer\n"))
	if err == nil || !strings.Contains(err.Error(), "static、none") {
		t.Fatalf("issuer 模式应报错并说明可选值：%v", err)
	}
}
