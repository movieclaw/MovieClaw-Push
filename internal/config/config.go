// Package config 读取推送中继的 YAML 配置。
//
// 鉴权方式（static / none）、能推送的 Bundle ID、开放的推送类型、APNs 密钥、限额都在配置里，
// 完整示例见 examples/config.yaml。
//
// 配置里的相对路径都相对于配置文件所在的目录，这样自建用户把 .p8 和配置放在一起即可。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/movieclaw/movieclaw-push/protocol"
	"go.yaml.in/yaml/v3"
)

// 鉴权方式。
const (
	// ModeStatic 由中继自己发令牌（movieclaw-push token create），给自建用户用。
	ModeStatic = "static"
	// ModeNone 不鉴权、只按设备限流，只在内网或运营方停运时用。
	ModeNone = "none"
)

// Config 是中继的全部配置。
type Config struct {
	// Listen 是 HTTP 监听地址，默认 :8080。TLS 由前面的反向代理终止。
	Listen string `yaml:"listen"`
	// Aud 是中继的固定标识，写进 /v1/info。
	Aud string `yaml:"aud"`
	// DataDir 存放计数 SQLite 和静态令牌，默认是配置文件旁边的 data/。
	DataDir string `yaml:"data_dir"`
	APNs    APNs   `yaml:"apns"`
	Auth    Auth   `yaml:"auth"`
	// Limits 是限额（day：每个令牌每天，device_day：每台设备每天）。负数表示不限。
	Limits map[string]int64 `yaml:"limits"`
	Log    Log              `yaml:"log"`
	// Admin 是已经去掉的管理接口的配置。只为老配置文件还能加载，启动时提示可以删掉。
	Admin map[string]any `yaml:"admin"`
}

// APNs 是苹果推送相关的配置。
type APNs struct {
	// Keys 是 .p8 密钥，可以挂多把：第一把优先，被苹果拒绝时自动换下一把，换密钥时不中断。
	Keys []Key `yaml:"keys"`
	// Topics 是能推送的基础 Bundle ID 白名单。
	Topics []string `yaml:"topics"`
	// Types 是开放的推送类型，规则见 docs/protocol.md「推送类型」。
	Types []string `yaml:"types"`
	// AlertTitle、AlertBody 是中继替实例填的通用文案，通知扩展解密后会替换掉。
	// 不填时用「MovieClaw」「你有一条新通知」。
	AlertTitle string `yaml:"alert_title"`
	AlertBody  string `yaml:"alert_body"`
	// AttributesType 是实时活动统一使用的、不带语义的 attributes-type，默认 SealedActivityAttributes。
	AttributesType string `yaml:"attributes_type"`
	// Rules 追加或整行覆盖内置的推送类型规则。
	Rules []protocol.Rule `yaml:"rules"`
	// DryRun 为 true 时不连接苹果，直接返回成功并记日志，只用于本地开发。
	DryRun bool `yaml:"dry_run"`
	// Endpoints 覆盖苹果的接口地址，只用于测试。
	Endpoints Endpoints `yaml:"endpoints"`
	// CAFile 是额外信任的根证书（PEM），只用于测试。
	CAFile string `yaml:"ca_file"`
}

// Key 是一把 APNs 鉴权密钥（.p8）。
type Key struct {
	TeamID string `yaml:"team_id"`
	KeyID  string `yaml:"key_id"`
	File   string `yaml:"file"`
}

// Endpoints 是苹果正式环境和测试环境的接口地址。
type Endpoints struct {
	Production  string `yaml:"production"`
	Development string `yaml:"development"`
}

// Auth 是实例鉴权的配置。
type Auth struct {
	Mode string `yaml:"mode"`
}

// Log 是日志配置。
type Log struct {
	Level string `yaml:"level"` // debug / info / warn / error
}

// Load 读取、补默认值并检查配置。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败：%w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // 拼错的字段名直接报错，免得配置悄悄不生效
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("配置文件 %s 格式错误：%w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c.applyDefaults(filepath.Dir(abs))
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("配置文件 %s 有误：%w", path, err)
	}
	return &c, nil
}

func (c *Config) applyDefaults(base string) {
	resolve := func(p *string) {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	resolve(&c.DataDir)
	for i := range c.APNs.Keys {
		resolve(&c.APNs.Keys[i].File)
	}
	resolve(&c.APNs.CAFile)
	if len(c.APNs.Types) == 0 {
		c.APNs.Types = []string{"alert"}
	}
	if c.Limits == nil {
		c.Limits = map[string]int64{}
	}
	if _, ok := c.Limits["day"]; !ok {
		c.Limits["day"] = 5000
	}
	if _, ok := c.Limits["device_day"]; !ok {
		c.Limits["device_day"] = 500
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
}

func (c *Config) validate() error {
	var errs []error
	if len(c.APNs.Topics) == 0 {
		errs = append(errs, errors.New("apns.topics 不能为空：至少写一个能推送的 Bundle ID"))
	}
	if len(c.APNs.Keys) == 0 && !c.APNs.DryRun {
		errs = append(errs, errors.New("apns.keys 不能为空：需要至少一把 .p8 密钥（本地开发可以设 apns.dry_run: true）"))
	}
	for i, k := range c.APNs.Keys {
		if k.TeamID == "" || k.KeyID == "" || k.File == "" {
			errs = append(errs, fmt.Errorf("apns.keys[%d] 的 team_id、key_id、file 都要填", i))
		}
	}
	switch c.Auth.Mode {
	case ModeStatic, ModeNone:
	case "":
		errs = append(errs, errors.New("auth.mode 没有配置，可选 static、none"))
	default:
		errs = append(errs, fmt.Errorf("auth.mode 只能是 static、none，不能是 %q", c.Auth.Mode))
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level 只能是 debug、info、warn、error，不能是 %q", c.Log.Level))
	}
	return errors.Join(errs...)
}
