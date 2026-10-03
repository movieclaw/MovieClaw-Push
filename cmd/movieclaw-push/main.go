// movieclaw-push 是 MovieClaw 的推送中继：把实例发来的密文推送转发给 APNs。
//
// 它看不到推送内容，不知道手机属于谁，也不保存设备令牌。官方中继和自建中继是同一份
// 代码，差别只在配置。用法：
//
//	movieclaw-push [-config config.yaml] [命令]
//
//	serve                      启动中继（默认）
//	token create --name 名称   创建静态令牌（auth.mode: static）
//	token list                 列出静态令牌
//	token revoke <ID>          吊销静态令牌
//	usage [--days 7]           查看按「实例 × 天」汇总的推送计数
//	version                    显示版本
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/movieclaw/movieclaw-push/apns"
	"github.com/movieclaw/movieclaw-push/internal/auth"
	"github.com/movieclaw/movieclaw-push/internal/config"
	"github.com/movieclaw/movieclaw-push/internal/limit"
	"github.com/movieclaw/movieclaw-push/internal/server"
	"github.com/movieclaw/movieclaw-push/protocol"
)

// version 在构建时用 -ldflags "-X main.version=..." 注入。
var version = "dev"

const usageText = `movieclaw-push：MovieClaw 推送中继

用法：
  movieclaw-push [-config 配置文件] [命令]

命令：
  serve                      启动中继（默认）
  token create --name 名称   创建静态令牌（auth.mode: static），令牌只显示一次
  token list                 列出静态令牌
  token revoke <ID>          吊销静态令牌
  usage [--days 7]           查看按「实例 × 天」汇总的推送计数
  version                    显示版本

配置文件默认是当前目录的 config.yaml，也可以用环境变量 MOVIECLAW_PUSH_CONFIG 指定。
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "错误："+err.Error())
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("movieclaw-push", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	defaultConfig := os.Getenv("MOVIECLAW_PUSH_CONFIG")
	if defaultConfig == "" {
		defaultConfig = "config.yaml"
	}
	configPath := fs.String("config", defaultConfig, "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	cmd := "serve"
	if len(rest) > 0 {
		cmd, rest = rest[0], rest[1:]
	}
	switch cmd {
	case "serve":
		return serve(*configPath)
	case "token":
		return tokenCmd(*configPath, rest)
	case "usage":
		return usageCmd(*configPath, rest)
	case "version":
		fmt.Println(version)
		return nil
	case "help":
		fmt.Print(usageText)
		return nil
	}
	return fmt.Errorf("不认识的命令 %q，运行 movieclaw-push help 查看用法", cmd)
}

func serve(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log.Level)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("创建数据目录失败：%w", err)
	}

	table, err := protocol.NewTable(cfg.APNs.Rules, cfg.APNs.Types, protocol.Options{
		AlertTitle: cfg.APNs.AlertTitle, AlertBody: cfg.APNs.AlertBody, AttributesType: cfg.APNs.AttributesType,
	})
	if err != nil {
		return err
	}
	sender, err := newAPNs(cfg, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var authn auth.Authenticator
	switch cfg.Auth.Mode {
	case config.ModeIssuer:
		var issuers []auth.IssuerConfig
		for _, is := range cfg.Auth.Issuers {
			ic := auth.IssuerConfig{Iss: is.Iss, JWKS: is.JWKS, Revocations: is.Revocations}
			if is.KeyFile != "" {
				if ic.Key, err = config.ReadSecret(is.KeyFile); err != nil {
					return err
				}
			}
			issuers = append(issuers, ic)
		}
		iss, err := auth.NewIssuer(cfg.Aud, issuers, cfg.Auth.CacheDir, cfg.Auth.RefreshInterval, log)
		if err != nil {
			return err
		}
		go iss.Run(ctx)
		authn = iss
	case config.ModeStatic:
		authn = auth.NewStatic(tokensPath(cfg))
	case config.ModeNone:
		log.Warn("auth.mode 是 none：任何人都能调用这个中继，只靠按设备的每日上限防刷")
		authn = auth.None{}
	}

	store, err := limit.OpenStore(filepath.Join(cfg.DataDir, "usage.db"), false)
	if err != nil {
		return err
	}
	defer store.Close()
	limiter, err := limit.New(cfg.Limits, store, log, time.Now())
	if err != nil {
		return err
	}
	go limiter.Run(ctx)

	var adminKey string
	if cfg.Admin.KeyFile != "" {
		if adminKey, err = config.ReadSecret(cfg.Admin.KeyFile); err != nil {
			return err
		}
	}

	srv := server.New(server.Options{
		Aud:      cfg.Aud,
		Checker:  protocol.NewChecker(cfg.APNs.Topics, table),
		Auth:     authn,
		Limiter:  limiter,
		Sender:   sender,
		Defaults: cfg.Limits,
		AdminKey: adminKey,
		Version:  version,
		Log:      log,
	})
	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("推送中继已启动", "listen", cfg.Listen, "version", version, "auth", authn.Mode(),
		"types", cfg.APNs.Types, "topics", cfg.APNs.Topics, "dry_run", cfg.APNs.DryRun)

	select {
	case err := <-errc:
		return fmt.Errorf("HTTP 服务异常退出：%w", err)
	case <-ctx.Done():
	}
	log.Info("正在停止推送中继")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		log.Warn("等待进行中的请求结束超时", "error", err)
	}
	if err := limiter.Flush(); err != nil {
		return fmt.Errorf("退出前写入推送计数失败：%w", err)
	}
	return nil
}

func newAPNs(cfg *config.Config, log *slog.Logger) (*apns.Client, error) {
	c := apns.Config{
		ProductionURL:  cfg.APNs.Endpoints.Production,
		DevelopmentURL: cfg.APNs.Endpoints.Development,
		DryRun:         cfg.APNs.DryRun,
		Log:            log,
	}
	for _, k := range cfg.APNs.Keys {
		pem, err := os.ReadFile(k.File)
		if err != nil {
			return nil, fmt.Errorf("读取 APNs 密钥 %s 失败：%w", k.KeyID, err)
		}
		c.Keys = append(c.Keys, apns.Key{TeamID: k.TeamID, KeyID: k.KeyID, PEM: pem})
	}
	if cfg.APNs.CAFile != "" {
		pem, err := os.ReadFile(cfg.APNs.CAFile)
		if err != nil {
			return nil, fmt.Errorf("读取 apns.ca_file 失败：%w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("apns.ca_file 里没有可用的证书")
		}
		c.RootCAs = pool
	}
	return apns.New(c)
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func tokensPath(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "tokens.json") }

func tokenCmd(configPath string, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("用法：movieclaw-push token create --name 名称 | token list | token revoke <ID>")
	}
	path := tokensPath(cfg)
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ContinueOnError)
		name := fs.String("name", "", "令牌名称，比如实例所在的机器「客厅服务器」")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*name) == "" {
			return errors.New("请用 --name 给令牌起个名字，以后查日志、吊销时好认")
		}
		token, rec, err := auth.CreateStaticToken(path, strings.TrimSpace(*name), time.Now())
		if err != nil {
			return err
		}
		if cfg.Auth.Mode != config.ModeStatic {
			fmt.Fprintf(os.Stderr, "注意：当前 auth.mode 是 %s，静态令牌要在 auth.mode: static 时才会生效。\n\n", cfg.Auth.Mode)
		}
		fmt.Printf("已创建令牌「%s」（ID %s）。令牌只显示这一次，请马上填进实例的推送中继设置：\n\n%s\n", rec.Name, rec.ID, token)
		return nil
	case "list":
		list, err := auth.ReadStaticTokens(path)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Println("还没有令牌。用 movieclaw-push token create --name 名称 创建。")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\t名称\t创建时间\t状态")
		for _, t := range list {
			status := "有效"
			if t.RevokedAt != nil {
				status = "已吊销 " + t.RevokedAt.Local().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.ID, t.Name, t.CreatedAt.Local().Format("2006-01-02 15:04"), status)
		}
		return tw.Flush()
	case "revoke":
		if len(args) != 2 {
			return errors.New("用法：movieclaw-push token revoke <ID>")
		}
		if err := auth.RevokeStaticToken(path, args[1], time.Now()); err != nil {
			return err
		}
		fmt.Printf("已吊销令牌 %s，运行中的中继会在一秒内生效。\n", args[1])
		return nil
	}
	return fmt.Errorf("不认识的 token 子命令 %q", args[0])
}

func usageCmd(configPath string, args []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("usage", flag.ContinueOnError)
	days := fs.Int("days", limit.RetentionDays, "查看最近几天（UTC）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := limit.OpenStore(filepath.Join(cfg.DataDir, "usage.db"), true)
	if err != nil {
		return err
	}
	defer store.Close()
	since := time.Now().UTC().AddDate(0, 0, -(max(*days, 1) - 1)).Format("2006-01-02")
	list, err := store.Since(since)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("这段时间没有推送记录（计数每 10 秒写一次盘）。")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "日期（UTC）\t实例\t条数\t设备数\t小时峰值\t失败")
	for _, d := range list {
		inst := d.Instance
		if inst == "" {
			inst = "（未鉴权）"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%s\n", d.Day, inst, d.Count, d.Devices, d.PeakHour, formatCounts(d.Failures))
	}
	return tw.Flush()
}

func formatCounts(m map[string]int64) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, m[k])
	}
	return strings.Join(parts, " ")
}
