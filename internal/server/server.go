// Package server 是推送中继的 HTTP 接口，协议见 docs/protocol.md。
//
//	GET  /v1/info          协议版本、aud、能推送的 Bundle ID、开放的类型、鉴权方式、默认限额
//	POST /v1/push          批量推送，一次最多 100 条，每条单独返回结果
//	GET  /admin/v1/usage   按「实例 × 天」汇总的计数（管理密钥）
//	GET  /healthz          健康检查
//
// 整个请求的错误用 HTTP 状态码表示（400 格式错误、401 凭证无效或已吊销、403 缺少权限），
// 单条推送的结果放在响应里，一条出错不影响同批的其他推送。
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/movieclaw/movieclaw-push/internal/apns"
	"github.com/movieclaw/movieclaw-push/internal/auth"
	"github.com/movieclaw/movieclaw-push/internal/limit"
	"github.com/movieclaw/movieclaw-push/internal/rules"
)

// ProtocolVersion 是推送中继协议的版本。只有破坏兼容时才升；加类型、加字段、加限额都不算。
const ProtocolVersion = 1

// MaxBatch 是一次请求最多带的推送条数。
const MaxBatch = 100

// Sender 把推送交给苹果，由 apns.Client 实现，测试里可以替换。
type Sender interface {
	Push(ctx context.Context, n *apns.Notification) (*apns.Response, error)
}

// Options 是组装中继需要的全部部件。
type Options struct {
	Aud      string
	Topics   []string
	Rules    *rules.Table
	Auth     auth.Authenticator
	Limiter  *limit.Limiter
	Sender   Sender
	Defaults map[string]int64
	// AdminKey 是 /admin/v1/usage 的管理密钥，为空时该接口关闭。
	AdminKey string
	Version  string
	Log      *slog.Logger
}

// Server 是推送中继的 HTTP 服务。
type Server struct {
	opts Options
	now  func() time.Time
}

// New 创建中继服务。
func New(opts Options) *Server {
	return &Server{opts: opts, now: time.Now}
}

// Handler 返回中继的全部路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", s.info)
	mux.HandleFunc("POST /v1/push", s.push)
	mux.HandleFunc("GET /admin/v1/usage", s.usage)
	mux.HandleFunc("GET /healthz", s.healthz)
	return s.accessLog(mux)
}

func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol":          ProtocolVersion,
		"software":          "movieclaw-push/" + s.opts.Version,
		"aud":               s.opts.Aud,
		"platforms":         []string{"apns"},
		"environments":      []string{"production", "development"},
		"topics":            s.opts.Topics,
		"types":             s.opts.Rules.Describe(),
		"auth":              s.opts.Auth.Info(),
		"limits":            s.opts.Defaults,
		"max_batch":         MaxBatch,
		"max_payload_bytes": rules.MaxPayloadBytes,
	})
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	if !s.opts.Auth.Ready() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "degraded", "message": "还没有拿到签发方的公钥，暂时无法验证实例凭证",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// usage 给 api 每小时拉取按天汇总的计数。since 是起始日期（UTC，含），默认最近 7 天。
func (s *Server) usage(w http.ResponseWriter, r *http.Request) {
	if s.opts.AdminKey == "" {
		writeError(w, http.StatusNotFound, "not_found", "管理接口没有开启（配置 admin.key_file 后开启）")
		return
	}
	got := bearer(r)
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.opts.AdminKey)) != 1 {
		writeError(w, http.StatusUnauthorized, "unauthorized", "管理密钥不对")
		return
	}
	since := r.URL.Query().Get("since")
	if since == "" {
		since = s.now().UTC().AddDate(0, 0, -(limit.RetentionDays - 1)).Format("2006-01-02")
	} else if _, err := time.Parse("2006-01-02", since); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "since 必须是 YYYY-MM-DD 格式的日期")
		return
	}
	days, err := s.opts.Limiter.Usage(since)
	if err != nil {
		s.opts.Log.Error("读取推送计数失败", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "读取推送计数失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": days})
}

// accessLog 记录每个请求，健康检查除外（监控每分钟都在调）。
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if r.URL.Path == "/healthz" {
			return
		}
		s.opts.Log.Info("请求", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError 写整个请求级别的错误：{"error": "<错误码>", "message": "<中文说明>"}。
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

// topicAllowed 检查基础 Bundle ID 是否在白名单里。
func (s *Server) topicAllowed(topic string) bool {
	return slices.Contains(s.opts.Topics, topic)
}
