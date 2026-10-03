// Package server 是推送中继的 HTTP 接口，协议见 docs/protocol.md。
//
//	GET  /v1/info   协议版本、aud、能推送的 Bundle ID、开放的类型、鉴权方式、默认限额
//	POST /v1/push   批量推送，一次最多 100 条，每条单独返回结果
//	GET  /healthz   健康检查
//
// 整个请求的错误用 HTTP 状态码表示（400 格式错误、401 凭证无效或已吊销），
// 单条推送的结果放在响应里，一条出错不影响同批的其他推送。
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/movieclaw/movieclaw-push/apns"
	"github.com/movieclaw/movieclaw-push/internal/auth"
	"github.com/movieclaw/movieclaw-push/internal/limit"
	"github.com/movieclaw/movieclaw-push/protocol"
)

// Sender 把推送交给苹果，由 apns.Client 实现，测试里可以替换。
type Sender interface {
	Push(ctx context.Context, n *apns.Notification) (*apns.Response, error)
}

// Options 是组装中继需要的全部部件。
type Options struct {
	Aud      string
	Checker  *protocol.Checker
	Auth     auth.Authenticator
	Limiter  *limit.Limiter
	Sender   Sender
	Defaults map[string]int64
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
	mux.HandleFunc("GET /healthz", s.healthz)
	return s.accessLog(mux)
}

func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	protocol.WriteJSON(w, http.StatusOK,
		s.opts.Checker.Info("movieclaw-push/"+s.opts.Version, s.opts.Aud, s.opts.Auth.Info(), s.opts.Defaults))
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	protocol.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
