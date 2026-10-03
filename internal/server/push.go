package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/movieclaw/movieclaw-push/internal/auth"
	"github.com/movieclaw/movieclaw-push/internal/limit"
	"github.com/movieclaw/movieclaw-push/protocol"
)

// concurrency 是一个批次里同时发给苹果的条数，它们共用一条 HTTP/2 连接的多个流。
const concurrency = 8

func (s *Server) push(w http.ResponseWriter, r *http.Request) {
	p, err := s.opts.Auth.Authenticate(r.Context(), protocol.Bearer(r))
	if err != nil {
		protocol.WriteError(w, err)
		return
	}
	messages, rerr := protocol.ReadBatch(w, r)
	if rerr != nil {
		protocol.WriteError(w, rerr)
		return
	}

	results := make([]protocol.Result, len(messages))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, raw := range messages {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			results[i] = s.deliver(r.Context(), p, raw)
		})
	}
	wg.Wait()

	// 带上剩余额度，实例快到上限时可以主动取舍：优先发 alert，静默推送和实时活动可以丢
	protocol.WriteJSON(w, http.StatusOK, protocol.Response{
		Results: results, Quota: s.opts.Limiter.Quota(p.Instance, s.now()),
	})
}

// deliver 处理一条推送：按协议检查 → 限额 → 发给苹果。
func (s *Server) deliver(ctx context.Context, p *auth.Principal, raw json.RawMessage) protocol.Result {
	now := s.now()
	prep, rejected := s.opts.Checker.Prepare(raw)
	if rejected != nil {
		return s.finish(ctx, p, prep, *rejected)
	}
	attempt := limit.Attempt{Device: prep.Device, Type: prep.Type, Priority: prep.Priority, Interruption: prep.Interruption}
	if d := s.opts.Limiter.Admit(p.Instance, attempt, now); d != nil {
		return s.finish(ctx, p, prep, protocol.RateLimited(prep.ID, d.Limit, d.RetryAfter, d.Message))
	}
	resp, err := s.opts.Sender.Push(ctx, prep.Notification)
	return s.finish(ctx, p, prep, protocol.Outcome(prep.ID, resp, err))
}

// finish 记失败计数和日志。日志只记实例、追踪 id、令牌哈希前缀和结果，不记内容和完整令牌。
func (s *Server) finish(ctx context.Context, p *auth.Principal, prep protocol.Prepared, res protocol.Result) protocol.Result {
	if res.Result != protocol.ResultOK {
		s.opts.Limiter.Fail(p.Instance, res.Result, s.now())
	}
	level := slog.LevelInfo
	if res.Result == protocol.ResultAPNsError {
		level = slog.LevelWarn
	}
	s.opts.Log.Log(ctx, level, "推送", append([]any{"instance", p.Instance}, prep.LogAttrs(res)...)...)
	return res
}
