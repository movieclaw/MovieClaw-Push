package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func newTable(t *testing.T, enabled ...string) *Table {
	t.Helper()
	tbl, err := NewTable(nil, enabled, Options{AlertTitle: "MovieClaw", AlertBody: "你有一条新通知", AttributesType: "SealedActivityAttributes"})
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func aps(t *testing.T, s string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func build(t *testing.T, tbl *Table, typ string, in input) (*output, *ruleError) {
	t.Helper()
	r, ok := tbl.lookup(typ)
	if !ok {
		t.Fatalf("类型 %s 没开放", typ)
	}
	return tbl.build(r, in)
}

func TestAlertWithPayloadGetsGenericCopy(t *testing.T) {
	tbl := newTable(t, "alert")
	out, err := build(t, tbl, "alert", input{
		APS:     aps(t, `{"interruption-level": "time-sensitive", "badge": 3}`),
		Payload: "v1.k7Qm2xP9.bm9uY2U.Y2lwaGVydGV4dA",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"aps":{"alert":{"body":"你有一条新通知","title":"MovieClaw"},"badge":3,"interruption-level":"time-sensitive","mutable-content":1},"e":"v1.k7Qm2xP9.bm9uY2U.Y2lwaGVydGV4dA"}`
	if string(out.Body) != want {
		t.Fatalf("最终 JSON 不对：\n%s\n%s", out.Body, want)
	}
	if out.Priority != 10 || out.PushType != "alert" || out.TopicSuffix != "" || out.Interruption != "time-sensitive" {
		t.Fatalf("输出不对：%+v", out)
	}
}

func TestAlertWithoutPayloadOnlyForwardsControlFields(t *testing.T) {
	tbl := newTable(t, "alert")
	out, err := build(t, tbl, "alert", input{APS: aps(t, `{"badge": 0}`)})
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Body) != `{"aps":{"badge":0}}` {
		t.Fatalf("不带 payload 时不应加文案：%s", out.Body)
	}
}

func TestSemanticPlaintextIsRejected(t *testing.T) {
	tbl := newTable(t, "alert", "liveactivity")
	cases := []struct {
		typ, aps, reason string
	}{
		{"alert", `{"alert": {"title": "流浪地球 已入库"}}`, "alert"},
		{"alert", `{"thread-id": "subscription-42"}`, "thread-id"},
		{"alert", `{"category": "DOWNLOAD_DONE"}`, "category"},
		{"alert", `{"sound": "download.caf"}`, "sound"},
		{"alert", `{"interruption-level": "critical"}`, "interruption-level"},
		{"alert", `{"badge": -1}`, "badge"},
		{"alert", `{"badge": "3"}`, "badge"},
		{"alert", `{"badge": 1.5}`, "badge"},
		{"alert", `{"relevance-score": null}`, "relevance-score"},
		{"alert", `{"relevance-score": 2}`, "relevance-score"},
		{"liveactivity", `{"timestamp": 1, "event": "update", "content-state": {"progress": 0.5}}`, "content-state"},
		{"liveactivity", `{"timestamp": 1, "event": "update", "content-state": {"e": "明文"}}`, "content-state"},
		{"liveactivity", `{"timestamp": 1, "event": "start", "attributes-type": "DownloadProgress"}`, "attributes-type"},
		{"liveactivity", `{"timestamp": 1, "event": "update", "alert": {"title": "下载完成"}}`, "alert"},
		{"liveactivity", `{"event": "update"}`, "timestamp"},
	}
	for _, c := range cases {
		_, err := build(t, tbl, c.typ, input{APS: aps(t, c.aps)})
		if err == nil || err.Result != ResultInvalidAPS || err.Reason != c.reason {
			t.Errorf("%s %s：期望 invalid_aps/%s，实际 %+v", c.typ, c.aps, c.reason, err)
		}
	}
}

func TestPayloadMustBeOpaque(t *testing.T) {
	tbl := newTable(t, "alert", "widgets")
	if _, err := build(t, tbl, "alert", input{Payload: `{"title":"片名"}`}); err == nil || err.Reason != "payload" {
		t.Fatalf("明文 payload 应被拒绝：%+v", err)
	}
	if _, err := build(t, tbl, "widgets", input{Payload: "v1.a.b.c"}); err == nil || err.Result != ResultInvalidMessage {
		t.Fatalf("widgets 不能带 payload：%+v", err)
	}
}

func TestBackgroundForcesFields(t *testing.T) {
	tbl := newTable(t, "background")
	out, err := build(t, tbl, "background", input{Payload: "v1.a.b.c"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Body) != `{"aps":{"content-available":1},"e":"v1.a.b.c"}` || out.Priority != 5 {
		t.Fatalf("background 输出不对：%s %d", out.Body, out.Priority)
	}
	if _, err := build(t, tbl, "background", input{Priority: 10}); err == nil || err.Reason != "priority" {
		t.Fatalf("background 不能用优先级 10：%+v", err)
	}
	if _, err := build(t, tbl, "background", input{APS: aps(t, `{"badge": 1}`)}); err == nil || err.Reason != "badge" {
		t.Fatalf("background 不能带 badge：%+v", err)
	}
}

func TestLiveActivity(t *testing.T) {
	tbl := newTable(t, "liveactivity")
	out, err := build(t, tbl, "liveactivity", input{APS: aps(t, `{
		"timestamp": 1767225600, "event": "start", "content-state": {"e": "v1.k.n.c"},
		"attributes-type": "SealedActivityAttributes", "attributes": {"e": "v1.k.n.d"}, "alert": true}`)})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		APS map[string]any `json:"aps"`
	}
	if err := json.Unmarshal(out.Body, &got); err != nil {
		t.Fatal(err)
	}
	alert, _ := got.APS["alert"].(map[string]any)
	if alert["title"] != "MovieClaw" || alert["sound"] != "default" {
		t.Fatalf("实时活动的提醒应由中继填通用文案：%s", out.Body)
	}
	if out.TopicSuffix != ".push-type.liveactivity" || out.PushType != "liveactivity" {
		t.Fatalf("topic 后缀或推送类型不对：%+v", out)
	}
}

func TestWidgets(t *testing.T) {
	tbl := newTable(t, "widgets")
	out, err := build(t, tbl, "widgets", input{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Body) != `{"aps":{"content-changed":true}}` || out.TopicSuffix != ".push-type.widgets" {
		t.Fatalf("widgets 输出不对：%s %+v", out.Body, out)
	}
}

func TestPayloadTooLarge(t *testing.T) {
	tbl := newTable(t, "alert")
	_, err := build(t, tbl, "alert", input{Payload: "v1." + strings.Repeat("A", MaxPayloadBytes)})
	if err == nil || err.Result != ResultTooLarge {
		t.Fatalf("超过 4KB 应返回 payload_too_large：%+v", err)
	}
}

func TestOnlyEnabledTypesAreOpen(t *testing.T) {
	tbl := newTable(t, "alert")
	if _, ok := tbl.lookup("background"); ok {
		t.Fatal("没开放的类型不应能用")
	}
	if _, ok := tbl.lookup("voip"); ok {
		t.Fatal("不认识的类型不应能用")
	}
	if _, err := NewTable(nil, []string{"voip"}, Options{}); err == nil {
		t.Fatal("开放没有规则的类型应报错")
	}
}

func TestConfigCanAddRule(t *testing.T) {
	tbl, err := NewTable([]Rule{{Type: "location", TopicSuffix: ".location-query", Priorities: []int{10}, Payload: "forbidden"}},
		[]string{"alert", "location"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, rerr := build(t, tbl, "location", input{})
	if rerr != nil || out.TopicSuffix != ".location-query" {
		t.Fatalf("配置追加的类型不生效：%+v %+v", out, rerr)
	}
	if _, err := NewTable([]Rule{{Type: "x", Priorities: []int{7}, Payload: "optional"}}, nil, Options{}); err == nil {
		t.Fatal("无效优先级应报错")
	}
}
