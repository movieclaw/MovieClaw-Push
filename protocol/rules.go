package protocol

// 推送类型规则表和 aps 允许清单。
//
// APNs 有 12 种推送类型，每种的 topic 后缀、优先级规则、负载字段都不同。这些差异写成
// 一张表（内置的 defaults.yaml + 中继配置里追加的规则），加新类型只是加一行配置，不改协议。
//
// 这里也是「中继只看得到密文」这条承诺的执行点：实例发来的 aps 只能包含表里允许的
// 控制类字段，任何能看出语义的文字（alert 下的文字、thread-id、category……）一律拒绝；
// 需要文案的地方由中继填通用文案，通知扩展解密后再替换。

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed defaults.yaml
var defaultsYAML []byte

// opaque 匹配不透明值：只有 base64url 字符和点。payload 与 sealed 字段里的密文都必须是它，
// 这样明文 JSON、中文文案之类的东西根本塞不进来。
var opaque = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// Field 是一个 aps 字段的取值规则，kind 的含义见 defaults.yaml 开头的说明。
type Field struct {
	Kind     string   `yaml:"kind" json:"kind"`
	Values   []string `yaml:"values,omitempty" json:"values,omitempty"`
	Min      *float64 `yaml:"min,omitempty" json:"min,omitempty"`
	Max      *float64 `yaml:"max,omitempty" json:"max,omitempty"`
	Required bool     `yaml:"required,omitempty" json:"required,omitempty"`
}

// Rule 是一种推送类型的规则。
type Rule struct {
	// Type 是协议里的推送类型名，同时也是 apns-push-type 的取值。
	Type string `yaml:"type"`
	// TopicSuffix 由中继补在基础 Bundle ID 后面，实例不用记各类型的后缀规则。
	TopicSuffix string `yaml:"topic_suffix"`
	// Priorities 是允许的 apns-priority，第一个是实例没填时的默认值。
	Priorities []int `yaml:"priorities"`
	// Payload 是 optional（可以带密文）或 forbidden（不能带）。
	Payload string `yaml:"payload"`
	// GenericAlert 为 true 时，带 payload 的推送由中继加通用文案和 mutable-content。
	GenericAlert bool `yaml:"generic_alert"`
	// Force 是强制加进 aps 的字段，覆盖实例填的同名字段。
	Force map[string]any `yaml:"force"`
	// Fields 是实例可以填写的 aps 字段，不在这里的一律拒绝。
	Fields map[string]Field `yaml:"fields"`
}

var validKinds = map[string]bool{
	"uint": true, "timestamp": true, "range": true, "enum": true,
	"sealed": true, "const": true, "generic_alert": true,
}

func (r *Rule) check() error {
	if r.Type == "" {
		return fmt.Errorf("推送类型规则缺少 type")
	}
	if len(r.Priorities) == 0 {
		return fmt.Errorf("推送类型 %s 没有写 priorities", r.Type)
	}
	for _, p := range r.Priorities {
		if p != 1 && p != 5 && p != 10 {
			return fmt.Errorf("推送类型 %s 的优先级 %d 无效，APNs 只接受 1、5、10", r.Type, p)
		}
	}
	if r.Payload != "optional" && r.Payload != "forbidden" {
		return fmt.Errorf("推送类型 %s 的 payload 只能是 optional 或 forbidden", r.Type)
	}
	for name, f := range r.Fields {
		switch {
		case !validKinds[f.Kind]:
			return fmt.Errorf("推送类型 %s 的字段 %s 用了不认识的 kind %q", r.Type, name, f.Kind)
		case f.Kind == "enum" && len(f.Values) == 0:
			return fmt.Errorf("推送类型 %s 的字段 %s 是 enum，但没有写 values", r.Type, name)
		case f.Kind == "range" && (f.Min == nil || f.Max == nil):
			return fmt.Errorf("推送类型 %s 的字段 %s 是 range，但没有写 min 和 max", r.Type, name)
		}
	}
	return nil
}

// Options 是规则表用到的配置值，留空的用默认值。
type Options struct {
	// AlertTitle、AlertBody 是中继替实例填的通用文案，默认「MovieClaw」「你有一条新通知」。
	AlertTitle string
	AlertBody  string
	// AttributesType 是实时活动统一使用的、不带语义的 attributes-type，默认 SealedActivityAttributes。
	AttributesType string
}

// 通用文案和实时活动类型名的默认值。
const (
	DefaultAlertTitle     = "MovieClaw"
	DefaultAlertBody      = "你有一条新通知"
	DefaultAttributesType = "SealedActivityAttributes"
)

// Table 是生效的规则表。只有 enabled 里的类型对实例开放。
type Table struct {
	rules   map[string]*Rule
	enabled []string
	opts    Options
}

// NewTable 合并内置规则和配置里的 extra（同名整行覆盖），并检查 enabled 里的类型都有规则。
func NewTable(extra []Rule, enabled []string, opts Options) (*Table, error) {
	var defaults []Rule
	if err := yaml.Unmarshal(defaultsYAML, &defaults); err != nil {
		return nil, fmt.Errorf("内置规则表格式错误：%w", err)
	}
	if opts.AlertTitle == "" {
		opts.AlertTitle = DefaultAlertTitle
	}
	if opts.AlertBody == "" {
		opts.AlertBody = DefaultAlertBody
	}
	if opts.AttributesType == "" {
		opts.AttributesType = DefaultAttributesType
	}
	t := &Table{rules: map[string]*Rule{}, opts: opts}
	for _, r := range append(defaults, extra...) {
		if err := r.check(); err != nil {
			return nil, err
		}
		t.rules[r.Type] = &r
	}
	for _, typ := range enabled {
		if t.rules[typ] == nil {
			return nil, fmt.Errorf("apns.types 里的 %q 没有对应的规则，请在 apns.rules 里补上", typ)
		}
		if !slices.Contains(t.enabled, typ) {
			t.enabled = append(t.enabled, typ)
		}
	}
	return t, nil
}

// lookup 返回开放的推送类型的规则；没开放或不认识的类型返回 false。
func (t *Table) lookup(typ string) (*Rule, bool) {
	if !slices.Contains(t.enabled, typ) {
		return nil, false
	}
	return t.rules[typ], true
}

// Describe 给 /v1/info 用：开放的类型及各自的优先级、payload 规则和 aps 允许清单。
func (t *Table) Describe() map[string]any {
	out := map[string]any{}
	for _, typ := range t.enabled {
		r := t.rules[typ]
		d := map[string]any{"priorities": r.Priorities, "payload": r.Payload, "aps": r.Fields}
		if _, ok := r.Fields["attributes-type"]; ok {
			d["attributes_type"] = t.opts.AttributesType
		}
		out[typ] = d
	}
	return out
}

// input 是实例发来的一条推送里和类型规则有关的部分。
type input struct {
	Priority int
	APS      map[string]json.RawMessage
	Payload  string
}

// output 是按规则处理后要交给苹果的内容。
type output struct {
	PushType    string
	TopicSuffix string
	Priority    int
	Body        []byte
	// Interruption 是 aps 里的 interruption-level，只用于计数。
	Interruption string
}

// ruleError 是一条推送没通过规则检查。
type ruleError struct {
	Result  string // invalid_aps / invalid_message / payload_too_large
	Reason  string // 出问题的字段
	Message string // 给人看的中文说明
}

// build 按规则检查一条推送，并拼出最终发给苹果的 JSON：
//
//	{"aps": {实例填的控制字段 + 强制字段 + 通用文案}, "e": "<payload 密文>"}
func (t *Table) build(r *Rule, in input) (*output, *ruleError) {
	out := &output{PushType: r.Type, TopicSuffix: r.TopicSuffix, Priority: in.Priority}
	if out.Priority == 0 {
		out.Priority = r.Priorities[0]
	} else if !slices.Contains(r.Priorities, out.Priority) {
		return nil, &ruleError{ResultInvalidMessage, "priority",
			fmt.Sprintf("%s 类型只允许优先级 %s", r.Type, joinInts(r.Priorities))}
	}
	if in.Payload != "" {
		if r.Payload == "forbidden" {
			return nil, &ruleError{ResultInvalidMessage, "payload", fmt.Sprintf("%s 类型不能带 payload", r.Type)}
		}
		if !opaque.MatchString(in.Payload) {
			return nil, &ruleError{ResultInvalidMessage, "payload", "payload 只能是不透明的密文（base64url 字符和点）"}
		}
	}

	aps := map[string]any{}
	// 按字段名排序检查，同一条坏推送每次报同一个字段
	for _, name := range slices.Sorted(maps.Keys(in.APS)) {
		f, ok := r.Fields[name]
		if !ok {
			return nil, &ruleError{ResultInvalidAPS, name, fmt.Sprintf("%s 类型的 aps 里不允许出现 %s", r.Type, name)}
		}
		v, problem := t.check(f, in.APS[name])
		if problem != "" {
			return nil, &ruleError{ResultInvalidAPS, name, name + problem}
		}
		aps[name] = v
	}
	for _, name := range slices.Sorted(maps.Keys(r.Fields)) {
		if _, ok := in.APS[name]; r.Fields[name].Required && !ok {
			return nil, &ruleError{ResultInvalidAPS, name, fmt.Sprintf("%s 类型的 aps 必须带 %s", r.Type, name)}
		}
	}
	maps.Copy(aps, r.Force)
	if r.GenericAlert && in.Payload != "" {
		aps["alert"] = map[string]string{"title": t.opts.AlertTitle, "body": t.opts.AlertBody}
		aps["mutable-content"] = 1
	}
	if s, ok := aps["interruption-level"].(string); ok {
		out.Interruption = s
	}

	body := map[string]any{"aps": aps}
	if in.Payload != "" {
		body["e"] = in.Payload
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, &ruleError{ResultInvalidAPS, "", "aps 无法序列化：" + err.Error()}
	}
	if len(b) > MaxPayloadBytes {
		return nil, &ruleError{ResultTooLarge, "",
			fmt.Sprintf("最终发给苹果的 JSON 有 %d 字节，超过 %d 字节上限", len(b), MaxPayloadBytes)}
	}
	out.Body = b
	return out, nil
}

// check 按字段规则检查一个值，返回要放进 aps 的值；不合规时返回说明（拼在字段名后面）。
func (t *Table) check(f Field, raw json.RawMessage) (any, string) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, " 不能是 null"
	}
	switch f.Kind {
	case "uint":
		n, ok := asInt(raw)
		if !ok || n < 0 || n > math.MaxInt32 {
			return nil, " 必须是非负整数"
		}
		return n, ""
	case "timestamp":
		n, ok := asInt(raw)
		if !ok || n <= 0 {
			return nil, " 必须是 Unix 时间戳（秒）"
		}
		return n, ""
	case "range":
		x, ok := asFloat(raw)
		if !ok || x < *f.Min || x > *f.Max {
			return nil, fmt.Sprintf(" 必须是 %g 到 %g 之间的数", *f.Min, *f.Max)
		}
		return x, ""
	case "enum":
		var s string
		if json.Unmarshal(raw, &s) != nil || !slices.Contains(f.Values, s) {
			return nil, " 只能是 " + strings.Join(f.Values, "、")
		}
		return s, ""
	case "sealed":
		var obj map[string]string
		if json.Unmarshal(raw, &obj) != nil || len(obj) != 1 || !opaque.MatchString(obj["e"]) {
			return nil, ` 只能是 {"e": "<密文>"}`
		}
		return obj, ""
	case "const":
		var s string
		if json.Unmarshal(raw, &s) != nil || s != t.opts.AttributesType {
			return nil, " 只能是 " + t.opts.AttributesType
		}
		return s, ""
	case "generic_alert":
		if !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
			return nil, " 只能是 true，文案由中继填写"
		}
		return map[string]string{"title": t.opts.AlertTitle, "body": t.opts.AlertBody, "sound": "default"}, ""
	}
	return nil, " 的规则无效"
}

// number 解出一个 JSON 数字字面量；字符串形式的 "5" 不算数字。
func number(raw json.RawMessage) (json.Number, bool) {
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return "", false
	}
	n, ok := v.(json.Number)
	return n, ok
}

func asInt(raw json.RawMessage) (int64, bool) {
	n, ok := number(raw)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	return i, err == nil
}

func asFloat(raw json.RawMessage) (float64, bool) {
	n, ok := number(raw)
	if !ok {
		return 0, false
	}
	x, err := n.Float64()
	return x, err == nil
}

func joinInts(xs []int) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = strconv.Itoa(x)
	}
	return strings.Join(s, "、")
}
