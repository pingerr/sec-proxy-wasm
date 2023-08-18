package denyallhaveoncemem

import (
	"bytes"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"strings"
)

func PluginStart() {
	proxywasm.SetVMContext(&vmContext{})
}

type (
	vmContext struct {
		types.DefaultVMContext
	}
	pluginContext struct {
		types.DefaultPluginContext
		hRule *Rule
		cRule *Rule
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID uint32
		p         *pluginContext
	}

	Rule struct {
		key string
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		hRule: &Rule{},
		cRule: &Rule{},
	}
}

func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{contextID: contextID, p: p}
}

func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	data, err := proxywasm.GetPluginConfiguration()
	if data == nil {
		return types.OnPluginStartStatusOK
	}
	if err != nil {
		return types.OnPluginStartStatusFailed
	}
	if !gjson.Valid(string(data)) {
		return types.OnPluginStartStatusFailed
	}

	results := gjson.Get(string(data), "cc_rules").Array()
	for i := range results {
		curMap := results[i].Map()
		if headerKey := curMap["header"].Str; headerKey != "" {
			var hRule Rule
			hRule.key = headerKey
			p.hRule = &hRule
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			var cRule Rule
			cRule.key = cookieKey
			p.cRule = &cRule
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	headerValue, _ := proxywasm.GetHttpRequestHeader(ctx.p.hRule.key)
	if headerValue != "" {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
		return types.ActionContinue
	}

	cookies, _ := proxywasm.GetHttpRequestHeader("cookie")
	if cookies == "" {
		return types.ActionContinue
	}
	cSub := bytes.NewBufferString(ctx.p.cRule.key)
	cSub.WriteString("=")
	cookieValue := strings.Replace(cookies, cSub.String(), "", -1)
	if cookieValue != "" {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
		return types.ActionContinue
	}

	return types.ActionContinue
}
