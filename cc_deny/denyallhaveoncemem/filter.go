package denyallhaveoncemem

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
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
		rules []*Rule
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID uint32
		p         *pluginContext
	}

	Rule struct {
		isHeader bool
		key      string
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		rules: []*Rule{},
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
			hRule.isHeader = true
			p.rules = append(p.rules, &hRule)
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			var cRule Rule
			cRule.key = cookieKey
			cRule.isHeader = false
			p.rules = append(p.rules, &cRule)
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {

	for _, rule := range ctx.p.rules {
		if rule.isHeader {
			headerValue, err := proxywasm.GetHttpRequestHeader(rule.key)
			if err == nil && headerValue != "" {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
				return types.ActionContinue
			}
			//} else {
			//	cookies, _ := proxywasm.GetHttpRequestHeader("cookie")
			//	if cookies == "" {
			//		continue
			//	}
			//	cSub := bytes.NewBufferString(rule.key)
			//	cSub.WriteString("=")
			//	if strings.HasPrefix(cookies, cSub.String()) {
			//		cookieValue := strings.Replace(cookies, cSub.String(), "", -1)
			//		if cookieValue != "" {
			//			_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			//			return types.ActionContinue
			//		}
			//	}
		}
	}

	return types.ActionContinue
}
