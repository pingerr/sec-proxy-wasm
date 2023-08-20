package errortest

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"sync"
)

func PluginStart() {
	proxywasm.SetVMContext(&vmContext{})
}

const (
	secondNano = 1000 * 1000 * 1000
	minuteNano = 60 * secondNano
	hourNano   = 60 * minuteNano
	dayNano    = 24 * hourNano
	cookiePre  = "c:"
	headerPre  = "h:"
)

type (
	vmContext struct {
		types.DefaultVMContext
	}
	pluginContext struct {
		types.DefaultPluginContext
		limitMap map[string]*Limiter
		rules    []*Rule
		mu       sync.Mutex
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID uint32
		p         *pluginContext
	}

	Limiter struct {
		sTokens     int64
		mTokens     int64
		dTokens     int64
		sRefillTime int64
		mRefillTime int64
		dRefillTime int64
		unlockTime  int64
		isBlock     bool
	}

	Rule struct {
		headerOrCookie bool
		key            string
		qps            int64
		qpm            int64
		qpd            int64
		needBlock      bool
		blockTime      int64
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		limitMap: map[string]*Limiter{},
		mu:       sync.Mutex{},
		rules:    []*Rule{},
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
	s := make([]string, 3)
	if len(results) <= 2 {
		proxywasm.LogInfof("len: %d", s[5])
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	return types.ActionContinue
}
