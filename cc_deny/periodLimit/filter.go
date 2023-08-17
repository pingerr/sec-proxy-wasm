package periodLimit

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"strings"
	"sync"
	"time"
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
		headerMap map[string]*MyLimiter
		cookieMap map[string]*MyLimiter
		config    Config
		mu        sync.Mutex
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID     uint32
		pluginContext *pluginContext
	}

	MyLimiter struct {
		qpsRemainTokens int64
		qpmRemainTokens int64
		qpdRemainTokens int64
		qpsLastFillTime int64
		qpmLastFillTime int64
		qpdLastFillTime int64
	}

	Config struct {
		headerKey       string
		headerQps       int64
		headerQpm       int64
		headerQpd       int64
		headerBlockNano int64

		cookieKey       string
		cookieQps       int64
		cookieQpm       int64
		cookieQpd       int64
		cookieBlockNano int64
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		headerMap: map[string]*MyLimiter{},
		cookieMap: map[string]*MyLimiter{},
		mu:        sync.Mutex{},
		config:    Config{},
	}
}

func (p *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{contextID: contextID, pluginContext: p}
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
			p.config.headerKey = headerKey
			if qps := curMap["qps"].Int(); qps != 0 {
				p.config.headerQps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				p.config.headerQpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				p.config.headerQpd = qpd
			}
			if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
				p.config.headerBlockNano = headerBlockTime * 1e9
			}
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			p.config.cookieKey = cookieKey
			if qps := curMap["qps"].Int(); qps != 0 {
				p.config.cookieQps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				p.config.cookieQpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				p.config.cookieQpd = qpd
			}
			if cookieBlockTime := curMap["block_seconds"].Int(); cookieBlockTime != 0 {
				p.config.cookieBlockNano = cookieBlockTime * 1e9
			}
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	curNanoSec := time.Now().UnixNano()

	ctx.pluginContext.mu.Lock()
	defer ctx.pluginContext.mu.Unlock()

	headerValue, _ := proxywasm.GetHttpRequestHeader(ctx.pluginContext.config.headerKey)
	if headerValue != "" {
		hLimiter, isOk := ctx.pluginContext.headerMap[headerValue]
		if !isOk {
			var newHLimiter MyLimiter
			if ctx.pluginContext.config.headerQps != 0 {
				newHLimiter.qpsRemainTokens = ctx.pluginContext.config.headerQps - 1
				newHLimiter.qpsLastFillTime = curNanoSec
			}
			if ctx.pluginContext.config.headerQpm != 0 {
				newHLimiter.qpmRemainTokens = ctx.pluginContext.config.headerQpm - 1
				newHLimiter.qpmLastFillTime = curNanoSec
			}
			if ctx.pluginContext.config.headerQpd != 0 {
				newHLimiter.qpdRemainTokens = ctx.pluginContext.config.headerQpd - 1
				newHLimiter.qpdLastFillTime = curNanoSec
			}
			ctx.pluginContext.headerMap[headerValue] = &newHLimiter

		} else {
			if ctx.pluginContext.config.headerBlockNano != 0 {
				if hLimiter.qpsLastFillTime != 0 && curNanoSec > hLimiter.qpsLastFillTime+ctx.pluginContext.config.headerBlockNano {
					hLimiter.qpsRemainTokens = ctx.pluginContext.config.headerQps
					hLimiter.qpsLastFillTime = curNanoSec
				}
				if hLimiter.qpmLastFillTime != 0 && curNanoSec > hLimiter.qpmLastFillTime+ctx.pluginContext.config.headerBlockNano {
					hLimiter.qpmRemainTokens = ctx.pluginContext.config.headerQpm
					hLimiter.qpmLastFillTime = curNanoSec
				}
				if hLimiter.qpdLastFillTime != 0 && curNanoSec > hLimiter.qpdLastFillTime+ctx.pluginContext.config.headerBlockNano {
					hLimiter.qpdRemainTokens = ctx.pluginContext.config.headerQpd
					hLimiter.qpdLastFillTime = curNanoSec
				}
			} else {
				if hLimiter.qpsLastFillTime != 0 && curNanoSec > hLimiter.qpsLastFillTime+1e9 {
					hLimiter.qpsRemainTokens = ctx.pluginContext.config.headerQps
					hLimiter.qpsLastFillTime = curNanoSec
				}
				if hLimiter.qpmLastFillTime != 0 && curNanoSec > hLimiter.qpmLastFillTime+1e9*60 {
					hLimiter.qpmRemainTokens = ctx.pluginContext.config.headerQpm
					hLimiter.qpmLastFillTime = curNanoSec
				}
				if hLimiter.qpdLastFillTime != 0 && curNanoSec > hLimiter.qpdLastFillTime+1e9*86400 {
					hLimiter.qpdRemainTokens = ctx.pluginContext.config.headerQpd
					hLimiter.qpdLastFillTime = curNanoSec
				}
			}

			hLimiter.qpsRemainTokens -= 1
			hLimiter.qpmRemainTokens -= 1
			hLimiter.qpdRemainTokens -= 1

			if (hLimiter.qpsLastFillTime != 0 && hLimiter.qpsRemainTokens <= 0) ||
				(hLimiter.qpmLastFillTime != 0 && hLimiter.qpmRemainTokens <= 0) ||
				(hLimiter.qpdLastFillTime != 0 && hLimiter.qpdRemainTokens <= 0) {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			}
		}
	}

	cookies, err := proxywasm.GetHttpRequestHeader("cookie")
	if err != nil {
		return types.ActionContinue
	}
	cookieValue := strings.Replace(cookies, ctx.pluginContext.config.cookieKey+"=", "", -1)
	if cookieValue != "" {
		cLimiter, isOk := ctx.pluginContext.cookieMap[cookieValue]
		if !isOk {
			var newCLimiter MyLimiter
			if ctx.pluginContext.config.cookieQps != 0 {
				newCLimiter.qpsRemainTokens = ctx.pluginContext.config.cookieQps - 1
				newCLimiter.qpsLastFillTime = curNanoSec
			}
			if ctx.pluginContext.config.cookieQpm != 0 {
				newCLimiter.qpmRemainTokens = ctx.pluginContext.config.cookieQpm - 1
				newCLimiter.qpmLastFillTime = curNanoSec
			}
			if ctx.pluginContext.config.cookieQpd != 0 {
				newCLimiter.qpdRemainTokens = ctx.pluginContext.config.cookieQpd - 1
				newCLimiter.qpdLastFillTime = curNanoSec
			}
			ctx.pluginContext.cookieMap[cookieValue] = &newCLimiter

		} else {
			if ctx.pluginContext.config.cookieBlockNano != 0 {
				if cLimiter.qpsLastFillTime != 0 && curNanoSec > cLimiter.qpsLastFillTime+ctx.pluginContext.config.cookieBlockNano {
					cLimiter.qpsRemainTokens = ctx.pluginContext.config.cookieQps
					cLimiter.qpsLastFillTime = curNanoSec
				}
				if cLimiter.qpmLastFillTime != 0 && curNanoSec > cLimiter.qpmLastFillTime+ctx.pluginContext.config.cookieBlockNano {
					cLimiter.qpmRemainTokens = ctx.pluginContext.config.cookieQpm
					cLimiter.qpmLastFillTime = curNanoSec
				}
				if cLimiter.qpdLastFillTime != 0 && curNanoSec > cLimiter.qpdLastFillTime+ctx.pluginContext.config.cookieBlockNano {
					cLimiter.qpdRemainTokens = ctx.pluginContext.config.cookieQpd
					cLimiter.qpdLastFillTime = curNanoSec
				}
			} else {
				if cLimiter.qpsLastFillTime != 0 && curNanoSec > cLimiter.qpsLastFillTime+1e9 {
					cLimiter.qpsRemainTokens = ctx.pluginContext.config.cookieQps
					cLimiter.qpsLastFillTime = curNanoSec
				}
				if cLimiter.qpmLastFillTime != 0 && curNanoSec > cLimiter.qpmLastFillTime+1e9*60 {
					cLimiter.qpmRemainTokens = ctx.pluginContext.config.cookieQpm
					cLimiter.qpmLastFillTime = curNanoSec
				}
				if cLimiter.qpdLastFillTime != 0 && curNanoSec > cLimiter.qpdLastFillTime+1e9*86400 {
					cLimiter.qpdRemainTokens = ctx.pluginContext.config.cookieQpd
					cLimiter.qpdLastFillTime = curNanoSec
				}
			}

			cLimiter.qpsRemainTokens -= 1
			cLimiter.qpmRemainTokens -= 1
			cLimiter.qpdRemainTokens -= 1

			if (cLimiter.qpsLastFillTime != 0 && cLimiter.qpsRemainTokens <= 0) ||
				(cLimiter.qpmLastFillTime != 0 && cLimiter.qpmRemainTokens <= 0) ||
				(cLimiter.qpdLastFillTime != 0 && cLimiter.qpdRemainTokens <= 0) {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			}
		}
	}
	return types.ActionContinue
}
