package ratelimit

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"golang.org/x/time/rate"
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
		qps          *rate.Limiter
		qpm          *rate.Limiter
		qpd          *rate.Limiter
		hasBlockTime bool
		nextTime     time.Time
	}

	Config struct {
		headerKey       string
		cookieKey       string
		headerQps       int64
		headerQpm       int64
		headerQpd       int64
		cookieQps       int64
		cookieQpm       int64
		cookieQpd       int64
		headerBlockTime string
		cookieBlockTime string
		hasHeaderBlock  bool
		hasCookieBlock  bool
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
		//proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	if !gjson.Valid(string(data)) {
		//proxywasm.LogCritical(`invalid configuration format; expected {"header": "<header name>", "value": "<header value>"}`)
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
			if headerBlockTime := curMap["block_seconds"].Str; headerBlockTime != "" {
				p.config.headerBlockTime = headerBlockTime + "s"
				p.config.hasHeaderBlock = true
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
			if cookieBlockTime := curMap["block_seconds"].Str; cookieBlockTime != "" {
				p.config.cookieBlockTime = cookieBlockTime + "s"
				p.config.hasCookieBlock = true
			}
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	now := time.Now()
	headerValue, _ := proxywasm.GetHttpRequestHeader(ctx.pluginContext.config.headerKey)

	ctx.pluginContext.mu.Lock()
	defer ctx.pluginContext.mu.Unlock()

	if headerValue != "" {
		hLimiter, isOk := ctx.pluginContext.headerMap[headerValue]
		if !isOk {
			var newHLimiter MyLimiter
			if ctx.pluginContext.config.headerQps != 0 {
				newHLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(ctx.pluginContext.config.headerQps))
				newHLimiter.qps.Allow()
			}
			if ctx.pluginContext.config.headerQpd != 0 {
				newHLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(ctx.pluginContext.config.headerQpm))
				newHLimiter.qpm.Allow()
			}
			if ctx.pluginContext.config.hasHeaderBlock {
				newHLimiter.nextTime = now
			}
			ctx.pluginContext.headerMap[headerValue] = &newHLimiter

		} else {
			if ctx.pluginContext.config.hasHeaderBlock && now.Before(hLimiter.nextTime) {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			} else {
				qpsAllow := true
				qpmAllow := true
				if hLimiter.qps != nil {
					qpsAllow = hLimiter.qps.Allow()
				}
				if hLimiter.qpm != nil {
					qpmAllow = hLimiter.qpm.Allow()
				}
				if !qpsAllow || !qpmAllow {
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					if ctx.pluginContext.config.hasHeaderBlock {
						s, _ := time.ParseDuration(ctx.pluginContext.config.headerBlockTime)
						hLimiter.nextTime = now.Add(s)
						if ctx.pluginContext.config.headerQps != 0 {
							hLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(ctx.pluginContext.config.headerQps))
							hLimiter.qps.Allow()
						}
						if ctx.pluginContext.config.headerQpm != 0 {
							hLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(ctx.pluginContext.config.headerQpm))
							hLimiter.qpm.Allow()
						}
					}
				}
			}
		}
	}

	cookies, err := proxywasm.GetHttpRequestHeader("cookie")
	if err != nil {
		return types.ActionContinue
	}
	uid := strings.Replace(cookies, ctx.pluginContext.config.cookieKey+"=", "", -1)
	if uid != "" {
		cLimiter, isOk := ctx.pluginContext.cookieMap[uid]
		if !isOk {
			var newCLimiter MyLimiter
			if ctx.pluginContext.config.cookieQps != 0 {
				newCLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(ctx.pluginContext.config.cookieQps))
				newCLimiter.qps.Allow()
			}
			if ctx.pluginContext.config.cookieQpm != 0 {
				newCLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(ctx.pluginContext.config.cookieQpm))
				newCLimiter.qpm.Allow()
			}
			if ctx.pluginContext.config.hasCookieBlock {
				newCLimiter.nextTime = now
			}
			ctx.pluginContext.cookieMap[uid] = &newCLimiter
		} else {
			if ctx.pluginContext.config.hasCookieBlock && now.Before(cLimiter.nextTime) {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			} else {
				qpsAllow := true
				qpmAllow := true
				if cLimiter.qps != nil {
					qpsAllow = cLimiter.qps.Allow()
				}
				if cLimiter.qpm != nil {
					qpmAllow = cLimiter.qpm.Allow()
				}
				if !qpsAllow || !qpmAllow {
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					if ctx.pluginContext.config.hasCookieBlock {
						s, _ := time.ParseDuration(ctx.pluginContext.config.cookieBlockTime)
						cLimiter.nextTime = now.Add(s)
						if ctx.pluginContext.config.cookieQps != 0 {
							cLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(ctx.pluginContext.config.cookieQps))
							cLimiter.qps.Allow()
						}
						if ctx.pluginContext.config.cookieQpm != 0 {
							cLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(ctx.pluginContext.config.cookieQpm))
							cLimiter.qpm.Allow()
						}
					}
				}
			}
		}
	}

	return types.ActionContinue
}
