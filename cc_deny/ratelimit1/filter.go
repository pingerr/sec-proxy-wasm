package ratelimit1

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
		contextID uint32
		p         *pluginContext
	}

	MyLimiter struct {
		qps       *rate.Limiter
		qpm       *rate.Limiter
		qpd       *rate.Limiter
		nextTime  int64
		blockStat bool
	}

	Config struct {
		headerKey       string
		headerQps       int64
		headerQpm       int64
		headerQpd       int64
		headerBlockTime int64
		hasHeaderBlock  bool

		cookieKey       string
		cookieQps       int64
		cookieQpm       int64
		cookieQpd       int64
		cookieBlockTime int64
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
	return &httpContext{contextID: contextID, p: p}
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
			if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
				p.config.headerBlockTime = headerBlockTime
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
			if cookieBlockTime := curMap["block_seconds"].Int(); cookieBlockTime != 0 {
				p.config.cookieBlockTime = cookieBlockTime
				p.config.hasCookieBlock = true
			}
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	now := time.Now().UnixNano()
	headerValue, _ := proxywasm.GetHttpRequestHeader(ctx.p.config.headerKey)

	ctx.p.mu.Lock()
	defer ctx.p.mu.Unlock()

	if headerValue != "" {
		hLimiter, isOk := ctx.p.headerMap[headerValue]
		if !isOk {
			var newHLimiter MyLimiter
			if ctx.p.config.headerQps != 0 {
				newHLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(ctx.p.config.headerQps))
				newHLimiter.qps.Allow()
			}
			if ctx.p.config.headerQpm != 0 {
				newHLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(ctx.p.config.headerQpm))
				newHLimiter.qpm.Allow()
			}
			if ctx.p.config.headerQpd != 0 {
				newHLimiter.qpd = rate.NewLimiter(rate.Every(24*time.Hour), int(ctx.p.config.headerQpd))
				newHLimiter.qpd.Allow()
			}

			ctx.p.headerMap[headerValue] = &newHLimiter

		} else {
			if hLimiter.blockStat {
				if now <= hLimiter.nextTime {
					// in lock duration
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc - in lock"), -1)
				} else {
					// out lock duration
					hLimiter.blockStat = false
					_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - out lock"), -1)
				}
			} else {
				qpsAllow := true
				qpmAllow := true
				qpdAllow := true
				if hLimiter.qps != nil {
					qpsAllow = hLimiter.qps.Allow()
				}
				if hLimiter.qpm != nil {
					qpmAllow = hLimiter.qpm.Allow()
				}
				if hLimiter.qpd != nil {
					qpdAllow = hLimiter.qpd.Allow()
				}
				if !qpsAllow || !qpmAllow || !qpdAllow {

					if ctx.p.config.hasHeaderBlock {
						// new lock duration
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc - new lock"), -1)
						hLimiter.blockStat = true
						hLimiter.nextTime = now + ctx.p.config.headerBlockTime*1e9
						if ctx.p.config.headerQps != 0 {
							hLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(ctx.p.config.headerQps))
						}
						if ctx.p.config.headerQpm != 0 {
							hLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(ctx.p.config.headerQpm))
						}
						if ctx.p.config.headerQpd != 0 {
							hLimiter.qpd = rate.NewLimiter(rate.Every(24*time.Hour), int(ctx.p.config.headerQpd))
						}
					} else {
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc - direct lock"), -1)
					}
				} else {
					_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - no lock"), -1)
				}
			}
		}
	}

	cookies, _ := proxywasm.GetHttpRequestHeader("cookie")
	if cookies == "" {
		return types.ActionContinue
	}
	cookieValue := strings.Replace(cookies, ctx.p.config.cookieKey+"=", "", -1)
	if cookieValue != "" {
		cLimiter, isOk := ctx.p.cookieMap[cookieValue]
		if !isOk {
			var newCLimiter MyLimiter
			if ctx.p.config.cookieQps != 0 {
				newCLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(ctx.p.config.cookieQps))
				newCLimiter.qps.Allow()
			}
			if ctx.p.config.cookieQpm != 0 {
				newCLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(ctx.p.config.cookieQpm))
				newCLimiter.qpm.Allow()
			}
			if ctx.p.config.cookieQpd != 0 {
				newCLimiter.qpd = rate.NewLimiter(rate.Every(24*time.Hour), int(ctx.p.config.cookieQpd))
				newCLimiter.qpd.Allow()
			}
			ctx.p.cookieMap[cookieValue] = &newCLimiter

		} else {
			if cLimiter.blockStat {
				if now <= cLimiter.nextTime {
					// in lock duration
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc - in lock"), -1)
				} else {
					// out lock duration
					cLimiter.blockStat = false
					_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - out lock"), -1)
				}
			} else {
				qpsAllow := true
				qpmAllow := true
				qpdAllow := true
				if cLimiter.qps != nil {
					qpsAllow = cLimiter.qps.Allow()
				}
				if cLimiter.qpm != nil {
					qpmAllow = cLimiter.qpm.Allow()
				}
				if cLimiter.qpd != nil {
					qpdAllow = cLimiter.qpd.Allow()
				}
				if !qpsAllow || !qpmAllow || !qpdAllow {
					// new lock duration
					cLimiter.blockStat = true
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc - new lock"), -1)
					if ctx.p.config.hasCookieBlock {
						cLimiter.nextTime = now + ctx.p.config.cookieBlockTime*1e9
						if ctx.p.config.cookieQps != 0 {
							cLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(ctx.p.config.cookieQps))
						}
						if ctx.p.config.cookieQpm != 0 {
							cLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(ctx.p.config.cookieQpm))
						}
						if ctx.p.config.cookieQpd != 0 {
							cLimiter.qpd = rate.NewLimiter(rate.Every(24*time.Hour), int(ctx.p.config.cookieQpd))
						}
					}
				} else {
					_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - no lock"), -1)
				}
			}
		}
	}

	return types.ActionContinue
}
