package periodLimit1

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
		headerMap   map[string]*MyLimiter
		cookieMap   map[string]*MyLimiter
		headerSlice []*LimitRule
		cookieSlice []*LimitRule
		mu          sync.Mutex
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID uint32
		p         *pluginContext
	}

	MyLimiter struct {
		sTokens   int64
		mTokens   int64
		dTokens   int64
		nextTime  int64
		blockStat bool
	}

	LimitRule struct {
		key       string
		qps       int64
		qpm       int64
		qpd       int64
		blockTime int64
		hasBlock  bool
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		headerMap:   map[string]*MyLimiter{},
		cookieMap:   map[string]*MyLimiter{},
		mu:          sync.Mutex{},
		headerSlice: []*LimitRule{},
		cookieSlice: []*LimitRule{},
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
			var hRule LimitRule
			hRule.key = headerKey
			if qps := curMap["qps"].Int(); qps != 0 {
				hRule.qps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				hRule.qpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				hRule.qpd = qpd
			}
			if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
				hRule.blockTime = headerBlockTime
				hRule.hasBlock = true
			}
			p.headerSlice = append(p.headerSlice, &hRule)
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			var cRule LimitRule
			cRule.key = cookieKey
			if qps := curMap["qps"].Int(); qps != 0 {
				cRule.qps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				cRule.qpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				cRule.qpd = qpd
			}
			if cookieBlockTime := curMap["block_seconds"].Int(); cookieBlockTime != 0 {
				cRule.blockTime = cookieBlockTime
				cRule.hasBlock = true
			}
			p.cookieSlice = append(p.cookieSlice, &cRule)
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	now := time.Now().UnixNano()

	//ctx.p.mu.Lock()
	//defer ctx.p.mu.Unlock()

	for _, rule := range ctx.p.headerSlice {
		headerValue, _ := proxywasm.GetHttpRequestHeader(rule.key)
		proxywasm.LogInfof("[headerValeu: %s]", headerValue)
		if headerValue != "" {
			hLimiter, isOk := ctx.p.headerMap[headerValue]
			if !isOk {
				var newHLimiter MyLimiter
				if rule.qps != 0 {
					newHLimiter.sTokens = rule.qps - 1
				}
				if rule.qpm != 0 {
					newHLimiter.mTokens = rule.qpm - 1
				}
				if rule.qpd != 0 {
					newHLimiter.dTokens = rule.qpd - 1
				}

				ctx.p.headerMap[headerValue] = &newHLimiter

			} else {
				if hLimiter.blockStat {
					if now <= hLimiter.nextTime {
						// in lock duration
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					} else {
						// out lock duration
						hLimiter.blockStat = false
						if rule.qps != 0 {
							hLimiter.sTokens = rule.qps - 1
						}
						if rule.qpm != 0 {
							hLimiter.mTokens = rule.qpm - 1
						}
						if rule.qpd != 0 {
							hLimiter.dTokens = rule.qpd - 1
						}
						//_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - out lock"), -1)
					}
				} else {
					sAllow := true
					mAllow := true
					dAllow := true
					if rule.qps != 0 && hLimiter.sTokens == 0 {
						sAllow = false
					}
					if rule.qps != 0 && hLimiter.mTokens == 0 {
						mAllow = false
					}
					if rule.qps != 0 && hLimiter.dTokens == 0 {
						dAllow = false
					}
					if !sAllow || !mAllow || !dAllow {

						if rule.hasBlock {
							// new lock duration
							//_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc - new lock"), -1)
							hLimiter.blockStat = true
							hLimiter.nextTime = now + rule.blockTime*1e9
						} else {
							//_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc - direct lock"), -1)
						}
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					} else {
						//_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - no lock"), -1)
					}
				}
			}
		}
	}

	cookies, _ := proxywasm.GetHttpRequestHeader("cookie")
	if cookies == "" {
		return types.ActionContinue
	}
	for _, rule := range ctx.p.cookieSlice {
		cookieValue := strings.Replace(cookies, rule.key+"=", "", -1)
		if cookieValue != "" {
			proxywasm.LogInfof("[headerValeu: %s]", cookieValue)
			cLimiter, isOk := ctx.p.cookieMap[cookieValue]
			if !isOk {
				var newCLimiter MyLimiter
				if rule.qps != 0 {
					newCLimiter.sTokens = rule.qps - 1
				}
				if rule.qps != 0 {
					newCLimiter.mTokens = rule.qpm - 1
				}
				if rule.qpd != 0 {
					newCLimiter.dTokens = rule.qpd - 1
				}
				ctx.p.cookieMap[cookieValue] = &newCLimiter

			} else {
				if cLimiter.blockStat {
					if now <= cLimiter.nextTime {
						// in lock duration
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					} else {
						// out lock duration
						cLimiter.blockStat = false
						if rule.qps != 0 {
							cLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(rule.qps))
							cLimiter.qps.Allow()
						}
						if rule.qpm != 0 {
							cLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(rule.qpm))
							cLimiter.qpm.Allow()
						}
						if rule.qpd != 0 {
							cLimiter.qpd = rate.NewLimiter(rate.Every(24*time.Hour), int(rule.qpd))
							cLimiter.qpd.Allow()
						}
						//_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - out lock"), -1)
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
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
						if rule.hasBlock {
							cLimiter.nextTime = now + rule.blockTime*1e9
							cLimiter.blockStat = true
						}
					} else {
						//_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - no lock"), -1)
					}
				}
			}
		}
	}

	return types.ActionContinue
}
