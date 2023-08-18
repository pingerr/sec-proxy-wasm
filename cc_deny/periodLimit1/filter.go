package periodLimit1

import (
	"bytes"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"sync"
	"time"
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
		hRule    *Rule
		cRule    *Rule
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
		key       string
		qps       int64
		qpm       int64
		qpd       int64
		needBlock bool
		blockTime int64
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		limitMap: map[string]*Limiter{},
		mu:       sync.Mutex{},
		hRule:    &Rule{},
		cRule:    &Rule{},
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
			var hRule Rule
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
				hRule.needBlock = true
			}
			p.hRule = &hRule
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			var cRule Rule
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
				cRule.needBlock = true
			}
			p.cRule = &cRule
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	now := time.Now().UnixNano()

	ctx.p.mu.Lock()
	defer ctx.p.mu.Unlock()

	headerValue, _ := proxywasm.GetHttpRequestHeader(ctx.p.hRule.key)
	if headerValue != "" {
		hLimitKeyBuf := bytes.NewBufferString(headerPre)
		hLimitKeyBuf.WriteString(headerValue)
		hLimiter, isOk := ctx.p.limitMap[hLimitKeyBuf.String()]
		if !isOk {
			var newHLimiter Limiter
			if ctx.p.cRule.qps != 0 {
				newHLimiter.sTokens = ctx.p.cRule.qps - 1
				newHLimiter.sRefillTime = now

			}
			if ctx.p.cRule.qpm != 0 {
				newHLimiter.mTokens = ctx.p.cRule.qpm - 1
				newHLimiter.mRefillTime = now
			}
			if ctx.p.cRule.qpd != 0 {
				newHLimiter.dTokens = ctx.p.cRule.qpd - 1
				newHLimiter.dRefillTime = now
			}
			ctx.p.limitMap[hLimitKeyBuf.String()] = &newHLimiter

			_ = proxywasm.SendHttpResponse(403, nil, []byte("init limiter"), -1)
			return types.ActionContinue
		} else {
			if hLimiter.isBlock {
				if ctx.p.hRule.needBlock {
					if now < hLimiter.unlockTime {
						// in lock duration
						_ = proxywasm.SendHttpResponse(403, nil, []byte("in time lock"), -1)
						return types.ActionContinue
					} else {
						// out lock duration
						hLimiter.isBlock = false
						if ctx.p.cRule.qps != 0 {
							hLimiter.sTokens = ctx.p.cRule.qps - 1
							hLimiter.sRefillTime = hLimiter.unlockTime
						}
						if ctx.p.cRule.qpm != 0 {
							hLimiter.mTokens = ctx.p.cRule.qpm - 1
							hLimiter.mRefillTime = hLimiter.unlockTime
						}
						if ctx.p.cRule.qpd != 0 {
							hLimiter.dTokens = ctx.p.cRule.qpd - 1
							hLimiter.dRefillTime = hLimiter.unlockTime
						}
						_ = proxywasm.SendHttpResponse(403, nil, []byte("out time lock"), -1)
						return types.ActionContinue
					}
				} else {
					if (ctx.p.cRule.qps != 0 && now < hLimiter.sRefillTime+secondNano) ||
						(ctx.p.cRule.qpm != 0 && now < hLimiter.mRefillTime+minuteNano) ||
						(ctx.p.cRule.qpd != 0 && now < hLimiter.dRefillTime+dayNano) {
						_ = proxywasm.SendHttpResponse(403, nil, []byte("in direct lock"), -1)
						return types.ActionContinue
					} else {
						hLimiter.isBlock = false
						if ctx.p.cRule.qps != 0 && now > hLimiter.sRefillTime+secondNano {
							hLimiter.sTokens = ctx.p.cRule.qps - 1
							hLimiter.sRefillTime = hLimiter.sRefillTime + secondNano
						}
						if ctx.p.cRule.qpm != 0 && now > hLimiter.mRefillTime+minuteNano {
							hLimiter.mTokens = ctx.p.cRule.qpm - 1
							hLimiter.mRefillTime = hLimiter.mRefillTime + minuteNano
						}
						if ctx.p.cRule.qpd != 0 && now > hLimiter.dRefillTime+dayNano {
							hLimiter.dTokens = ctx.p.cRule.qpd - 1
							hLimiter.dRefillTime = hLimiter.dRefillTime + dayNano
						}
						_ = proxywasm.SendHttpResponse(403, nil, []byte("out direct lock"), -1)
						return types.ActionContinue
					}
				}
			} else {
				//sFill := ctx.p.cRule.qps != 0 && now > hLimiter.sRefillTime+secondNano
				//if sFill {
				//	hLimiter.sTokens = ctx.p.cRule.qps
				//	hLimiter.sRefillTime = hLimiter.sRefillTime + secondNano
				//}
				//mFill := ctx.p.cRule.qpm != 0 && now > hLimiter.mRefillTime+minuteNano
				//if mFill {
				//	hLimiter.mTokens = ctx.p.cRule.qpm
				//	hLimiter.mRefillTime = hLimiter.mRefillTime + minuteNano
				//}
				//dFill := ctx.p.cRule.qpd != 0 && now > hLimiter.dRefillTime+dayNano
				//if dFill {
				//	hLimiter.dTokens = ctx.p.cRule.qpd
				//	hLimiter.dRefillTime = hLimiter.dRefillTime + dayNano
				//}

				sBlock := ctx.p.cRule.qps != 0 && hLimiter.sTokens == 0
				mBlock := ctx.p.cRule.qpm != 0 && hLimiter.mTokens == 0
				dBlock := ctx.p.cRule.qpd != 0 && hLimiter.dTokens == 0
				if sBlock || mBlock || dBlock {
					hLimiter.isBlock = true
					if ctx.p.cRule.needBlock {
						// new lock duration
						hLimiter.unlockTime = now + ctx.p.cRule.blockTime*secondNano
						_ = proxywasm.SendHttpResponse(403, nil, []byte("new period lock"), -1)
						return types.ActionContinue
					} else {
						_ = proxywasm.SendHttpResponse(403, nil, []byte("new direct lock"), -1)
						return types.ActionContinue
					}
					//_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
				} else {
					if ctx.p.cRule.qps != 0 {
						hLimiter.sTokens--
					}
					if ctx.p.cRule.qpm != 0 {
						hLimiter.mTokens--
					}
					if ctx.p.cRule.qpd != 0 {
						hLimiter.dTokens--
					}
					_ = proxywasm.SendHttpResponse(403, nil, []byte("no lock"), -1)
				}
			}
		}
	}

	//cookies, _ := proxywasm.GetHttpRequestHeader("cookie")
	//if cookies == "" {
	//	return types.ActionContinue
	//}
	//for _, rule := range ctx.p.cookieSlice {
	//	cookieValue := strings.Replace(cookies, rule.key+"=", "", -1)
	//	if cookieValue != "" {
	//		proxywasm.LogInfof("[headerValeu: %s]", cookieValue)
	//		cLimiter, isOk := ctx.p.cookieMap[cookieValue]
	//		if !isOk {
	//			var newCLimiter MyLimiter
	//			if rule.qps != 0 {
	//				newCLimiter.sTokens = rule.qps - 1
	//			}
	//			if rule.qps != 0 {
	//				newCLimiter.mTokens = rule.qpm - 1
	//			}
	//			if rule.qpd != 0 {
	//				newCLimiter.dTokens = rule.qpd - 1
	//			}
	//			ctx.p.cookieMap[cookieValue] = &newCLimiter
	//
	//		} else {
	//			if cLimiter.blockStat {
	//				if now <= cLimiter.nextTime {
	//					// in lock duration
	//					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	//				} else {
	//					// out lock duration
	//					cLimiter.blockStat = false
	//					if rule.qps != 0 {
	//						cLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(rule.qps))
	//						cLimiter.qps.Allow()
	//					}
	//					if rule.qpm != 0 {
	//						cLimiter.qpm = rate.NewLimiter(rate.Every(time.Minute), int(rule.qpm))
	//						cLimiter.qpm.Allow()
	//					}
	//					if rule.qpd != 0 {
	//						cLimiter.qpd = rate.NewLimiter(rate.Every(24*time.Hour), int(rule.qpd))
	//						cLimiter.qpd.Allow()
	//					}
	//					//_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - out lock"), -1)
	//				}
	//			} else {
	//				qpsAllow := true
	//				qpmAllow := true
	//				qpdAllow := true
	//				if cLimiter.qps != nil {
	//					qpsAllow = cLimiter.qps.Allow()
	//				}
	//				if cLimiter.qpm != nil {
	//					qpmAllow = cLimiter.qpm.Allow()
	//				}
	//				if cLimiter.qpd != nil {
	//					qpdAllow = cLimiter.qpd.Allow()
	//				}
	//				if !qpsAllow || !qpmAllow || !qpdAllow {
	//					// new lock duration
	//					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	//					if rule.hasBlock {
	//						cLimiter.nextTime = now + rule.blockTime*1e9
	//						cLimiter.blockStat = true
	//					}
	//				} else {
	//					//_ = proxywasm.SendHttpResponse(403, nil, []byte("pass - no lock"), -1)
	//				}
	//			}
	//		}
	//	}
	//}

	return types.ActionContinue
}
