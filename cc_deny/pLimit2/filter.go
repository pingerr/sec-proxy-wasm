package pLimit2

import (
	"bytes"
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
		cRule    Rule
		hRule    Rule
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
		hRule:    Rule{},
		cRule:    Rule{},
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
			p.hRule.key = headerKey
			if qps := curMap["qps"].Int(); qps != 0 {
				p.hRule.qps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				p.hRule.qpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				p.hRule.qpd = qpd
			}
			if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
				p.hRule.blockTime = headerBlockTime
				p.hRule.needBlock = true
			}
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			p.cRule.key = cookieKey
			if qps := curMap["qps"].Int(); qps != 0 {
				p.cRule.qps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				p.cRule.qpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				p.cRule.qpd = qpd
			}
			if cookieBlockTime := curMap["block_seconds"].Int(); cookieBlockTime != 0 {
				p.cRule.blockTime = cookieBlockTime
				p.cRule.needBlock = true
			}
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {

	ctx.p.mu.Lock()
	defer ctx.p.mu.Unlock()
	now := time.Now().UnixNano()

	headerValue, err := proxywasm.GetHttpRequestHeader(ctx.p.hRule.key)
	if err == nil && headerValue != "" {
		hLimitKeyBuf := bytes.NewBufferString(headerPre)
		hLimitKeyBuf.WriteString(headerValue)
		hLimiter, isOk := ctx.p.limitMap[hLimitKeyBuf.String()]
		if !isOk {
			var newHLimiter Limiter
			if ctx.p.hRule.qps != 0 {
				newHLimiter.sTokens = ctx.p.hRule.qps - 1
				newHLimiter.sRefillTime = now
			}
			if ctx.p.hRule.qpm != 0 {
				newHLimiter.mTokens = ctx.p.hRule.qpm - 1
				newHLimiter.mRefillTime = now
			}
			if ctx.p.hRule.qpd != 0 {
				newHLimiter.dTokens = ctx.p.hRule.qpd - 1
				newHLimiter.dRefillTime = now
			}
			ctx.p.limitMap[hLimitKeyBuf.String()] = &newHLimiter

		} else {
			if hLimiter.isBlock {
				if ctx.p.hRule.needBlock {
					if now < hLimiter.unlockTime {
						// in lock duration
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					} else {
						// out lock duration
						hLimiter.isBlock = false
						if ctx.p.hRule.qps != 0 {
							hLimiter.sTokens = ctx.p.hRule.qps
							hLimiter.sRefillTime = now
						}
						if ctx.p.hRule.qpm != 0 {
							hLimiter.mTokens = ctx.p.hRule.qpm
							hLimiter.mRefillTime = now
						}
						if ctx.p.hRule.qpd != 0 {
							hLimiter.dTokens = ctx.p.hRule.qpd
							hLimiter.dRefillTime = now
						}
					}
				} else {
					if (ctx.p.hRule.qps != 0 && now < hLimiter.sRefillTime+secondNano) ||
						(ctx.p.hRule.qpm != 0 && now < hLimiter.mRefillTime+minuteNano) ||
						(ctx.p.hRule.qpd != 0 && now < hLimiter.dRefillTime+dayNano) {
						//_ = proxywasm.SendHttpResponse(403, nil, []byte("in h direct lock"), -1)
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
						//return types.ActionContinue
					} else {
						hLimiter.isBlock = false
						if ctx.p.hRule.qps != 0 && now > hLimiter.sRefillTime+secondNano {
							hLimiter.sTokens = ctx.p.hRule.qps
							hLimiter.sRefillTime = now
						}
						if ctx.p.hRule.qpm != 0 && now > hLimiter.mRefillTime+minuteNano {
							hLimiter.mTokens = ctx.p.hRule.qpm
							hLimiter.mRefillTime = now
						}
						if ctx.p.hRule.qpd != 0 && now > hLimiter.dRefillTime+dayNano {
							hLimiter.dTokens = ctx.p.hRule.qpd
							hLimiter.dRefillTime = now
						}
						//_ = proxywasm.SendHttpResponse(403, nil, []byte("out h direct lock"), -1)
						//return types.ActionContinue
					}
				}
			} else {
				sRefill := ctx.p.hRule.qps != 0 && now > hLimiter.sRefillTime+secondNano
				if sRefill {
					hLimiter.sTokens = ctx.p.hRule.qps
					hLimiter.sRefillTime = now
				}
				mRefill := ctx.p.hRule.qpm != 0 && now > hLimiter.mRefillTime+minuteNano
				if mRefill {
					hLimiter.mTokens = ctx.p.hRule.qpm
					hLimiter.mRefillTime = now
				}
				dRefill := ctx.p.hRule.qpd != 0 && now > hLimiter.dRefillTime+dayNano
				if dRefill {
					hLimiter.dTokens = ctx.p.hRule.qpd
					hLimiter.dRefillTime = now
				}

				sBlock := ctx.p.hRule.qps != 0 && hLimiter.sTokens <= 0
				mBlock := ctx.p.hRule.qpm != 0 && hLimiter.mTokens <= 0
				dBlock := ctx.p.hRule.qpd != 0 && hLimiter.dTokens <= 0
				if sBlock || mBlock || dBlock {
					//proxywasm.LogInfof("[h sBlock: %s, mBlock: %s, dBlock: %s]", sBlock, mBlock, dBlock)
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					hLimiter.isBlock = true
					if ctx.p.hRule.needBlock {
						// new lock duration
						hLimiter.unlockTime = now + ctx.p.hRule.blockTime*secondNano
					}
				}
			}
			if ctx.p.hRule.qps != 0 {
				hLimiter.sTokens--
			}
			if ctx.p.hRule.qpm != 0 {
				hLimiter.mTokens--
			}
			if ctx.p.hRule.qpd != 0 {
				hLimiter.dTokens--
			}
		}
	}

	cookies, err := proxywasm.GetHttpRequestHeader("cookie")
	if err != nil || cookies == "" {
		return types.ActionContinue
	}
	cSub := bytes.NewBufferString(ctx.p.cRule.key)
	cSub.WriteString("=")
	if strings.HasPrefix(cookies, cSub.String()) {
		cookieValue := strings.Replace(cookies, cSub.String(), "", -1)
		if cookieValue != "" {
			cLimitKeyBuf := bytes.NewBufferString(cookiePre)
			cLimitKeyBuf.WriteString(cookieValue)
			cLimiter, isOk := ctx.p.limitMap[cLimitKeyBuf.String()]
			if !isOk {
				var limiter Limiter
				if ctx.p.cRule.qps != 0 {
					limiter.sTokens = ctx.p.cRule.qps - 1
					limiter.sRefillTime = now
				}
				if ctx.p.cRule.qpm != 0 {
					limiter.mTokens = ctx.p.cRule.qpm - 1
					limiter.mRefillTime = now
				}
				if ctx.p.cRule.qpd != 0 {
					limiter.dTokens = ctx.p.cRule.qpd - 1
					limiter.dRefillTime = now
				}
				ctx.p.limitMap[cLimitKeyBuf.String()] = &limiter
			} else {
				if cLimiter.isBlock {
					if ctx.p.cRule.needBlock {
						if now < cLimiter.unlockTime {
							// in lock duration
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
						} else {
							// out lock duration
							cLimiter.isBlock = false
							if ctx.p.cRule.qps != 0 {
								cLimiter.sTokens = ctx.p.cRule.qps
								cLimiter.sRefillTime = now
							}
							if ctx.p.cRule.qpm != 0 {
								cLimiter.mTokens = ctx.p.cRule.qpm
								cLimiter.mRefillTime = now
							}
							if ctx.p.cRule.qpd != 0 {
								cLimiter.dTokens = ctx.p.cRule.qpd
								cLimiter.dRefillTime = now
							}
						}
					} else {
						if (ctx.p.cRule.qps != 0 && now < cLimiter.sRefillTime+secondNano) ||
							(ctx.p.cRule.qpm != 0 && now < cLimiter.mRefillTime+minuteNano) ||
							(ctx.p.cRule.qpd != 0 && now < cLimiter.dRefillTime+dayNano) {
							//_ = proxywasm.SendHttpResponse(403, nil, []byte("in h direct lock"), -1)
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
							//return types.ActionContinue
						} else {
							cLimiter.isBlock = false
							if ctx.p.cRule.qps != 0 && now > cLimiter.sRefillTime+secondNano {
								cLimiter.sTokens = ctx.p.cRule.qps
								cLimiter.sRefillTime = now
							}
							if ctx.p.cRule.qpm != 0 && now > cLimiter.mRefillTime+minuteNano {
								cLimiter.mTokens = ctx.p.cRule.qpm
								cLimiter.mRefillTime = now
							}
							if ctx.p.cRule.qpd != 0 && now > cLimiter.dRefillTime+dayNano {
								cLimiter.dTokens = ctx.p.cRule.qpd
								cLimiter.dRefillTime = now
							}
							//_ = proxywasm.SendHttpResponse(403, nil, []byte("out h direct lock"), -1)
							//return types.ActionContinue
						}
					}
				} else {
					sRefill := ctx.p.cRule.qps != 0 && now > cLimiter.sRefillTime+secondNano
					if sRefill {
						cLimiter.sTokens = ctx.p.cRule.qps
						cLimiter.sRefillTime = now
					}
					mRefill := ctx.p.cRule.qpm != 0 && now > cLimiter.mRefillTime+minuteNano
					if mRefill {
						cLimiter.mTokens = ctx.p.cRule.qpm
						cLimiter.mRefillTime = now
					}
					dRefill := ctx.p.cRule.qpd != 0 && now > cLimiter.dRefillTime+dayNano
					if dRefill {
						cLimiter.dTokens = ctx.p.cRule.qpd
						cLimiter.dRefillTime = now
					}

					sBlock := ctx.p.cRule.qps != 0 && cLimiter.sTokens <= 0
					mBlock := ctx.p.cRule.qpm != 0 && cLimiter.mTokens <= 0
					dBlock := ctx.p.cRule.qpd != 0 && cLimiter.dTokens <= 0
					if sBlock || mBlock || dBlock {
						//proxywasm.LogInfof("[h sBlock: %s, mBlock: %s, dBlock: %s]", sBlock, mBlock, dBlock)
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
						cLimiter.isBlock = true
						if ctx.p.cRule.needBlock {
							// new lock duration
							cLimiter.unlockTime = now + ctx.p.cRule.blockTime*secondNano
						}
					}
				}
				if ctx.p.cRule.qps != 0 {
					cLimiter.sTokens--
				}
				if ctx.p.cRule.qpm != 0 {
					cLimiter.mTokens--
				}
				if ctx.p.cRule.qpd != 0 {
					cLimiter.dTokens--
				}
			}
		}
	}

	return types.ActionContinue
}
