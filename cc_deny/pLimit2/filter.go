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
	for i := range results {
		curMap := results[i].Map()
		if headerKey := curMap["header"].Str; headerKey != "" {
			var hRule Rule
			hRule.key = headerKey
			hRule.headerOrCookie = true
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
			p.rules = append(p.rules, &hRule)
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			var cRule Rule
			cRule.key = cookieKey
			cRule.headerOrCookie = false
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
			p.rules = append(p.rules, &cRule)
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {

	ctx.p.mu.Lock()
	defer ctx.p.mu.Unlock()
	now := time.Now().UnixNano()

	for _, rule := range ctx.p.rules {
		if rule.headerOrCookie {
			headerValue, _ := proxywasm.GetHttpRequestHeader(rule.key)
			if headerValue != "" {
				hLimitKeyBuf := bytes.NewBufferString(headerPre)
				hLimitKeyBuf.WriteString(rule.key)
				hLimitKeyBuf.WriteString(":")
				hLimitKeyBuf.WriteString(headerValue)
				hLimiter, isOk := ctx.p.limitMap[hLimitKeyBuf.String()]
				if !isOk {
					var newHLimiter Limiter
					if rule.qps != 0 {
						newHLimiter.sTokens = rule.qps - 1
						newHLimiter.sRefillTime = now
					}
					if rule.qpm != 0 {
						newHLimiter.mTokens = rule.qpm - 1
						newHLimiter.mRefillTime = now
					}
					if rule.qpd != 0 {
						newHLimiter.dTokens = rule.qpd - 1
						newHLimiter.dRefillTime = now
					}
					ctx.p.limitMap[hLimitKeyBuf.String()] = &newHLimiter

					//_ = proxywasm.SendHttpResponse(403, nil, []byte("init h limiter"), -1)
					//return types.ActionContinue
				} else {
					if hLimiter.isBlock {
						if rule.needBlock {
							if now < hLimiter.unlockTime {
								// in lock duration
								//_ = proxywasm.SendHttpResponse(403, nil, []byte("in h time lock"), -1)
								_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
								//return types.ActionContinue
							} else {
								// out lock duration
								hLimiter.isBlock = false
								if rule.qps != 0 {
									hLimiter.sTokens = rule.qps
									hLimiter.sRefillTime = hLimiter.unlockTime
								}
								if rule.qpm != 0 {
									hLimiter.mTokens = rule.qpm
									hLimiter.mRefillTime = hLimiter.unlockTime
								}
								if rule.qpd != 0 {
									hLimiter.dTokens = rule.qpd
									hLimiter.dRefillTime = hLimiter.unlockTime
								}
								//_ = proxywasm.SendHttpResponse(403, nil, []byte("out h time lock"), -1)
								//return types.ActionContinue
							}
						} else {
							if (rule.qps != 0 && now < hLimiter.sRefillTime+secondNano) ||
								(rule.qpm != 0 && now < hLimiter.mRefillTime+minuteNano) ||
								(rule.qpd != 0 && now < hLimiter.dRefillTime+dayNano) {
								//_ = proxywasm.SendHttpResponse(403, nil, []byte("in h direct lock"), -1)
								_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
								//return types.ActionContinue
							} else {
								hLimiter.isBlock = false
								if rule.qps != 0 && now > hLimiter.sRefillTime+secondNano {
									hLimiter.sTokens = rule.qps
									hLimiter.sRefillTime = hLimiter.sRefillTime + secondNano
								}
								if rule.qpm != 0 && now > hLimiter.mRefillTime+minuteNano {
									hLimiter.mTokens = rule.qpm
									hLimiter.mRefillTime = hLimiter.mRefillTime + minuteNano
								}
								if rule.qpd != 0 && now > hLimiter.dRefillTime+dayNano {
									hLimiter.dTokens = rule.qpd
									hLimiter.dRefillTime = hLimiter.dRefillTime + dayNano
								}
								//_ = proxywasm.SendHttpResponse(403, nil, []byte("out h direct lock"), -1)
								//return types.ActionContinue
							}
						}
					} else {

						sBlock := rule.qps != 0 && hLimiter.sTokens <= 0
						mBlock := rule.qpm != 0 && hLimiter.mTokens <= 0
						dBlock := rule.qpd != 0 && hLimiter.dTokens <= 0
						if sBlock || mBlock || dBlock {
							//proxywasm.LogInfof("[h sBlock: %s, mBlock: %s, dBlock: %s]", sBlock, mBlock, dBlock)
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
							hLimiter.isBlock = true
							if rule.needBlock {
								// new lock duration
								hLimiter.unlockTime = now + rule.blockTime*secondNano
								//_ = proxywasm.SendHttpResponse(403, nil, []byte("new h period lock"), -1)
								//return types.ActionContinue
							} else {
								//_ = proxywasm.SendHttpResponse(403, nil, []byte("new h direct lock"), -1)
								//return types.ActionContinue
							}
						}
					}
					if rule.qps != 0 {
						hLimiter.sTokens--
					}
					if rule.qpm != 0 {
						hLimiter.mTokens--
					}
					if rule.qpd != 0 {
						hLimiter.dTokens--
					}
				}
			}
		} else {
			cookies, _ := proxywasm.GetHttpRequestHeader("cookie")
			if cookies == "" {
				continue
			}
			cSub := bytes.NewBufferString(rule.key)
			cSub.WriteString("=")
			if strings.HasPrefix(cookies, cSub.String()) {
				cookieValue := strings.Replace(cookies, cSub.String(), "", -1)
				if cookieValue != "" {
					cLimitKeyBuf := bytes.NewBufferString(cookiePre)
					cLimitKeyBuf.WriteString(rule.key)
					cLimitKeyBuf.WriteString(":")
					cLimitKeyBuf.WriteString(cookieValue)
					cLimiter, isOk := ctx.p.limitMap[cLimitKeyBuf.String()]
					if !isOk {
						var newCLimiter Limiter
						if rule.qps != 0 {
							newCLimiter.sTokens = rule.qps
							newCLimiter.sRefillTime = now
						}
						if rule.qpm != 0 {
							newCLimiter.mTokens = rule.qpm
							newCLimiter.mRefillTime = now
						}
						if rule.qpd != 0 {
							newCLimiter.dTokens = rule.qpd
							newCLimiter.dRefillTime = now
						}
						ctx.p.limitMap[cLimitKeyBuf.String()] = &newCLimiter

						//_ = proxywasm.SendHttpResponse(403, nil, []byte("init c limiter"), -1)
						//return types.ActionContinue

					} else {
						if cLimiter.isBlock {
							if rule.needBlock {
								if now < cLimiter.unlockTime {
									// in lock duration
									//_ = proxywasm.SendHttpResponse(403, nil, []byte("in c time lock"), -1)
									_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
									//return types.ActionContinue
								} else {
									// out lock duration
									cLimiter.isBlock = false
									if rule.qps != 0 {
										cLimiter.sTokens = rule.qps
										cLimiter.sRefillTime = cLimiter.unlockTime
									}
									if rule.qpm != 0 {
										cLimiter.mTokens = rule.qpm
										cLimiter.mRefillTime = cLimiter.unlockTime
									}
									if rule.qpd != 0 {
										cLimiter.dTokens = rule.qpd
										cLimiter.dRefillTime = cLimiter.unlockTime
									}
									//_ = proxywasm.SendHttpResponse(403, nil, []byte("out c time lock"), -1)
									//return types.ActionContinue
								}
							} else {
								if (rule.qps != 0 && now < cLimiter.sRefillTime+secondNano) ||
									(rule.qpm != 0 && now < cLimiter.mRefillTime+minuteNano) ||
									(rule.qpd != 0 && now < cLimiter.dRefillTime+dayNano) {
									//_ = proxywasm.SendHttpResponse(403, nil, []byte("in c direct lock"), -1)
									_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
									//return types.ActionContinue
								} else {
									cLimiter.isBlock = false
									if rule.qps != 0 && now > cLimiter.sRefillTime+secondNano {
										cLimiter.sTokens = rule.qps
										cLimiter.sRefillTime = cLimiter.sRefillTime + secondNano
									}
									if rule.qpm != 0 && now > cLimiter.mRefillTime+minuteNano {
										cLimiter.mTokens = rule.qpm
										cLimiter.mRefillTime = cLimiter.mRefillTime + minuteNano
									}
									if rule.qpd != 0 && now > cLimiter.dRefillTime+dayNano {
										cLimiter.dTokens = rule.qpd
										cLimiter.dRefillTime = cLimiter.dRefillTime + dayNano
									}
									//_ = proxywasm.SendHttpResponse(403, nil, []byte("out c direct lock"), -1)
									//return types.ActionContinue
								}
							}
						} else {
							sBlock := rule.qps != 0 && cLimiter.sTokens == 0
							mBlock := rule.qpm != 0 && cLimiter.mTokens == 0
							dBlock := rule.qpd != 0 && cLimiter.dTokens == 0
							if sBlock || mBlock || dBlock {
								_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
								cLimiter.isBlock = true
								if rule.needBlock {
									// new lock duration
									cLimiter.unlockTime = now + rule.blockTime*secondNano
									//_ = proxywasm.SendHttpResponse(403, nil, []byte("new c period lock"), -1)
									//return types.ActionContinue
								} else {
									//_ = proxywasm.SendHttpResponse(403, nil, []byte("new c direct lock"), -1)
									//return types.ActionContinue
								}
							}
						}
						if rule.qps != 0 {
							cLimiter.sTokens--
						}
						if rule.qpm != 0 {
							cLimiter.mTokens--
						}
						if rule.qpd != 0 {
							cLimiter.dTokens--
						}
					}
				}
			}

		}
	}

	return types.ActionContinue
}
