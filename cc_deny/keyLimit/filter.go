package keyLimit

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
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
		headerMap       map[string]*Limiter
		cookieMap       map[string]*Limiter
		headerRuleSlice []*LimitRule
		cookieRuleSlice []*LimitRule
		mu              sync.Mutex
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID     uint32
		pluginContext *pluginContext
	}

	Limiter struct {
		qpsRemainTokens int64
		qpmRemainTokens int64
		qpdRemainTokens int64
		qpsLastFillTime int64
		qpsLastLockTime int64
		qpmLastFillTime int64
		qpmLastLockTime int64
		qpdLastFillTime int64
		qpdLastLockTime int64
		blockStat       bool
	}

	LimitRule struct {
		key       string
		qps       int64
		qpm       int64
		qpd       int64
		blockNano int64
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		headerMap:       map[string]*Limiter{},
		cookieMap:       map[string]*Limiter{},
		mu:              sync.Mutex{},
		headerRuleSlice: []*LimitRule{},
		cookieRuleSlice: []*LimitRule{},
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
			var headerRule LimitRule
			headerRule.key = headerKey
			if qps := curMap["qps"].Int(); qps != 0 {
				headerRule.qps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				headerRule.qpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				headerRule.qpd = qpd
			}
			if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
				headerRule.blockNano = headerBlockTime * 1000
			}
			proxywasm.LogInfof("[qps:%d, qpm:%d, qpd:%d]", headerRule.qps, headerRule.qpm, headerRule.qpd)
			p.headerRuleSlice = append(p.headerRuleSlice, &headerRule)
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			var cookieRule LimitRule
			cookieRule.key = cookieKey
			if qps := curMap["qps"].Int(); qps != 0 {
				cookieRule.qps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				cookieRule.qpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				cookieRule.qpd = qpd
			}
			if cookieBlockTime := curMap["block_seconds"].Int(); cookieBlockTime != 0 {
				cookieRule.blockNano = cookieBlockTime * 1000
			}
			p.cookieRuleSlice = append(p.cookieRuleSlice, &cookieRule)
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {

	//ctx.pluginContext.mu.Lock()
	//defer ctx.pluginContext.mu.Unlock()

	curNanoSec := time.Now().UnixMilli()
	proxywasm.LogInfof("[cur time: %d]", curNanoSec)

	for _, limitRule := range ctx.pluginContext.headerRuleSlice {
		headerValue, _ := proxywasm.GetHttpRequestHeader(limitRule.key)
		if headerValue != "" {
			hLimiter, isOk := ctx.pluginContext.headerMap[headerValue]
			if !isOk {
				var newHLimiter Limiter
				//if limitRule.qps != 0 {
				//	newHLimiter.qpsRemainTokens = limitRule.qps - 1
				//	newHLimiter.qpsLastFillTime = curNanoSec
				//}
				if limitRule.qpm != 0 {
					newHLimiter.qpmRemainTokens = limitRule.qpm - 1
					newHLimiter.qpmLastFillTime = curNanoSec
				}
				//if limitRule.qpd != 0 {
				//	newHLimiter.qpdRemainTokens = limitRule.qpd - 1
				//	newHLimiter.qpdLastFillTime = curNanoSec
				//}
				newHLimiter.blockStat = false
				ctx.pluginContext.headerMap[headerValue] = &newHLimiter

			} else {
				if hLimiter.blockStat {
					if limitRule.blockNano != 0 {
						if (limitRule.qps != 0 && curNanoSec < hLimiter.qpsLastLockTime+limitRule.blockNano) ||
							(limitRule.qpm != 0 && curNanoSec < hLimiter.qpmLastLockTime+limitRule.blockNano) ||
							(limitRule.qpd != 0 && curNanoSec < hLimiter.qpdLastLockTime+limitRule.blockNano) {
							proxywasm.LogInfof("[-------in lock--------]")
							proxywasm.LogInfof("[qpmLastLockTime:%d]", hLimiter.qpmLastLockTime)
							proxywasm.LogInfof("[next LockTime:%d]", hLimiter.qpmLastLockTime+limitRule.blockNano)
							proxywasm.LogInfof("[curNanoSec:%d]", curNanoSec)
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
						} else {
							hLimiter.blockStat = false
							//if limitRule.qps != 0 && curNanoSec > hLimiter.qpsLastLockTime+limitRule.blockNano {
							//	hLimiter.qpsRemainTokens = limitRule.qps
							//	hLimiter.qpsLastFillTime = curNanoSec
							//}
							if limitRule.qpm != 0 && curNanoSec > hLimiter.qpmLastLockTime+limitRule.blockNano {
								hLimiter.qpmRemainTokens = limitRule.qpm
								hLimiter.qpmLastFillTime = curNanoSec
								proxywasm.LogInfof("[-------out lock--------]")
								proxywasm.LogInfof("[curNanoSec: %d]", curNanoSec)
								proxywasm.LogInfof("[next LockTime:%d]", hLimiter.qpmLastLockTime+limitRule.blockNano)
							}
							//if limitRule.qpd != 0 && curNanoSec > hLimiter.qpdLastLockTime+limitRule.blockNano {
							//	hLimiter.qpdRemainTokens = limitRule.qpd
							//	hLimiter.qpdLastFillTime = curNanoSec
							//}
						}
					} else {
						if (limitRule.qps != 0 && curNanoSec < hLimiter.qpsLastLockTime+1000) ||
							(limitRule.qpm != 0 && curNanoSec < hLimiter.qpmLastLockTime+1000*60) ||
							(limitRule.qpd != 0 && curNanoSec < hLimiter.qpdLastLockTime+1000*86400) {
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
						} else {
							hLimiter.blockStat = false
							//if limitRule.qps != 0 && curNanoSec > hLimiter.qpsLastLockTime+1000 {
							//	hLimiter.qpsRemainTokens = limitRule.qps
							//	hLimiter.qpsLastFillTime = curNanoSec
							//}
							if limitRule.qpm != 0 && curNanoSec > hLimiter.qpmLastLockTime+1000*60 {
								hLimiter.qpmRemainTokens = limitRule.qpm
								hLimiter.qpmLastFillTime = curNanoSec
							}
							//if limitRule.qpd != 0 && curNanoSec > hLimiter.qpdLastLockTime+1000*86400 {
							//	hLimiter.qpdRemainTokens = limitRule.qpd
							//	hLimiter.qpdLastFillTime = curNanoSec
							//}
						}
					}
				} else {
					//if limitRule.qps != 0 && curNanoSec > hLimiter.qpsLastFillTime+1000 {
					//	hLimiter.qpsRemainTokens = limitRule.qps
					//	hLimiter.qpsLastFillTime = hLimiter.qpsLastFillTime + 1000
					//}
					//if limitRule.qpm != 0 && curNanoSec > hLimiter.qpmLastFillTime+1000*60 {
					//	hLimiter.qpmRemainTokens = limitRule.qpm
					//	hLimiter.qpmLastFillTime = hLimiter.qpmLastFillTime + 1000*60
					//}
					//if limitRule.qpd != 0 && curNanoSec > hLimiter.qpdLastFillTime+1000*86400 {
					//	hLimiter.qpdRemainTokens = limitRule.qpd
					//	hLimiter.qpdLastFillTime = hLimiter.qpdLastFillTime + 1000*86400
					//}
					//if (limitRule.qps != 0 && hLimiter.qpsRemainTokens == 0) ||
					//	(limitRule.qpm != 0 && hLimiter.qpmRemainTokens == 0) ||
					//	(limitRule.qpd != 0 && hLimiter.qpdRemainTokens == 0) {
					//	hLimiter.blockStat = true
					//	_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					//	if limitRule.qps != 0 {
					//		hLimiter.qpsLastLockTime = curNanoSec
					//	}
					//	if limitRule.qpm != 0 {
					//		hLimiter.qpmLastLockTime = curNanoSec
					//	}
					//	if limitRule.qpd != 0 {
					//		hLimiter.qpdLastLockTime = curNanoSec
					//	}
					//}
					if curNanoSec > hLimiter.qpmLastFillTime+1000*60 {
						hLimiter.qpmRemainTokens = limitRule.qpm
						hLimiter.qpmLastFillTime = hLimiter.qpmLastFillTime + 1000*60
						proxywasm.LogInfof("[-------new fill--------]")
						proxywasm.LogInfof("[curNanoSec: %d]", curNanoSec)
						proxywasm.LogInfof("[next filltime: %d]", hLimiter.qpmLastFillTime+1000*60)
					} else {
						if limitRule.qpm != 0 && hLimiter.qpmRemainTokens == 0 {

							hLimiter.blockStat = true
							if limitRule.qpm != 0 {
								hLimiter.qpmLastLockTime = curNanoSec
							}
							proxywasm.LogInfof("[-------new lock--------]")
							proxywasm.LogInfof("[curNanoSec: %d]", curNanoSec)
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)

							//hLimiter.blockStat = true
							//if limitRule.qpm != 0 {
							//	hLimiter.qpmLastLockTime = curNanoSec
							//}
							//_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
						}
					}

					//if limitRule.qps != 0 {
					//	hLimiter.qpsRemainTokens -= 1
					//}
					if limitRule.qpm != 0 {
						hLimiter.qpmRemainTokens = hLimiter.qpmRemainTokens - 1
					}
					//if limitRule.qpd != 0 {
					//	hLimiter.qpdRemainTokens -= 1
					//}
				}
			}
		}
	}

	//for _, limitRule := range ctx.pluginContext.cookieRuleSlice {
	//	cookies, _ := proxywasm.GetHttpRequestHeader("cookie")
	//	if cookies == "" {
	//		continue
	//	}
	//	cookieValue := strings.Replace(cookies, limitRule.key+"=", "", -1)
	//
	//	if cookieValue != "" {
	//		cLimiter, isOk := ctx.pluginContext.cookieMap[cookieValue]
	//		if !isOk {
	//			var newCLimiter Limiter
	//			if limitRule.qps != 0 {
	//				newCLimiter.qpsRemainTokens = limitRule.qps - 1
	//				newCLimiter.qpsLastFillTime = curNanoSec
	//			}
	//			if limitRule.qpm != 0 {
	//				newCLimiter.qpmRemainTokens = limitRule.qpm - 1
	//				newCLimiter.qpmLastFillTime = curNanoSec
	//			}
	//			if limitRule.qpd != 0 {
	//				newCLimiter.qpdRemainTokens = limitRule.qpd - 1
	//				newCLimiter.qpdLastFillTime = curNanoSec
	//			}
	//			newCLimiter.blockStat = false
	//			ctx.pluginContext.cookieMap[cookieValue] = &newCLimiter
	//
	//		} else {
	//			if cLimiter.blockStat {
	//				if limitRule.blockNano != 0 {
	//					if (cLimiter.qpsLastFillTime != 0 && curNanoSec < cLimiter.qpsLastFillTime+limitRule.blockNano) ||
	//						(cLimiter.qpmLastFillTime != 0 && curNanoSec < cLimiter.qpmLastFillTime+limitRule.blockNano) ||
	//						(cLimiter.qpdLastFillTime != 0 && curNanoSec < cLimiter.qpdLastFillTime+limitRule.blockNano) {
	//						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	//					} else {
	//						cLimiter.blockStat = false
	//						if cLimiter.qpsLastFillTime != 0 && curNanoSec > cLimiter.qpsLastFillTime+limitRule.blockNano {
	//							cLimiter.qpsRemainTokens = limitRule.qps
	//							cLimiter.qpsLastFillTime = curNanoSec
	//						}
	//						if cLimiter.qpmLastFillTime != 0 && curNanoSec > cLimiter.qpmLastFillTime+limitRule.blockNano {
	//							cLimiter.qpmRemainTokens = limitRule.qpm
	//							cLimiter.qpmLastFillTime = curNanoSec
	//						}
	//						if cLimiter.qpdLastFillTime != 0 && curNanoSec > cLimiter.qpdLastFillTime+limitRule.blockNano {
	//							cLimiter.qpdRemainTokens = limitRule.qpd
	//							cLimiter.qpdLastFillTime = curNanoSec
	//						}
	//					}
	//
	//				} else {
	//					if (cLimiter.qpsLastFillTime != 0 && curNanoSec < cLimiter.qpsLastFillTime+1e9) ||
	//						(cLimiter.qpmLastFillTime != 0 && curNanoSec < cLimiter.qpmLastFillTime+1e9*60) ||
	//						(cLimiter.qpdLastFillTime != 0 && curNanoSec < cLimiter.qpdLastFillTime+1e9*86400) {
	//						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	//					} else {
	//						cLimiter.blockStat = false
	//						if cLimiter.qpsLastFillTime != 0 && curNanoSec > cLimiter.qpsLastFillTime+1e9 {
	//							cLimiter.qpsRemainTokens = limitRule.qps
	//							cLimiter.qpsLastFillTime = curNanoSec
	//						}
	//						if cLimiter.qpmLastFillTime != 0 && curNanoSec > cLimiter.qpmLastFillTime+1e9*60 {
	//							cLimiter.qpmRemainTokens = limitRule.qpm
	//							cLimiter.qpmLastFillTime = curNanoSec
	//						}
	//						if cLimiter.qpdLastFillTime != 0 && curNanoSec > cLimiter.qpdLastFillTime+1e9*86400 {
	//							cLimiter.qpdRemainTokens = limitRule.qpd
	//							cLimiter.qpdLastFillTime = curNanoSec
	//						}
	//					}
	//				}
	//			} else {
	//				if cLimiter.qpsLastFillTime != 0 && curNanoSec > cLimiter.qpsLastFillTime+1e9 {
	//					cLimiter.qpsRemainTokens = limitRule.qps
	//					cLimiter.qpsLastFillTime = curNanoSec
	//				}
	//				if cLimiter.qpmLastFillTime != 0 && curNanoSec > cLimiter.qpmLastFillTime+1e9*60 {
	//					cLimiter.qpmRemainTokens = limitRule.qpm
	//					cLimiter.qpmLastFillTime = curNanoSec
	//				}
	//				if cLimiter.qpdLastFillTime != 0 && curNanoSec > cLimiter.qpdLastFillTime+1e9*86400 {
	//					cLimiter.qpdRemainTokens = limitRule.qpd
	//					cLimiter.qpdLastFillTime = curNanoSec
	//				}
	//				if (cLimiter.qpsLastFillTime != 0 && cLimiter.qpsRemainTokens == 0) ||
	//					(cLimiter.qpmLastFillTime != 0 && cLimiter.qpmRemainTokens == 0) ||
	//					(cLimiter.qpdLastFillTime != 0 && cLimiter.qpdRemainTokens == 0) {
	//					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	//					cLimiter.blockStat = true
	//					if cLimiter.qpsLastFillTime != 0 {
	//						cLimiter.qpsLastFillTime = curNanoSec
	//					}
	//					if cLimiter.qpmLastFillTime != 0 {
	//						cLimiter.qpmLastFillTime = curNanoSec
	//					}
	//					if cLimiter.qpdLastFillTime != 0 {
	//						cLimiter.qpdLastFillTime = curNanoSec
	//					}
	//				}
	//				if cLimiter.qpsLastFillTime != 0 {
	//					cLimiter.qpsRemainTokens -= 1
	//				}
	//				if cLimiter.qpmLastFillTime != 0 {
	//					cLimiter.qpmRemainTokens -= 1
	//				}
	//				if cLimiter.qpdLastFillTime != 0 {
	//					cLimiter.qpdRemainTokens -= 1
	//				}
	//			}
	//		}
	//	}
	//}
	return types.ActionContinue
}
