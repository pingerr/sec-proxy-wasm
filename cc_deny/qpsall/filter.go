package qpsall

import (
	"bytes"
	"errors"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"strconv"
	"strings"
	"time"
)

func PluginStart() {
	proxywasm.SetVMContext(&vmContext{})
}

const (
	secondNano  = 1000 * 1000 * 1000
	minuteNano  = 60 * secondNano
	hourNano    = 60 * minuteNano
	dayNano     = 24 * hourNano
	secondFloat = secondNano * 1.0
	hourFloat   = minuteNano * 1.0
	dayFloat    = dayNano * 1.0

	cookiePre        = "c:"
	headerPre        = "h:"
	maxGetTokenRetry = 20
)

type (
	vmContext struct {
		types.DefaultVMContext
	}
	pluginContext struct {
		types.DefaultPluginContext
		rules []Rule
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID uint32
		p         *pluginContext
	}

	Entry struct {
		shareDataKey string
		cas          uint32

		requestCount  int64
		refreshTime   int64
		lastBlockTime int64
	}

	Rule struct {
		isHeader  bool
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
		rules: []Rule{},
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
			var rule Rule
			rule.isHeader = true
			rule.key = headerKey
			if qps := curMap["qps"].Int(); qps != 0 {
				rule.qps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				rule.qpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				rule.qpd = qpd
			}
			if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
				rule.blockTime = headerBlockTime * secondNano
				rule.needBlock = true
			}
			p.rules = append(p.rules, rule)
			//proxywasm.LogInfof("[h qps:%d, qpm:%d, qpd:%s, time:%d]", p.hRule.qps, p.hRule.qpm, p.hRule.qpd, p.hRule.blockTime)
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			var rule Rule
			rule.isHeader = false
			rule.key = cookieKey
			if qps := curMap["qps"].Int(); qps != 0 {
				rule.qps = qps
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				rule.qpm = qpm
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				rule.qpd = qpd
			}
			if cookieBlockTime := curMap["block_seconds"].Int(); cookieBlockTime != 0 {
				rule.blockTime = cookieBlockTime * secondNano
				rule.needBlock = true
			}
			p.rules = append(p.rules, rule)
			//proxywasm.LogInfof("[c qps:%d, qpm:%d, qpd:%s, time:%d]", p.cRule.qps, p.cRule.qpm, p.cRule.qpd, p.cRule.blockTime)
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	var rule Rule

	for _, rule = range ctx.p.rules {
		if rule.isHeader {
			headerValue, err := proxywasm.GetHttpRequestHeader(rule.key)
			if err == nil && headerValue != "" {
				hLimitKeyBuf := bytes.NewBufferString(headerPre)
				hLimitKeyBuf.WriteString(rule.key)
				hLimitKeyBuf.WriteString(":")
				hLimitKeyBuf.WriteString(headerValue)
				if !getEntry(hLimitKeyBuf.String(), rule) {
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					return types.ActionContinue
				}

			}
		} else {
			cookies, err := proxywasm.GetHttpRequestHeader("cookie")
			if err != nil || cookies == "" {
				return types.ActionContinue
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
					if !getEntry(cLimitKeyBuf.String(), rule) {
						_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
						return types.ActionContinue
					}
				}
			}
		}
	}

	return types.ActionContinue
}

// data=[count:sRefillTime:mRefillTime:dRefillTime:isBlock:lastBlockTime]
func getEntry(shareDataKey string, rule Rule) bool {
	var data []byte
	var cas uint32
	var sRequestCount int64
	var mRequestCount int64
	var dRequestCount int64
	var sRefillTime int64
	var mRefillTime int64
	var dRefillTime int64
	var isBlock int
	var lastBlockTime int64

	var err error

	now := time.Now().UnixNano() //放入循环

	for i := 0; i < maxGetTokenRetry; i++ {
		isAllow := false
		data, cas, err = proxywasm.GetSharedData(shareDataKey)

		if err != nil && err == types.ErrorStatusNotFound {
			sRequestCount = 1
			mRequestCount = 1
			dRequestCount = 1
			sRefillTime = now
			mRefillTime = now
			dRefillTime = now
			isBlock = 0
			lastBlockTime = 0
			//proxywasm.LogInfo("[getsharedata not found]")
			isAllow = true

		} else if err == nil {
			// Tokenize the string on :
			parts := strings.Split(string(data), ":")
			sRequestCount, _ = strconv.ParseInt(parts[0], 0, 64)
			mRequestCount, _ = strconv.ParseInt(parts[1], 0, 64)
			dRequestCount, _ = strconv.ParseInt(parts[2], 0, 64)
			sRefillTime, _ = strconv.ParseInt(parts[3], 0, 64)
			mRefillTime, _ = strconv.ParseInt(parts[4], 0, 64)
			dRefillTime, _ = strconv.ParseInt(parts[5], 0, 64)
			isBlock, _ = strconv.Atoi(parts[6])
			lastBlockTime, _ = strconv.ParseInt(parts[7], 0, 64)

			if rule.needBlock {
				if isBlock == 1 {
					if now-lastBlockTime > rule.blockTime {
						isBlock = 0
						sRequestCount = 1
						mRequestCount = 1
						dRequestCount = 1

						//if (now-sRefillTime)/secondNano*secondNano > secondNano {
						//	sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
						//} else {
						//	sRefillTime = now
						//}
						//if (now-mRefillTime)/minuteNano*minuteNano > minuteNano {
						//	mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
						//} else {
						//	mRefillTime = now
						//}
						//if (now-dRefillTime)/dayNano*dayNano > dayNano {
						//	dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
						//} else {
						//	dRefillTime = now
						//}

						//sRefillTime = lastBlockTime + rule.blockTime
						//mRefillTime = lastBlockTime + rule.blockTime
						//dRefillTime = lastBlockTime + rule.blockTime

						if now-(lastBlockTime+rule.blockTime) > secondNano {
							sRefillTime = (now-(lastBlockTime+rule.blockTime))/secondNano*secondNano + lastBlockTime + rule.blockTime
						} else {
							sRefillTime = lastBlockTime + rule.blockTime
						}
						if now-(lastBlockTime+rule.blockTime) > minuteNano {
							mRefillTime = (now-(lastBlockTime+rule.blockTime))/minuteNano*minuteNano + lastBlockTime + rule.blockTime
						} else {
							mRefillTime = lastBlockTime + rule.blockTime
						}
						if now-(lastBlockTime+rule.blockTime) > dayNano {
							dRefillTime = (now-(lastBlockTime+rule.blockTime))/dayNano*dayNano + lastBlockTime + rule.blockTime
						} else {
							dRefillTime = lastBlockTime + rule.blockTime
						}

					}
				} else {
					if rule.qps != 0 && now-sRefillTime > secondNano {
						sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
						sRequestCount = 0
						//proxywasm.LogInfo("[out s direct lock]")
					}
					if rule.qpm != 0 && now-mRefillTime > minuteNano {
						mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
						mRequestCount = 0
						//proxywasm.LogInfo("[out m direct lock]")
					}
					if rule.qpd != 0 && now-dRefillTime > dayNano {
						dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
						dRequestCount = 0
						//proxywasm.LogInfo("[out m direct lock]")
					}

					sRequestCount++
					mRequestCount++
					dRequestCount++

					if (rule.qps != 0 && sRequestCount > rule.qps && now-sRefillTime < secondNano) ||
						(rule.qpm != 0 && mRequestCount > rule.qpm && now-mRefillTime < minuteNano) ||
						(rule.qpd != 0 && dRequestCount > rule.qpd && now-dRefillTime < dayNano) {
						lastBlockTime = now
						isBlock = 1
						isAllow = false
					} else {
						isAllow = true
					}
				}
			} else {
				if rule.qps != 0 && now-sRefillTime > secondNano {
					sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
					sRequestCount = 0
					//proxywasm.LogInfo("[out s direct lock]")
				}
				if rule.qpm != 0 && now-mRefillTime > minuteNano {
					mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
					mRequestCount = 0
					//proxywasm.LogInfo("[out m direct lock]")
				}
				if rule.qpd != 0 && now-dRefillTime > dayNano {
					dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
					dRequestCount = 0
					//proxywasm.LogInfo("[out m direct lock]")
				}

				sRequestCount++
				mRequestCount++
				dRequestCount++

				if (rule.qps != 0 && sRequestCount > rule.qps && now-sRefillTime < secondNano) ||
					(rule.qpm != 0 && mRequestCount > rule.qpm && now-mRefillTime < minuteNano) ||
					(rule.qpd != 0 && dRequestCount > rule.qpd && now-dRefillTime < dayNano) {
					isAllow = false
				} else {
					isAllow = true
				}
			}

			//(rule.qps != 0 && sRequestCount > rule.qps && now-sRefillTime < secondNano) ||
			//	(rule.qpm != 0 && mRequestCount > rule.qpm && now-mRefillTime < minuteNano) ||
			//	(rule.qpd != 0 && dRequestCount > rule.qpd && now-dRefillTime < dayNano) ||
			//(rule.qps != 0 && sRequestCount > 1 && (now-sRefillTime)/sRequestCount < secondNano/rule.qps) ||
			//	(rule.qpm != 0 && mRequestCount > 1 && (now-mRefillTime)/mRequestCount < minuteNano/rule.qpm) ||
			//	(rule.qpd != 0 && dRequestCount > 1 && (now-dRefillTime)/dRequestCount < dayNano/rule.qpd)

		} else {
			//proxywasm.LogInfo("[get share data other error]")
			return isAllow
		}

		newData := bytes.NewBufferString(strconv.FormatInt(sRequestCount, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(mRequestCount, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(dRequestCount, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(sRefillTime, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(mRefillTime, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(dRefillTime, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(int64(isBlock), 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(lastBlockTime, 10))

		err := proxywasm.SetSharedData(shareDataKey, newData.Bytes(), cas)
		if err != nil {
			if errors.Is(err, types.ErrorStatusCasMismatch) {
				//proxywasm.LogInfo("[gset sharedata mis]")
				continue
			} else {
				//proxywasm.LogInfo("[gset sharedata other err]")
				return false
			}
		}

		return isAllow
	}
	return false
}
