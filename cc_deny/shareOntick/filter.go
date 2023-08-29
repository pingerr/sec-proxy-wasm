package shareOntick

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
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

	cookiePre = "c:"
	headerPre = "h:"

	maxGetTokenRetry = 10
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

	Rule struct {
		isHeader   bool
		isBlockAll bool
		key        string
		qps        int64
		qpm        int64
		qpd        int64
		needBlock  bool
		blockTime  int64
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
			if curMap["qps"].Exists() {
				rule.qps = curMap["qps"].Int()
				if rule.qps == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["qpm"].Exists() {
				rule.qpm = curMap["qpm"].Int()
				if rule.qpm == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["qpd"].Exists() {
				rule.qpd = curMap["qpd"].Int()
				if rule.qpd == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["block_seconds"].Exists() {
				rule.blockTime = curMap["block_seconds"].Int() * secondNano
				if rule.blockTime == 0 {
					rule.needBlock = false
				} else {
					rule.needBlock = true
				}
			}
			p.rules = append(p.rules, rule)
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			var rule Rule
			rule.isHeader = false
			rule.key = cookieKey
			if curMap["qps"].Exists() {
				rule.qps = curMap["qps"].Int()
				if rule.qps == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["qpm"].Exists() {
				rule.qpm = curMap["qpm"].Int()
				if rule.qpm == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["qpd"].Exists() {
				rule.qpd = curMap["qpd"].Int()
				if rule.qpd == 0 {
					rule.isBlockAll = true
				}
			}
			if curMap["block_seconds"].Exists() {
				rule.blockTime = curMap["block_seconds"].Int() * secondNano
				if rule.blockTime == 0 {
					rule.needBlock = false
				} else {
					rule.needBlock = true
				}
			}
			p.rules = append(p.rules, rule)
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	var rule Rule

	now := time.Now().UnixNano()

	isBlock := false
	var md5Str string
	for _, rule = range ctx.p.rules {
		if rule.isBlockAll {
			isBlock = true
		} else {
			if rule.isHeader {
				headerValue, err := proxywasm.GetHttpRequestHeader(rule.key)
				if err == nil && headerValue != "" {

					hLimitKeyBuf := bytes.NewBufferString(headerPre)
					hLimitKeyBuf.WriteString(rule.key)
					hLimitKeyBuf.WriteString(":")
					hLimitKeyBuf.WriteString(headerValue)

					sum := md5.Sum(hLimitKeyBuf.Bytes())
					md5Str = hex.EncodeToString(sum[:])

					if !getEntry(md5Str, rule, now) {
						isBlock = true
					}

				}
			} else {
				cookies, err := proxywasm.GetHttpRequestHeader("cookie")
				if err == nil && cookies != "" {
					cSub := bytes.NewBufferString(rule.key)
					cSub.WriteString("=")
					if strings.HasPrefix(cookies, cSub.String()) {
						cookieValue := strings.Replace(cookies, cSub.String(), "", -1)
						if cookieValue != "" {
							cLimitKeyBuf := bytes.NewBufferString(cookiePre)
							cLimitKeyBuf.WriteString(rule.key)
							cLimitKeyBuf.WriteString(":")
							cLimitKeyBuf.WriteString(cookieValue)

							sum := md5.Sum(cLimitKeyBuf.Bytes())
							md5Str = hex.EncodeToString(sum[:])

							if !getEntry(md5Str, rule, now) {
								isBlock = true
							}
						}
					}
				}
			}
		}
	}
	if isBlock {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	}

	return types.ActionContinue
}

func (ctx *httpContext) OnHttpRequestBody(bodySize int, _ bool) types.Action {
	if bodySize > 10*1024 {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
	}
	return types.ActionContinue
}

// data=[count:sRefillTime:mRefillTime:dRefillTime:isBlock:lastBlockTime]
func getEntry(shareDataKey string, rule Rule, now int64) bool {
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

	for i := 0; i < maxGetTokenRetry; i++ {
		isAllow := true
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
			//proxywasm.LogInfo("[share data not found]")
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

			//if rule.needBlock {
			if rule.needBlock {
				if isBlock == 1 {
					if now-lastBlockTime > rule.blockTime {
						isBlock = 0

						sRequestCount = 0
						mRequestCount = 0
						dRequestCount = 0
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
					//if rule.qps != 0 && now-sRefillTime > secondNano {
					//	sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
					//	sRequestCount = 0
					//}
					//if rule.qpm != 0 && now-mRefillTime > minuteNano {
					//	mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
					//	mRequestCount = 0
					//}
					//if rule.qpd != 0 && now-dRefillTime > dayNano {
					//	dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
					//	dRequestCount = 0
					//}
					if rule.qps != 0 && now-sRefillTime > secondNano {
						if (now-sRefillTime)/secondNano > 2 {
							sRequestCount = 0
						} else {
							sRequestCount = rule.qps - int64((now-sRefillTime-secondNano)/secondFloat*rule.qps)
						}
						sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
					}
					if rule.qpm != 0 && now-mRefillTime > minuteNano {
						if (now-mRefillTime)/minuteNano > 2 {
							mRequestCount = 0
						} else {
							mRequestCount = rule.qpm - int64((now-mRefillTime-minuteNano)/secondFloat*rule.qpm)
						}
						mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
					}
					if rule.qpd != 0 && now-dRefillTime > dayNano {
						if (now-dRefillTime)/dayNano > 2 {
							dRequestCount = 0
						} else {
							dRequestCount = rule.qpd - int64((now-dRefillTime-dayNano)/dayFloat*rule.qpm)
						}
						dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
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
					if (now-sRefillTime)/secondNano > 2 {
						sRequestCount = 0
					} else {
						sRequestCount = rule.qps - int64((now-sRefillTime-secondNano)/secondFloat*rule.qps)
					}
					sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
				}
				if rule.qpm != 0 && now-mRefillTime > minuteNano {
					if (now-mRefillTime)/minuteNano > 2 {
						mRequestCount = 0
					} else {
						mRequestCount = rule.qpm - int64((now-mRefillTime-minuteNano)/secondFloat*rule.qpm)
					}
					mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
				}
				if rule.qpd != 0 && now-dRefillTime > dayNano {
					if (now-dRefillTime)/dayNano > 2 {
						dRequestCount = 0
					} else {
						dRequestCount = rule.qpd - int64((now-dRefillTime-dayNano)/dayFloat*rule.qpm)
					}
					dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
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

			//rate
			//(rule.qps != 0 && sRequestCount > 1 && (now-sRefillTime)/sRequestCount < secondNano/rule.qps) ||
			//	(rule.qpm != 0 && mRequestCount > 1 && (now-mRefillTime)/mRequestCount < minuteNano/rule.qpm) ||
			//	(rule.qpd != 0 && dRequestCount > 1 && (now-dRefillTime)/dRequestCount < dayNano/rule.qpd)

		} else {
			//proxywasm.LogInfo("[get share data other error]")
			continue
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
				continue
			}
		}

		return isAllow
	}
	return true
}
