package ratelimit

import (
	"bytes"
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
	secondNano = 1000 * 1000 * 1000
	minuteNano = 60 * secondNano
	hourNano   = 60 * minuteNano
	dayNano    = 24 * hourNano

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
		isHeader    bool
		isBlockAll  bool
		key         string
		maxReqCount int64
		duration    int64
		needBlock   bool
		blockTime   int64
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
		if curMap["header"].Exists() {
			var rule Rule
			rule.isHeader = true
			rule.key = curMap["header"].String()
			if curMap["qps"].Exists() {
				rule.maxReqCount = curMap["qps"].Int()
				if curMap["qps"].Int() == 0 {
					rule.isBlockAll = true
				}
			} else {
				continue
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
		} else if curMap["cookie"].Exists() {
			var rule Rule
			rule.isHeader = false
			rule.key = curMap["cookie"].String()
			if curMap["qps"].Exists() {
				rule.maxReqCount = curMap["qps"].Int()
				if curMap["qps"].Int() == 0 {
					rule.isBlockAll = true
				}
			} else {
				continue
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

	for _, rule := range ctx.p.rules {
		if rule.isHeader {
			headerValue, err := proxywasm.GetHttpRequestHeader(rule.key)
			if err == nil && headerValue != "" {

				if rule.isBlockAll {
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					return types.ActionContinue
				}

				hLimitKeyBuf := bytes.NewBufferString(headerPre)
				hLimitKeyBuf.WriteString(rule.key)
				hLimitKeyBuf.WriteString(":")
				hLimitKeyBuf.WriteString(headerValue)

				if !getEntry(hLimitKeyBuf.String(), rule) {
					//isBlock = true
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					return types.ActionContinue
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

						if rule.isBlockAll {
							_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
							return types.ActionContinue
						}

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

	for i := 0; i < maxGetTokenRetry; i++ {
		now := time.Now().UnixNano()
		isAllow := true
		data, cas, err = proxywasm.GetSharedData(shareDataKey)

		if err != nil && err != types.ErrorStatusNotFound {
			continue
		}

		if err != nil && err == types.ErrorStatusNotFound {

			mRequestCount = 1
			mRefillTime = now

			isBlock = 0
			lastBlockTime = 0
		}

		if err == nil {
			// Tokenize the string on :
			parts := strings.Split(string(data), ":")

			mRequestCount, _ = strconv.ParseInt(parts[1], 0, 64)
			mRefillTime, _ = strconv.ParseInt(parts[4], 0, 64)

			isBlock, _ = strconv.Atoi(parts[6])
			lastBlockTime, _ = strconv.ParseInt(parts[7], 0, 64)

			if rule.needBlock {
				if isBlock == 1 {
					if now-lastBlockTime > rule.blockTime {
						isBlock = 0

						if rule.maxReqCount != 0 && now-mRefillTime > secondNano {
							mRefillTime = (now-mRefillTime)/secondNano*secondNano + mRefillTime
							mRequestCount = 0
						}

						mRequestCount++

						if rule.maxReqCount != 0 && mRequestCount > rule.maxReqCount && now-mRefillTime < secondNano {
							lastBlockTime = now
							isBlock = 1
							isAllow = false
						}

					} else {
						isAllow = false
					}
				} else {
					if rule.maxReqCount != 0 && now-mRefillTime > secondNano {
						mRefillTime = (now-mRefillTime)/secondNano*secondNano + mRefillTime
						mRequestCount = 0
					}

					mRequestCount++

					if rule.maxReqCount != 0 && mRequestCount > rule.maxReqCount && now-mRefillTime < secondNano {
						lastBlockTime = now
						isBlock = 1
						isAllow = false
					}
				}
			} else {
				if rule.maxReqCount != 0 && now-mRefillTime > secondNano {
					mRequestCount = 0
					mRefillTime = mRefillTime + (now-mRefillTime)/secondNano*secondNano
				}

				mRequestCount++

				if rule.maxReqCount != 0 && mRequestCount > rule.maxReqCount && now-mRefillTime < secondNano {
					isAllow = false
				}
			}
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
			continue
		}

		return isAllow
	}
	return false
}
