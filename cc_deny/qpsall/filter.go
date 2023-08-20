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
	secondNano = 1000 * 1000 * 1000
	minuteNano = 60 * secondNano
	hourNano   = 60 * minuteNano
	dayNano    = 24 * hourNano

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
		hRule *Rule
		cRule *Rule
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
		key         string
		minDuration int64
		needBlock   bool
		blockTime   int64
	}
)

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		hRule: &Rule{},
		cRule: &Rule{},
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
			isInit := false
			p.hRule.key = headerKey
			if qps := curMap["qps"].Int(); qps != 0 {
				p.hRule.minDuration = secondNano
				isInit = true
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				if !isInit {
					p.hRule.minDuration = minuteNano / qpm
					isInit = true
				} else if minuteNano < p.hRule.minDuration*qpm {
					p.hRule.minDuration = minuteNano / qpm
				}
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				if !isInit {
					p.hRule.minDuration = dayNano / qpd
					isInit = true
				} else if dayNano < p.hRule.minDuration*qpd {
					p.hRule.minDuration = dayNano / qpd
				}
			}
			if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
				p.hRule.blockTime = headerBlockTime * secondNano
				p.hRule.needBlock = true
			}
			//proxywasm.LogInfof("[h qps:%d, qpm:%d, qpd:%s, time:%d]", p.hRule.qps, p.hRule.qpm, p.hRule.qpd, p.hRule.blockTime)
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			isInit := false
			p.cRule.key = cookieKey
			if qps := curMap["qps"].Int(); qps != 0 {
				p.cRule.minDuration = secondNano
				isInit = true
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				if !isInit {
					p.cRule.minDuration = minuteNano / qpm
					isInit = true
				} else if minuteNano < p.cRule.minDuration*qpm {
					p.cRule.minDuration = minuteNano / qpm
				}
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				if !isInit {
					p.cRule.minDuration = dayNano / qpd
					isInit = true
				} else if dayNano < p.cRule.minDuration*qpd {
					p.cRule.minDuration = dayNano / qpd
				}
			}
			if cookieBlockTime := curMap["block_seconds"].Int(); cookieBlockTime != 0 {
				p.cRule.blockTime = cookieBlockTime * secondNano
				p.cRule.needBlock = true
			}
			//proxywasm.LogInfof("[c qps:%d, qpm:%d, qpd:%s, time:%d]", p.cRule.qps, p.cRule.qpm, p.cRule.qpd, p.cRule.blockTime)
		}
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {
	var isHAllow, isCAllow bool

	headerValue, err := proxywasm.GetHttpRequestHeader(ctx.p.hRule.key)
	if err == nil && headerValue != "" {
		hLimitKeyBuf := bytes.NewBufferString(headerPre)
		hLimitKeyBuf.WriteString(headerValue)
		isHAllow = getEntry(hLimitKeyBuf.String(), ctx.p.hRule)
		if !isHAllow {
			_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
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
			isCAllow = getEntry(cLimitKeyBuf.String(), ctx.p.cRule)
			if !isCAllow {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			}
		}
	}

	return types.ActionContinue
}

// data=[count:refreshTime:isBlock:lastBlockTime]
func getEntry(shareDataKey string, rule *Rule) bool {
	isAllow := false

	var data []byte
	var cas uint32
	var requestCount int64
	var refreshTime int64
	var isBlock int
	var lastBlockTime int64

	var err error

	for i := 0; i < maxGetTokenRetry; i++ {
		now := time.Now().UnixNano() //放入循环
		data, cas, err = proxywasm.GetSharedData(shareDataKey)

		if err != nil && err == types.ErrorStatusNotFound {
			requestCount = 1
			refreshTime = now
			isBlock = 0
			lastBlockTime = 0
			proxywasm.LogInfo("[getsharedata not found]")

		} else if err == nil {
			// Tokenize the string on :
			parts := strings.Split(string(data), ":")
			requestCount, _ = strconv.ParseInt(parts[0], 0, 64)
			refreshTime, _ = strconv.ParseInt(parts[1], 0, 64)
			isBlock, _ = strconv.Atoi(parts[2])
			lastBlockTime, _ = strconv.ParseInt(parts[3], 0, 64)

			if isBlock == 1 && now > lastBlockTime+rule.blockTime {
				requestCount = 0
				refreshTime = now
				isBlock = 0
				proxywasm.LogInfo("[out period lock]")
			}

			if !rule.needBlock && requestCount <= 1 && now > refreshTime+rule.minDuration {
				requestCount = 0
				refreshTime = now
				proxywasm.LogInfo("[out direct lock]")
			}

			requestCount++

			if requestCount >= 1 && now < refreshTime+rule.minDuration {

				if rule.needBlock {
					proxywasm.LogInfo("[in period lock]")
					lastBlockTime = now
					isBlock = 1
				} else {
					proxywasm.LogInfo("[in direct lock]")
				}
			} else {
				proxywasm.LogInfo("[pass]")
				isAllow = true
			}
		} else {
			proxywasm.LogInfo("[getsharedata other error]")
			return isAllow
		}

		newData := bytes.NewBufferString(strconv.FormatInt(requestCount, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(refreshTime, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(int64(isBlock), 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(lastBlockTime, 10))

		err := proxywasm.SetSharedData(shareDataKey, newData.Bytes(), cas)
		if err != nil {
			if errors.Is(err, types.ErrorStatusCasMismatch) {
				proxywasm.LogInfo("[gset sharedata mis]")
				continue
			} else {
				proxywasm.LogInfo("[gset sharedata other err]")
				return false
			}
		}

		return isAllow
	}
	return false
}
