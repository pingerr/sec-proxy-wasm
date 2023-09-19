package ratelimit

import (
	"bytes"
	"github.com/spaolacci/murmur3"
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

	maxKeyNum = 10000

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
		key        string
		isBlockAll bool
		maxTokens  int64
		interval   int64
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
		if curMap["header"].Exists() {
			var rule Rule
			rule.isHeader = true
			rule.key = curMap["header"].String()
			if curMap["qps"].Exists() {
				if curMap["qps"].Int() == 0 {
					rule.isBlockAll = true
				} else {
					rule.maxTokens = curMap["qps"].Int()
					rule.interval = secondNano / curMap["qps"].Int()
				}
			}

			if curMap["qpm"].Exists() {
				if curMap["qpm"].Int() == 0 {
					rule.isBlockAll = true
				} else {
					if curMap["qpm"].Int() > rule.maxTokens {
						rule.maxTokens = curMap["qpm"].Int()
					}
					interval := minuteNano / curMap["qpm"].Int()
					if interval > rule.interval {
						rule.interval = interval
					}
				}
			}

			if curMap["qpd"].Exists() {
				if curMap["qpd"].Int() == 0 {
					rule.isBlockAll = true
				} else {
					if curMap["qpd"].Int() > rule.maxTokens {
						rule.maxTokens = curMap["qpd"].Int()
					}
					interval := dayNano / curMap["qpd"].Int()
					if interval > rule.interval {
						rule.interval = interval
					}
				}
			}

			if curMap["block_seconds"].Exists() {
				rule.needBlock = true
				rule.blockTime = curMap["block_seconds"].Int() * secondNano
			} else {
				rule.needBlock = false
			}
			p.rules = append(p.rules, rule)
		} else if curMap["cookie"].Exists() {
			var rule Rule
			rule.isHeader = false
			rule.key = curMap["cookie"].String()
			if curMap["qps"].Exists() {
				if curMap["qps"].Int() == 0 {
					rule.isBlockAll = true
				} else {
					rule.maxTokens = curMap["qps"].Int()
					rule.interval = secondNano / curMap["qps"].Int()
				}
			}

			if curMap["qpm"].Exists() {
				if curMap["qpm"].Int() == 0 {
					rule.isBlockAll = true
				} else {
					if curMap["qpm"].Int() > rule.maxTokens {
						rule.maxTokens = curMap["qpm"].Int()
					}
					interval := minuteNano / curMap["qpm"].Int()
					if interval > rule.interval {
						rule.interval = interval
					}
				}
			}

			if curMap["qpd"].Exists() {
				if curMap["qpd"].Int() == 0 {
					rule.isBlockAll = true
				} else {
					if curMap["qpd"].Int() > rule.maxTokens {
						rule.maxTokens = curMap["qpd"].Int()
					}
					interval := dayNano / curMap["qpd"].Int()
					if interval > rule.interval {
						rule.interval = interval
					}
				}
			}

			if curMap["block_seconds"].Exists() {
				rule.needBlock = true
				rule.blockTime = curMap["block_seconds"].Int() * secondNano
			} else {
				rule.needBlock = false
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

				if rule.isBlockAll || rule.maxTokens <= 0 {
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					return types.ActionContinue
				}

				hLimitKeyBuf := bytes.NewBufferString(headerPre)
				hLimitKeyBuf.WriteString(rule.key)
				hLimitKeyBuf.WriteString(":")
				hLimitKeyBuf.WriteString(headerValue)

				headerHs := murmur3.Sum64(hLimitKeyBuf.Bytes()) % maxKeyNum

				if !getEntry("h"+strconv.FormatUint(headerHs, 10), rule) {
					//isBlock = true
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					return types.ActionContinue
				}

			}
		}
		//} else {
		//	cookies, err := proxywasm.GetHttpRequestHeader("cookie")
		//	if err == nil && cookies != "" {
		//		cSub := bytes.NewBufferString(rule.key)
		//		cSub.WriteString("=")
		//		if strings.HasPrefix(cookies, cSub.String()) {
		//			cookieValue := strings.Replace(cookies, cSub.String(), "", -1)
		//			if cookieValue != "" {
		//
		//				if rule.isBlockAll || rule.maxTokens <= 0 {
		//					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
		//					return types.ActionContinue
		//				}
		//
		//				cLimitKeyBuf := bytes.NewBufferString(cookiePre)
		//				cLimitKeyBuf.WriteString(rule.key)
		//				cLimitKeyBuf.WriteString(":")
		//				cLimitKeyBuf.WriteString(cookieValue)
		//
		//				cookieHs := murmur3.Sum64(cLimitKeyBuf.Bytes()) % maxKeyNum
		//
		//				if !getEntry("c"+strconv.FormatUint(cookieHs, 10), rule) {
		//					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
		//					return types.ActionContinue
		//				}
		//			}
		//		}
		//	}
		//}
	}

	return types.ActionContinue
}

// data=[count:sRefillTime:mRefillTime:dRefillTime:isBlock:lastBlockTime]
func getEntry(shareDataKey string, rule Rule) bool {
	var data []byte
	var cas uint32

	var tokens int64
	var refillTime int64
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
			//第一次访问时初始化
			tokens = rule.maxTokens - 1
			refillTime = now
			isBlock = 0
			lastBlockTime = 0
		}

		if err == nil {
			// 反序列化
			parts := strings.Split(string(data), ":")
			tokens, _ = strconv.ParseInt(parts[0], 0, 64)
			refillTime, _ = strconv.ParseInt(parts[1], 0, 64)
			isBlock, _ = strconv.Atoi(parts[2])
			lastBlockTime, _ = strconv.ParseInt(parts[3], 0, 64)

			if rule.needBlock {
				if isBlock == 1 {
					if now-lastBlockTime > rule.blockTime {
						isBlock = 0

						//refillTime = lastBlockTime + rule.blockTime
						//tokens = rule.maxTokens
						//
						////用 延迟计算 取代 定时器，每次访问前更新 令牌数 和 上一次填充时间
						//refillTime = refillTime + (now-refillTime)/rule.interval*rule.interval
						//tokens--

						//用 延迟计算 取代 定时器，每次访问前更新 令牌数 和 上一次填充时间
						if now-refillTime > rule.interval {
							tokens = tokens + (now-refillTime)/rule.interval
							if tokens > rule.maxTokens {
								tokens = rule.maxTokens
							}
							refillTime = refillTime + (now-refillTime)/rule.interval*rule.interval
						}

						if tokens <= 0 {
							isAllow = false
							lastBlockTime = now
							isBlock = 1
						} else {
							tokens--
						}
					} else {
						isAllow = false
					}
				} else {
					//用 延迟计算 取代 定时器，每次访问前更新 令牌数 和 上一次填充时间
					if now-refillTime > rule.interval {
						tokens = tokens + (now-refillTime)/rule.interval
						if tokens > rule.maxTokens {
							tokens = rule.maxTokens
						}
						refillTime = refillTime + (now-refillTime)/rule.interval*rule.interval
					}

					if tokens <= 0 {
						isAllow = false
						lastBlockTime = now
						isBlock = 1
					} else {
						tokens--
					}
				}
			} else {
				//用 延迟计算 取代 定时器，每次访问前更新 令牌数 和 上一次填充时间
				if now-refillTime > rule.interval {
					tokens := tokens + (now-refillTime)/rule.interval
					if tokens > rule.maxTokens {
						tokens = rule.maxTokens
					}
					refillTime = refillTime + (now-refillTime)/rule.interval*rule.interval
				}

				if tokens <= 0 {
					isAllow = false
				} else {
					tokens--
				}
			}
		}

		newData := bytes.NewBufferString(strconv.FormatInt(tokens, 10))
		newData.WriteString(":")
		newData.WriteString(strconv.FormatInt(refillTime, 10))
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
