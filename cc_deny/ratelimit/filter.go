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

	// shareDataKey 前缀
	cookiePre = "c:"
	headerPre = "h:"

	// shareDataKey最大存储数量
	maxKeyNum = 10000
	// cas最大重试次数
	maxGetTokenRetry = 10
)

type (
	vmContext struct {
		types.DefaultVMContext
	}
	pluginContext struct {
		types.DefaultPluginContext
		//cc规则
		rules []Rule
	}

	httpContext struct {
		types.DefaultHttpContext
		contextID uint32
		p         *pluginContext
	}

	// Rule cc防护规则
	Rule struct {
		//规则类别，true为header规则，false为cookie规则
		isHeader bool
		//如果qps存在且等于0，当作黑名单
		isBlockAll bool
		key        string
		qps        int64
		qpm        int64
		qpd        int64
		//是否要屏蔽
		needBlock bool
		//屏蔽时间
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
		var rule Rule
		curMap := results[i].Map()
		if curMap["header"].Exists() {
			rule.isHeader = true
			rule.key = curMap["header"].String()
		} else if curMap["cookie"].Exists() {
			rule.isHeader = false
			rule.key = curMap["cookie"].String()
		} else {
			continue
		}
		if curMap["qps"].Exists() {
			rule.qps = curMap["qps"].Int()
			if rule.qps == 0 {
				// 存在且为0，相当于黑名单
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
			rule.needBlock = true
			rule.blockTime = curMap["block_seconds"].Int() * secondNano
		}
		p.rules = append(p.rules, rule)
	}

	return types.OnPluginStartStatusOK
}

func (ctx *httpContext) OnHttpRequestHeaders(_ int, _ bool) types.Action {

	for _, rule := range ctx.p.rules {
		if rule.isHeader { //header规则限流检测
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

				// 将key hash为整数后取模，实现key到整数[0, maxKeyNum]范围的映射，限制key的内存上限
				headerHs := murmur3.Sum64(hLimitKeyBuf.Bytes()) % maxKeyNum

				if !getEntry(headerPre+strconv.FormatUint(headerHs, 10), rule) {
					// 未通过限流
					_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
					return types.ActionContinue
				}

			}
		} else { //cookie规则限流检测
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

						// 将key hash为整数后取模，实现key到整数[0, maxKeyNum]范围的映射，限制key的内存上限
						headerHs := murmur3.Sum64(cLimitKeyBuf.Bytes()) % maxKeyNum

						if !getEntry(cookiePre+strconv.FormatUint(headerHs, 10), rule) {
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

// 判断是否通过限流.
// true:通过, false:未通过
func getEntry(shareDataKey string, rule Rule) bool {

	//shareData序列格式: "sRequestCount:mRequestCount:dRequestCount:sRefillTime:mRefillTime:dRefillTime:isBlock:lastBlockTime"
	var sRequestCount int64 // 请求计数（秒）
	var mRequestCount int64 // 请求计数（分）
	var dRequestCount int64 // 请求计数（天）
	var sRefillTime int64   // 请求计数最近一次刷新时间（秒）
	var mRefillTime int64   // 请求计数最近一次刷新时间（分）
	var dRefillTime int64   // 请求计数最近一次刷新时间（天）
	var isBlock int         // 是否处于屏蔽状态. 1:屏蔽，0:未屏蔽
	var lastBlockTime int64 //最近一次屏蔽时间

	var data []byte
	var cas uint32
	var err error

	for i := 0; i < maxGetTokenRetry; i++ {
		isAllow := true //初始化是否通过限流

		now := time.Now().UnixNano()
		data, cas, err = proxywasm.GetSharedData(shareDataKey)

		if err != nil && err != types.ErrorStatusNotFound {
			// 获取shareData错误，重试
			continue
		}
		if err != nil && err == types.ErrorStatusNotFound {
			// shareData不存在，初始化
			sRequestCount = 1
			mRequestCount = 1
			dRequestCount = 1
			sRefillTime = now
			mRefillTime = now
			dRefillTime = now
			isBlock = 0
			lastBlockTime = 0
		}

		if err == nil {
			// 反序列化
			parts := strings.Split(string(data), ":")
			sRequestCount, _ = strconv.ParseInt(parts[0], 0, 64)
			mRequestCount, _ = strconv.ParseInt(parts[1], 0, 64)
			dRequestCount, _ = strconv.ParseInt(parts[2], 0, 64)
			sRefillTime, _ = strconv.ParseInt(parts[3], 0, 64)
			mRefillTime, _ = strconv.ParseInt(parts[4], 0, 64)
			dRefillTime, _ = strconv.ParseInt(parts[5], 0, 64)
			isBlock, _ = strconv.Atoi(parts[6])
			lastBlockTime, _ = strconv.ParseInt(parts[7], 0, 64)

			if rule.needBlock { // 规则要求屏蔽时
				if isBlock == 1 { // 处于屏蔽状态
					if now-lastBlockTime > rule.blockTime { //屏蔽时间结束
						isBlock = 0 //解除屏蔽状态

						// 请求数增加
						sRequestCount++
						mRequestCount++
						dRequestCount++
					} else { //屏蔽时间未结束
						isAllow = false //未通过限流
					}
				} else { // 未处于屏蔽状态
					// lazyload(延迟计算)取代定时器，每次访问前更新“请求计数”和“请求计数最近一次刷新时间”
					if rule.qps != 0 && now-sRefillTime > secondNano {
						sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
						sRequestCount = 0
					}
					if rule.qpm != 0 && now-mRefillTime > minuteNano {
						mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
						mRequestCount = 0
					}
					if rule.qpd != 0 && now-dRefillTime > dayNano {
						dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
						dRequestCount = 0
					}

					// 判断当前周期的请求计数是否超过限制数量
					if (rule.qps != 0 && sRequestCount+1 > rule.qps && now-sRefillTime < secondNano) ||
						(rule.qpm != 0 && mRequestCount+1 > rule.qpm && now-mRefillTime < minuteNano) ||
						(rule.qpd != 0 && dRequestCount+1 > rule.qpd && now-dRefillTime < dayNano) {
						lastBlockTime = now //更新最近一次屏蔽时间
						isBlock = 1         //进入屏蔽状态
						isAllow = false     //未通过限流

						//重置请求计数
						sRequestCount = 0
						mRequestCount = 0
						dRequestCount = 0
						//”计数刷新时间“更新为屏蔽解除时
						sRefillTime = now + rule.blockTime
						mRefillTime = now + rule.blockTime
						dRefillTime = now + rule.blockTime
					} else {
						sRequestCount++
						mRequestCount++
						dRequestCount++
					}
				}
			} else { //规则不要求屏蔽时
				// lazyload(延迟计算)取代定时器，每次访问前更新“请求计数”和“请求计数最近一次刷新时间”
				if rule.qps != 0 && now-sRefillTime > secondNano {
					sRequestCount = 0
					sRefillTime = (now-sRefillTime)/secondNano*secondNano + sRefillTime
				}
				if rule.qpm != 0 && now-mRefillTime > minuteNano {
					mRequestCount = 0
					mRefillTime = (now-mRefillTime)/minuteNano*minuteNano + mRefillTime
				}
				if rule.qpd != 0 && now-dRefillTime > dayNano {
					dRequestCount = 0
					dRefillTime = (now-dRefillTime)/dayNano*dayNano + dRefillTime
				}

				// 判断当前周期的请求计数是否超过限制数量
				if (rule.qps != 0 && sRequestCount+1 > rule.qps && now-sRefillTime < secondNano) ||
					(rule.qpm != 0 && mRequestCount+1 > rule.qpm && now-mRefillTime < minuteNano) ||
					(rule.qpd != 0 && dRequestCount+1 > rule.qpd && now-dRefillTime < dayNano) {
					isAllow = false //未通过限流
				} else {
					sRequestCount++
					mRequestCount++
					dRequestCount++
				}
			}
		}

		//shareData序列化
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
