package ccfiltermuli

import (
	"encoding/json"
	"errors"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"golang.org/x/time/rate"
	"strings"
	"time"
)

const (
	shareHeaderMapKey = "headerMap"
	shareCookieMapKey = "cookieMap"
)

func PluginStart() {
	proxywasm.SetVMContext(&vmContext{})
	wrapper.SetCtx(
		"cc-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
	)
}

type (
	vmContext struct {
		types.DefaultVMContext
	}
	pluginContext struct {
		types.DefaultPluginContext
	}
)

func (v vmContext) OnVMStart(vmConfigurationSize int) types.OnVMStartStatus {
	headerMap := make(map[string]*MyLimiter)
	headerMapBuf, _ := json.Marshal(headerMap)
	cookieMap := make(map[string]*MyLimiter)
	cookieMapBuf, _ := json.Marshal(cookieMap)

	if err := proxywasm.SetSharedData(shareHeaderMapKey, headerMapBuf, 0); err != nil {
		proxywasm.LogWarnf("error headerMap shared data on OnVMStart: %v", err)
	}
	if err := proxywasm.SetSharedData(shareCookieMapKey, cookieMapBuf, 0); err != nil {
		proxywasm.LogWarnf("error cookieMap shared data on OnVMStart: %v", err)
	}
	return types.OnVMStartStatusOK
}

func (v vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

type CCConfig struct {
	headerKey       string
	cookieKey       string
	headerQps       int64
	headerQpm       int64
	headerQpd       int64
	cookieQps       int64
	cookieQpm       int64
	cookieQpd       int64
	headerBlockTime int64
	cookieBlockTime int64
	hasHeaderBlock  bool
	hasCookieBlock  bool
	//headerMap       map[string]*MyLimiter
	//cookieMap       map[string]*MyLimiter
}

type MyLimiter struct {
	qps *rate.Limiter
	qpm *rate.Limiter
	//qpd          rate.Limiter
	hasBlockTime bool
	nextTime     int64
}

func parseConfig(json gjson.Result, config *CCConfig, log wrapper.Log) error {
	results := json.Get("cc_rules").Array()
	//log.Infof("[json]: %s", json.Get("cc_rules").String())
	//config.headerMap = make(map[string]*MyLimiter)
	//config.cookieMap = make(map[string]*MyLimiter)
	for i := range results {
		curMap := results[i].Map()
		//if headerBlockTime := curMap["block_seconds"].Int(); headerBlockTime != 0 {
		//	config.headerBlockTime = headerBlockTime
		//	config.hasHeaderBlock = true
		//}
		if headerKey := curMap["header"].Str; headerKey != "" {
			config.headerKey = headerKey
			//log.Infof("[header config success: %s]", headerKey)
			if qps := curMap["qps"].Int(); qps != 0 {
				config.headerQps = qps
			} else {
				//log.Error("[qps config failed]")
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				config.headerQpm = qpm
			} else {
				//log.Info("[qpm config failed]")
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				config.headerQpd = qpd
			}
		} else if cookieKey := curMap["cookie"].Str; cookieKey != "" {
			config.cookieKey = cookieKey
			//log.Infof("[cookie config success: %s]", cookieKey)
			if qps := curMap["qps"].Int(); qps != 0 {
				config.cookieQps = qps
			} else {
				//log.Error("[qps config failed]")
			}
			if qpm := curMap["qpm"].Int(); qpm != 0 {
				config.cookieQpm = qpm
			} else {
				//log.Info("[qpm config failed]")
			}
			if qpd := curMap["qpd"].Int(); qpd != 0 {
				config.cookieQpd = qpd
			}
		}
	}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config CCConfig, log wrapper.Log) types.Action {
	now := time.Now()
	for {
		isOk, err := checkDate(now, config, log)
		if err == nil {
			proxywasm.LogInfof("shared value ok?: %s", isOk)
		} else if errors.Is(err, types.ErrorStatusCasMismatch) {
			continue
		}
		break
	}
	return types.ActionContinue
}

func checkDate(now time.Time, config CCConfig, log wrapper.Log) (bool, error) {
	headerMapStr, casH, err := proxywasm.GetSharedData(shareHeaderMapKey)
	if err != nil {
		log.Error("[get headerMap error]")
	}
	headerMap := make(map[string]*MyLimiter)
	err = json.Unmarshal(headerMapStr, &headerMap)
	if err != nil {
		log.Error("[Unmarshal cookieMap error]")
	}

	headerValue, _ := proxywasm.GetHttpRequestHeader(config.headerKey)
	if headerValue != "" {
		//log.Infof("[headerValue: %s]", headerValue)
		hLimiter, isOk := headerMap[headerValue]
		if !isOk {
			var newHLimiter MyLimiter
			if config.headerQps != 0 {
				newHLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(config.headerQps))
			}
			//if config.headerQpd != 0 {
			//	myLimiter.qpm = rate.NewLimiter(rate.Every(time.Second*60), int(config.headerQpm))
			//}
			//if config.hasHeaderBlock {
			//	myLimiter.hasBlockTime = config.hasHeaderBlock
			//	myLimiter.nextTime = now.UnixMilli()
			//}
			headerMap[headerValue] = &newHLimiter
		} else {
			if hLimiter.hasBlockTime && now.UnixMilli() < hLimiter.nextTime {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			} else if hLimiter.qps != nil && !hLimiter.qps.Allow() {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
				//if limiter.hasBlockTime {
				//	limiter.nextTime = now.UnixMilli() + config.headerBlockTime*1000
				//	log.Infof("[block time : %s ms]", config.headerBlockTime*1000)
				//}
			}
		}
	}
	cookies, err := proxywasm.GetHttpRequestHeader("cookie")
	if err != nil {
		return true, nil
	}
	log.Infof("[cookies: %s]", cookies)
	uid := strings.Replace(cookies, config.cookieKey+"=", "", -1)

	cookieMapStr, casC, err := proxywasm.GetSharedData(shareHeaderMapKey)
	if err != nil {
		log.Error("[get cookieMap error]")
	}
	cookieMap := make(map[string]*MyLimiter)
	err = json.Unmarshal(cookieMapStr, &cookieMap)
	if err != nil {
		log.Error("[Unmarshal cookieMap error]")
	}

	if uid == "" {
		log.Errorf("[uid is null, %s]")
	} else {
		log.Infof("[uid: %s]", uid)
		cLimiter, isOk := cookieMap[uid]
		if !isOk {
			var newCLimiter MyLimiter
			if config.cookieQps != 0 {
				newCLimiter.qps = rate.NewLimiter(rate.Every(time.Second), int(config.cookieQps))
			}
			//if config.headerQpd != 0 {
			//	myLimiter.qpm = rate.NewLimiter(rate.Every(time.Second*60), int(config.headerQpm))
			//}
			//if config.hasHeaderBlock {
			//	myLimiter.hasBlockTime = config.hasHeaderBlock
			//	myLimiter.nextTime = now.UnixMilli()
			//}
			cookieMap[uid] = &newCLimiter
		} else {
			if cLimiter.hasBlockTime && now.UnixMilli() < cLimiter.nextTime {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
			} else if cLimiter.qps != nil && !cLimiter.qps.Allow() {
				_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by cc"), -1)
				//if limiter.hasBlockTime {
				//	limiter.nextTime = now.UnixMilli() + config.headerBlockTime*1000
				//	log.Infof("[block time : %s ms]", config.headerBlockTime*1000)
				//}
			}
		}
	}

	headerMapBuf, _ := json.Marshal(headerMap)
	errH := proxywasm.SetSharedData(shareHeaderMapKey, headerMapBuf, casH)
	cookieMapBuf, _ := json.Marshal(cookieMap)
	errC := proxywasm.SetSharedData(shareCookieMapKey, cookieMapBuf, casC)
	if errH != nil {
		proxywasm.LogWarnf("error setting headerMap on OnHttpRequestHeaders: %v", err)
		return false, errH
	}
	if errC != nil {
		proxywasm.LogWarnf("error setting cookieMap on OnHttpRequestHeaders: %v", err)
		return false, errC
	}
	return true, nil
}
