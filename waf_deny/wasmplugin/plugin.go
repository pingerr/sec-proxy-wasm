package wasmplugin

import (
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"github.com/tidwall/gjson"
	"strings"
)

func PluginStart() {
	wrapper.SetCtx(
		"waf-deny",
		wrapper.ParseConfigBy(parseConfig),
		wrapper.ProcessRequestHeadersBy(onHttpRequestHeaders),
		wrapper.ProcessRequestBodyBy(onHttpRequestBody),
	)
}

type WafConfig struct {
	waf coraza.WAF
}

func parseConfig(json gjson.Result, config *WafConfig, log wrapper.Log) error {
	var secRules []string
	rules := json.Get("secRules").Array()
	for i := range rules {
		//rule := item.String()
		secRules = append(secRules, rules[i].String())
	}
	//log.Debugf("[rinfx log] %s", strings.Join(secRules, "\n"))
	conf := coraza.NewWAFConfig().WithRootFS(root)
	// error: Failed to load Wasm module due to a missing import: wasi_snapshot_preview1.fd_filestat_get
	// because without fs.go
	config.waf, _ = coraza.NewWAF(conf.WithDirectives(strings.Join(secRules, "\n")))
	//if err != nil {
	//	//log.Errorf("Failed to create waf conf: %v", err)
	//	return errors.New("failed to create waf conf")
	//}
	return nil
}

func onHttpRequestHeaders(ctx wrapper.HttpContext, config WafConfig, log wrapper.Log) types.Action {
	ctx.SetContext("interruptionHandled", false)
	//ctx.SetContext("processedRequestBody", false)
	//ctx.SetContext("processedResponseBody", false)
	tx := config.waf.NewTransaction()
	ctx.SetContext("tx", tx)

	// Note the pseudo-header :path includes the query.
	// See https://httpwg.org/specs/rfc9113.html#rfc.section.8.3.1
	uri, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		return types.ActionContinue
	}

	// This currently relies on Envoy's behavior of mapping all requests to HTTP/2 semantics
	// and its request properties, but they may not be true of other proxies implementing
	// proxy-wasm.

	//if tx.IsRuleEngineOff() {
	//	return types.ActionContinue
	//}
	// OnHttpRequestHeaders does not terminate if IP/Port retrieve goes wrong
	srcIP, srcPort := retrieveAddressInfo(log, "source")
	dstIP, dstPort := retrieveAddressInfo(log, "destination")

	tx.ProcessConnection(srcIP, srcPort, dstIP, dstPort)

	//proxywasm.LogInfof("[rinfx log] OnHttpRequestHeaders, RuleEngine On, url = %s", uri)

	method, err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		//log.Error("Failed to get :method")
		return types.ActionContinue
	}

	protocol, err := proxywasm.GetProperty([]string{"request", "protocol"})
	if err != nil {
		// TODO(anuraaga): HTTP protocol is commonly required in WAF rules, we should probably
		// fail fast here, but proxytest does not support properties yet.
		protocol = []byte("HTTP/2.0")
	}

	ctx.SetContext("httpProtocol", string(protocol))

	tx.ProcessURI(uri, method, string(protocol))

	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		//log.Error("Failed to get request headers")
		return types.ActionContinue
	}

	for _, h := range hs {
		tx.AddRequestHeader(h[0], h[1])
	}

	// CRS rules tend to expect Host even with HTTP/2
	authority, err := proxywasm.GetHttpRequestHeader(":authority")
	if err == nil {
		tx.AddRequestHeader("Host", authority)
		tx.SetServerName(parseServerName(log, authority))
	}

	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		return handleInterruption(ctx, "http_request_headers", interruption, log)
	}

	return types.ActionContinue
}

func onHttpRequestBody(ctx wrapper.HttpContext, config WafConfig, body []byte, log wrapper.Log) types.Action {
	//log.Info("[rinfx log] OnHttpRequestBody")

	if ctx.GetContext("interruptionHandled").(bool) {
		return types.ActionContinue
	}

	tx := ctx.GetContext("tx").(ctypes.Transaction)

	//if tx.IsRuleEngineOff() {
	//	return types.ActionContinue
	//}

	interruption, _, err := tx.WriteRequestBody(body)
	if err != nil {
		return types.ActionContinue
	}

	if interruption != nil {
		return handleInterruption(ctx, "http_request_body", interruption, log)
	}
	//ctx.SetContext("processedRequestBody", true)
	interruption, err = tx.ProcessRequestBody()
	if err != nil {
		//log.Error("Failed to process request body")
		return types.ActionContinue
	}
	if interruption != nil {
		return handleInterruption(ctx, "http_request_body", interruption, log)
	}

	return types.ActionContinue
}
