package wasmplugin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"math"
	"net"
	"strconv"
)

const noGRPCStream int32 = -1
const replaceResponseBody int = 10

// retrieveAddressInfo retrieves address properties from the proxy
// Expected targets are "source" or "destination"
// Envoy ref: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/attributes#connection-attributes
func retrieveAddressInfo(logger wrapper.Log, target string) (string, int) {
	var targetIP, targetPortStr string
	var targetPort int
	targetAddressRaw, err := proxywasm.GetProperty([]string{target, "address"})
	if err != nil {
		logger.Debug(fmt.Sprintf("Failed to get %s address", target))
	} else {
		targetIP, targetPortStr, err = net.SplitHostPort(string(targetAddressRaw))
		if err != nil {
			logger.Debug(fmt.Sprintf("Failed to parse %s address", target))
		}
	}
	targetPortRaw, err := proxywasm.GetProperty([]string{target, "port"})
	if err == nil {
		targetPort, err = parsePort(targetPortRaw)
		if err != nil {
			logger.Debug(fmt.Sprintf("Failed to parse %s port", target))
		}
	} else if targetPortStr != "" {
		// If GetProperty fails we rely on the port inside the Address property
		// Mostly useful for proxies other than Envoy
		targetPort, err = strconv.Atoi(targetPortStr)
		if err != nil {
			logger.Debug(fmt.Sprintf("Failed to get %s port", target))
		}
	}
	return targetIP, targetPort
}

// parsePort converts port, retrieved as little-endian bytes, into int
func parsePort(b []byte) (int, error) {
	// Port attribute ({"source", "port"}) is populated as uint64 (8 byte)
	// Ref: https://github.com/envoyproxy/envoy/blob/1b3da361279a54956f01abba830fc5d3a5421828/source/common/network/utility.cc#L201
	if len(b) < 8 {
		return 0, errors.New("port bytes not found")
	}
	// 0 < Port number <= 65535, therefore the retrieved value should never exceed 16 bits
	// and correctly fit int (at least 32 bits in size)
	unsignedInt := binary.LittleEndian.Uint64(b)
	if unsignedInt > math.MaxInt32 {
		return 0, errors.New("port conversion error")
	}
	return int(unsignedInt), nil
}

// parseServerName parses :authority pseudo-header in order to retrieve the
// virtual host.
func parseServerName(logger wrapper.Log, authority string) string {
	host, _, err := net.SplitHostPort(authority)
	if err != nil {
		// missing port or bad format
		host = authority
	}
	return host
}

func handleInterruption(ctx wrapper.HttpContext, phase string, interruption *ctypes.Interruption, log wrapper.Log) types.Action {
	if ctx.GetContext("interruptionHandled").(bool) {
		// handleInterruption should never be called more than once
		panic("Interruption already handled")
	}

	ctx.SetContext("interruptionHandled", true)

	statusCode := interruption.Status

	if statusCode == 0 {
		_ = proxywasm.SendHttpResponse(403, nil, []byte("denied by waf"), -1)
	}

	return types.ActionPause
}
