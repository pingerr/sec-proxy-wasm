package pingerPlugins

import (
	"bytes"
	"encoding/base64"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"strings"
	"waf_deny/pingerPlugins/utils"
)

// RegisterPingerTransformations “=” 好像还原不了
func RegisterPingerTransformations() error {

	base64flatDecode := func(input string) (string, bool, error) {
		var inputBuf bytes.Buffer
		inputBuf.WriteString(input)
		if l := len(input); l%4 != 0 {
			inputBuf.WriteString(strings.Repeat("=", 4-l%4))
		}
		dec, err := base64.StdEncoding.DecodeString(inputBuf.String())
		if err != nil {
			// Forgiving implementation, which ignores invalid characters
			return input, false, nil
		}
		return utils.WrapUnsafe(dec), true, nil
	}

	plugins.RegisterTransformation("base64flatDecode", base64flatDecode)
	return nil
}
