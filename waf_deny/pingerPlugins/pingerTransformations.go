package pingerPlugins

import (
	"encoding/base64"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"waf_deny/pingerPlugins/utils"
)

// RegisterPingerTransformations “=” 好像还原不了
func RegisterPingerTransformations() error {

	base64flatDecode := func(input string) (string, bool, error) {
		dec, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			// Forgiving implementation, which ignores invalid characters
			return input, false, nil
		}
		return utils.WrapUnsafe(dec), true, nil
	}

	plugins.RegisterTransformation("base64flatDecode", base64flatDecode)
	return nil
}
