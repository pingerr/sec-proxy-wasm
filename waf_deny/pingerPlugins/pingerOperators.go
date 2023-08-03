package pingerPlugins

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/gijsbers/go-pcre"
)

type rx struct {
	re pcre.Regexp
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	// (?sm) enables multiline mode which makes 942522-7 work, see
	// - https://stackoverflow.com/a/27680233
	// - https://groups.google.com/g/golang-nuts/c/jiVdamGFU9E
	data := fmt.Sprintf("(?sm)%s", options.Arguments)

	var re pcre.Regexp
	var err error

	re, err = pcre.Compile(data, pcre.DOTALL|pcre.DOLLAR_ENDONLY)
	if err != nil {
		return nil, err
	}
	return &rx{re: re}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {

	match := o.re.MatcherString(value, 0)

	return match.Matches()

}

// RegisterRX registers the rx operator using a WASI implementation instead of Go.
func RegisterRX() {
	plugins.RegisterOperator("rx", newRX)
}
