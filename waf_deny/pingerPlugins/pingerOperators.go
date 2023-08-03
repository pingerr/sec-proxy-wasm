package pingerPlugins

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/samthor/sre2"
)

type rx struct {
	re sre2.Re
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {

	data := fmt.Sprintf("(?sm)%s", options.Arguments)

	//var re *pcre.Regexp
	re := sre2.MustParse(data)
	//re := MustCompile(data, 0)

	return &rx{re: re}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {

	return o.re.Match(value)

}

// RegisterRX registers the rx operator using a WASI implementation instead of Go.
func RegisterRX() {
	plugins.RegisterOperator("rx", newRX)
}
