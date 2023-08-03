package pingerPlugins

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"go.elara.ws/pcre"
)

type rx struct {
	re *pcre.Regexp
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {

	data := fmt.Sprintf("(?sm)%s", options.Arguments)

	//var re *pcre.Regexp
	//re := pcre.MustCompile(data, 0)
	re := pcre.MustCompile(data)

	return &rx{re: re}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {

	return o.re.MatchString(value)

}

// RegisterRX registers the rx operator using a WASI implementation instead of Go.
func RegisterRX() {
	plugins.RegisterOperator("rx", newRX)
}
