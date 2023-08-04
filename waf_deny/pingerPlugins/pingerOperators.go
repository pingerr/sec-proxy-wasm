package pingerPlugins

import (
	"bytes"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"regexp"
)

type rx struct {
	re *regexp.Regexp
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {

	//var data bytes.Buffer
	data := bytes.NewBufferString("(?sm)")
	data.WriteString(options.Arguments)
	//data := fmt.Sprintf("%s", options.Arguments)

	re := regexp.MustCompile(data.String())

	return &rx{re: re}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	return o.re.MatchString(value)
}

// RegisterRX registers the rx operator using a WASI implementation instead of Go.
func RegisterRX() {
	plugins.RegisterOperator("rx", newRX)
}
