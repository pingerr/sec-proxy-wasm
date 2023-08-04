package pingerPlugins

import (
	"bytes"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/dlclark/regexp2"
)

type rx struct {
	re *regexp2.Regexp
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {

	//var data bytes.Buffer
	data := bytes.NewBufferString("(?sm)")
	data.WriteString(options.Arguments)
	//data := fmt.Sprintf("%s", options.Arguments)

	//var re *pcre.Regexp
	re := regexp2.MustCompile(data.String(), 0)
	//re := MustCompile(data, 0)

	return &rx{re: re}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	isMatch, _ := o.re.MatchString(value)
	return isMatch

}

// RegisterRX registers the rx operator using a WASI implementation instead of Go.
func RegisterRX() {
	plugins.RegisterOperator("rx", newRX)
}
