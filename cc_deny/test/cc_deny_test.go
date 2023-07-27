package test

import (
	"cc_deny/ccfilter"
	json2 "encoding/json"
	"fmt"
	"testing"
)

func TestCc(t *testing.T) {
	file := `{
                            "header": "user-agent",
                            "qps": 10,
                            "qpm": 100,
                            "qpd": 1000,
                            "block_seconds": 300
                          }`
	//ccfilter.CCTest(file)
	var rule ccfilter.CCRule

	err := json2.Unmarshal([]byte(file), &rule)
	if err != nil {
		fmt.Printf("[json parse error: %s]", file)
	}
	fmt.Println(rule)
}
