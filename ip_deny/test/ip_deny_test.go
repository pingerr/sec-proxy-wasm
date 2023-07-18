package test

import (
	"bufio"
	"fmt"
	"ip_deny/cidranger"
	"os"
	"testing"
)

func BenchmarkIp(b *testing.B) {

	f, err := os.Open("./cidr")
	if err != nil {
		fmt.Println("read file fail")
	}
	defer f.Close()

	buf := bufio.NewScanner(f)
	var ipArr []string
	for {
		if !buf.Scan() {
			break
		}
		line := buf.Text()
		ipArr = append(ipArr, line)
	}

	for n := 0; n < b.N; n++ {
		cidranger.CidrangerTest(ipArr) // BenchmarkIp            5           3651340 ns/op          809230 B/op      43798 allocs/op
	}
}

//func TestHs(t *testing.T) {
//	f, err := os.Open("./cidr")
//	if err != nil {
//		fmt.Println("read file fail")
//	}
//	defer f.Close()
//
//	buf := bufio.NewScanner(f)
//	var ipArr []string
//	for {
//		if !buf.Scan() {
//			break
//		}
//		line := buf.Text()
//		ipArr = append(ipArr, line)
//	}
//	cidranger.HsTest(ipArr)
//}
