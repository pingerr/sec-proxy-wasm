package test

import (
	"bufio"
	"fmt"
	"ip_deny/radixTree"
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
		//cidranger.CidrangerTest(ipArr) // BenchmarkIp-4                302           3414727 ns/op          801432 B/op      43729 allocs/op
		radixTree.RadixTest(ipArr) // BenchmarkIp-4               2467            533437 ns/op          639043 B/op         13 allocs/op
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
