package lctrie

//
//import "sort"
//
//const (
//	adrSize      = 32
//	firstSkipBit = 27
//	firstAdrBit  = 22
//
//	noPrefix = -1
//
//	rootBranch = 16
//
//	fillFacto = 0.5
//)
//
//// 从位置p开始提取字符串str的n位
//func extract(p int, n int, str int) int {
//	return str << p >> (adrSize - n)
//}
//
//func getBranch(w int) int {
//	return w >> firstSkipBit
//}
//func getSkip(w int) int {
//	return w >> firstAdrBit & 0x1F
//}
//func getSdr(w int) int {
//	return w & 0x3FFFFF
//}
//
//type RoutingTable struct {
//	trie *[]int
//
//	base *[]Base
//
//	pre *[]Prefix
//
//	nextHop *[]int
//
//	trieSize int
//
//	preSize int
//
//	baseSize int
//}
//
//type Base struct {
//	str     int
//	len     int
//	pre     int
//	nextHop int
//}
//
//func getBase(str int, len int, pre int) *Base {
//	return &Base{
//		str: str,
//		len: len,
//		pre: pre,
//	}
//}
//
//type Prefix struct {
//	len     int
//	pre     int
//	nextHop int
//}
//
//func getPre(len int, pre int) *Prefix {
//	return &Prefix{
//		len: len,
//		pre: pre,
//	}
//}
//
//func BuildRoutingTable(entry []Entry) *RoutingTable {
//	var size int
//
//	nextHop := buildNextHopTable(entry)
//
//	sort.(entry)
//
//}
//
//func buildNextHopTable(entry []Entry) []int {
//	nextTemp := make([]int, len(entry))
//
//	for i := range entry {
//		nextTemp[i] = entry[i].nextHop
//	}
//
//	sort.Ints(nextTemp)
//
//	var count int
//	if len(entry) > 0 {
//		count = 1
//	} else {
//		count = 0
//	}
//	for i := range entry {
//		if nextTemp[i-1] != nextTemp[i] {
//			nextTemp[count] = nextTemp[i]
//			count++
//		}
//	}
//	nextHop := make([]int, count)
//	for i := 0; i < count; i++ {
//		nextHop[i] = nextTemp[i]
//	}
//	return nextHop
//}
