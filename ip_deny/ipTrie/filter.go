package ipTrie

import (
	"net"
)

func Test(ipArr []string, trie TrieNode) {
	for i := range ipArr {
		_ = trie.Lookup(net.ParseIP(ipArr[i]))
	}
}
