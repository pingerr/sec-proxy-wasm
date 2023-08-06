package ipTrie

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// this is the fundamental type, a classic binary tree struct
type TrieNode struct {
	LNode, RNode *TrieNode
	Payload      interface{}
}

// very large uint, needed for IPv6
type Uint128 struct {
	H, L uint64
}

// shift right by n, used to extract single bits
func (u Uint128) ShiftRight(n uint) Uint128 {
	newH := u.H >> n
	newL := u.L >> n
	if n <= 64 {
		newL |= u.H << (64 - n)
	} else {
		newL = u.H >> (n - 64)
	}
	return Uint128{newH, newL}
}

// used to fill our custom type, basically the same as FromBytes
func ip2int(ip net.IP) Uint128 {
	// the .To16() bit is important, net.IP sometimes stores v4 addresses
	// in smaller slices instead of using large ones with padding
	hi := binary.BigEndian.Uint64(ip.To16()[:8])
	lo := binary.BigEndian.Uint64(ip.To16()[8:])
	return Uint128{hi, lo}
}

// Insert data for a number of prefixes below a given root node.
//
// Parameters:
//   - trie is a (root) TrieNode
//   - payload is the data stored for a prefix
//   - prefixes is a slice of prefixes
//
// Note that this could be done recursively, too. The use case however does not
// include non-root inserts or lookups.
func (root *TrieNode) Insert(payload interface{}, prefixes []string) {
	for _, cidr := range prefixes {
		current_node := root
		if i := bytes.IndexByte([]byte(cidr), '/'); i < 0 {
			cidrBuf := bytes.NewBufferString(cidr)
			cidrBuf.WriteString("/32")
			cidr = cidrBuf.String()
		}
		ip, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Printf("Error parsing prefix: %v\n", err)
		}
		plen, max_plen := prefix.Mask.Size()
		var bits Uint128 = ip2int(ip)
		// Iterate to the correct node under which we insert.
		for i := 0; i < plen; i++ {
			next_bit := bits.ShiftRight(uint(max_plen-i-1)).L & 1
			var next_node **TrieNode
			if next_bit == 0 {
				next_node = &current_node.LNode
			} else if next_bit == 1 {
				next_node = &current_node.RNode
			}
			// Insert.
			if *next_node == nil {
				*next_node = new(TrieNode)
			}
			current_node = *next_node
		}
		current_node.Payload = payload
	}
}

// Print Trie for debugging purposes. Normally called with ("", true) on a root node, but whatever.
func (node *TrieNode) Print(prefix string, tail bool) {
	// set # as a symbol when there is no content
	symbol := "#"
	if node.Payload != nil {
		symbol = fmt.Sprintf("%d", node.Payload)
	}

	// depending on whether we are a tail node, i.e. a right node as this a binary trie
	if tail {
		// this should be the case for root nodes, these shouldn't have same level neighbors
		fmt.Println(prefix, "└─", symbol, fmt.Sprintf("(/%d)", len([]rune(prefix))/3))
		prefix = prefix + "   "
	} else {
		// left nodes will need a line continuation
		fmt.Println(prefix, "├─", symbol, fmt.Sprintf("(/%d)", len([]rune(prefix))/3))
		prefix = prefix + " │ "
	}

	// if there aren't any children, don't bother to draw anything
	if node.LNode == nil && node.RNode == nil {
		return
	}

	// draw the children, either recursively or as a nice dead end
	if node.LNode != nil {
		node.LNode.Print(prefix, false)
	} else {
		fmt.Println(prefix, "├─ #", fmt.Sprintf("(/%d)", len([]rune(prefix))/3))
	}
	if node.RNode != nil {
		node.RNode.Print(prefix, true)
	} else {
		fmt.Println(prefix, "└─ #", fmt.Sprintf("(/%d)", len([]rune(prefix))/3))
	}
}

// Match an IP to the prefixes and return the correct content.
// Selects IPv4 or IPv6 mode, i.e. the correct prefix length, automatically.
// The tree however needs to be built with the correct addresses.
func (root *TrieNode) Lookup(ip net.IP) interface{} {
	if ip == nil {
		return nil
	}
	current_node := root
	most_specific_payload := root.Payload // this var is used to remember any matches

	// Find maximum prefix length depending on query.
	// Mind that the query has to match the Trie's IP version, else the
	// results will be nonsense.
	var max_plen int
	if ip.To4() == nil {
		max_plen = 128
	} else {
		max_plen = 32
	}

	var bits Uint128 = ip2int(ip)

	// Lookup correct Trie Node iteratively.
	for i := uint(max_plen); i > 0; i-- {
		next_bit := bits.ShiftRight(i-1).L & 1
		if next_bit == 0 && current_node.LNode != nil {
			current_node = current_node.LNode
		} else if next_bit == 1 && current_node.RNode != nil {
			current_node = current_node.RNode
		} else {
			break
		}
		if current_node.Payload != nil {
			most_specific_payload = current_node.Payload
		}
	}
	return most_specific_payload
}
