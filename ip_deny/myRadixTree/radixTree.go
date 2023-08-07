package myRadixTree

import (
	"bytes"
	"errors"
)

type node struct {
	left, right *node
	value       interface{}
}

// Tree implements radix tree for working with IP/mask. Thread safety is not guaranteed, you should choose your own style of protecting safety of operations.
type Tree struct {
	root *node
	free *node

	alloc []node
}

const (
	startbit = uint32(0x80000000)
)

var (
	ErrNodeBusy = errors.New("Node Busy")
	ErrBadIP    = errors.New("Bad IP address or mask")
)

// NewTree creates Tree and preallocates (if preallocate not zero) number of nodes that would be ready to fill with data.
func NewTree() *Tree {
	tree := new(Tree)
	tree.root = tree.newnode()
	return tree
}

func (tree *Tree) SetCIDRb(cidr []byte, val interface{}) error {
	ip, mask, err := parsecidr4(cidr)
	if err != nil {
		return err
	}
	return tree.insert32(ip, mask, val)
}

func (tree *Tree) FindCIDRb(cidr []byte) (interface{}, error) {
	ip, mask, err := parsecidr4(cidr)
	if err != nil {
		return nil, err
	}
	return tree.find32(ip, mask), nil

}

func (tree *Tree) insert32(key, mask uint32, value interface{}) error {
	bit := startbit
	node := tree.root
	next := tree.root
	for bit&mask != 0 {
		if key&bit != 0 {
			next = node.right
		} else {
			next = node.left
		}
		if next == nil {
			break
		}
		bit = bit >> 1
		node = next
	}
	if next != nil {
		node.value = value
		return nil
	}
	for bit&mask != 0 {
		next = tree.newnode()
		if key&bit != 0 {
			node.right = next
		} else {
			node.left = next
		}
		bit >>= 1
		node = next
	}
	node.value = value

	return nil
}

func (tree *Tree) find32(key, mask uint32) (value interface{}) {
	bit := startbit
	node := tree.root
	for node != nil {
		if node.value != nil {
			value = node.value
		}
		if key&bit != 0 {
			node = node.right
		} else {
			node = node.left
		}
		if mask&bit == 0 {
			break
		}
		bit >>= 1

	}
	return value
}

func (tree *Tree) newnode() (p *node) {
	if tree.free != nil {
		p = tree.free
		tree.free = tree.free.right

		// release all prior links
		p.right = nil
		p.left = nil
		p.value = nil
		return p
	}

	ln := len(tree.alloc)
	if ln == cap(tree.alloc) {
		// filled one row, make bigger one
		tree.alloc = make([]node, ln+200)[:1] // 200, 600, 1400, 3000, 6200, 12600 ...
		ln = 0
	} else {
		tree.alloc = tree.alloc[:ln+1]
	}
	return &(tree.alloc[ln])
}

func loadip4(ipstr []byte) (uint32, error) {
	var (
		ip  uint32
		oct uint32
		b   byte
		num byte
	)

	for _, b = range ipstr {
		switch {
		case b == '.':
			num++
			if 0xffffffff-ip < oct {
				return 0, ErrBadIP
			}
			ip = ip<<8 + oct
			oct = 0
		case b >= '0' && b <= '9':
			oct = oct*10 + uint32(b-'0')
			if oct > 255 {
				return 0, ErrBadIP
			}
		default:
			return 0, ErrBadIP
		}
	}
	if num != 3 {
		return 0, ErrBadIP
	}
	if 0xffffffff-ip < oct {
		return 0, ErrBadIP
	}
	return ip<<8 + oct, nil
}

func parsecidr4(cidr []byte) (uint32, uint32, error) {
	var mask uint32
	p := bytes.IndexByte(cidr, '/')
	if p > 0 {
		for _, c := range cidr[p+1:] {
			if c < '0' || c > '9' {
				return 0, 0, ErrBadIP
			}
			mask = mask*10 + uint32(c-'0')
		}
		mask = 0xffffffff << (32 - mask)
		cidr = cidr[:p]
	} else {
		mask = 0xffffffff
	}
	ip, err := loadip4(cidr)
	if err != nil {
		return 0, 0, err
	}
	return ip, mask, nil
}
