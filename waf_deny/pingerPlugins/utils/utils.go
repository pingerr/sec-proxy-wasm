package utils

import "unsafe"

// WrapUnsafe wraps the provided buffer as a string. The buffer
// must not be mutated after calling this function.
func WrapUnsafe(buf []byte) string {
	return *(*string)(unsafe.Pointer(&buf))
}
