package lctrie

type Entry struct {
	data int

	length int

	nextHop int
}

func getEntry(data int, length int, nextHop int) *Entry {
	return &Entry{
		data:    data >> (32 - length) << (32 - length),
		length:  length,
		nextHop: nextHop,
	}
}

func (e *Entry) isPrefixOf(t *Entry) bool {
	return e.length == 0 || e.length <= t.length && (e.data^t.data)>>(32-e.length) == 0
}

func (e *Entry) equals(t *Entry) bool {
	if e.data == t.data && e.length == t.length {
		return true
	}
	return false
}
