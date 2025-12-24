package e2ewebsocket

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// Intersection 通用切片交集（无重复元素专用）
func Intersection[T comparable](a, b []T) T {
	elementMap := make(map[T]struct{}, len(a))
	for _, v := range a {
		elementMap[v] = struct{}{}
	}

	for _, v := range b {
		if _, exists := elementMap[v]; exists {
			return v
		}
	}
	var zero T
	return zero
}
