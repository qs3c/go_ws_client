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
func Intersection[T comparable](preferred, other []T) (T, bool) {
	if len(preferred) == 0 || len(other) == 0 {
		var zero T
		return zero, false
	}
	elementMap := make(map[T]struct{}, len(other))
	for _, v := range other {
		elementMap[v] = struct{}{}
	}
	for _, v := range preferred {
		if _, exists := elementMap[v]; exists {
			return v, true
		}
	}
	var zero T
	return zero, false
}

func BEUint16(b []byte) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[1]) | uint16(b[0])<<8
}

// todo:
// 1. 读取本地静态公钥的方法（其实就是对key.go中方法的上层封装），那么就是要设计静态公钥文件夹结构
// 2. sm2的协议构建是需要很多外围信息的比如id等，从这里开始倒推，搞清楚和ciphersuite中ka的关系
