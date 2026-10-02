package limit

import (
	"math"
	"math/bits"
)

// hllP 是 HyperLogLog 的精度：2^10 = 1024 个寄存器，每个实例每天 1KB，误差约 3%。
const (
	hllP = 10
	hllM = 1 << hllP
)

// HLL 是一个 HyperLogLog 近似计数器，用来数「不同设备数」。
//
// 寄存器里只记哈希值前导零的个数，从中还原不出任何设备令牌或令牌哈希，所以可以
// 放心落盘——这正是方案里「不保存令牌哈希」的要求。
type HLL [hllM]uint8

// Add 加入一个 64 位哈希值。
func (h *HLL) Add(x uint64) {
	idx := x >> (64 - hllP)
	// 剩下的位左移到顶端，再补一个哨兵位，保证前导零数不超过 64-hllP。
	w := x<<hllP | 1<<(hllP-1)
	rho := uint8(bits.LeadingZeros64(w)) + 1
	if rho > h[idx] {
		h[idx] = rho
	}
}

// Count 返回近似的不同元素个数。
func (h *HLL) Count() int64 {
	const m = float64(hllM)
	alpha := 0.7213 / (1 + 1.079/m)
	sum, zeros := 0.0, 0
	for _, r := range h {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	est := alpha * m * m / sum
	// 小基数时改用线性计数，否则误差很大（每个实例的设备数通常只有个位数）。
	if est <= 2.5*m && zeros > 0 {
		est = m * math.Log(m/float64(zeros))
	}
	return int64(est + 0.5)
}
