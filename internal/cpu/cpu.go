// 将 golang.org/x/sys/cpu 桥接为 internal/cpu 兼容接口。
package cpu

import "golang.org/x/sys/cpu"

// X86 包含 x86/amd64 架构的 CPU 特性标志。
var X86 = struct {
	HasAES       bool
	HasAESCTR    bool
	HasPCLMULQDQ bool
	HasSSE41     bool
	HasSSSE3     bool
}{
	HasAES:       cpu.X86.HasAES,
	HasPCLMULQDQ: cpu.X86.HasPCLMULQDQ,
	HasSSE41:     cpu.X86.HasSSE41,
	HasSSSE3:     cpu.X86.HasSSSE3,
}

// ARM64 包含 arm64 架构的 CPU 特性标志。
var ARM64 = struct {
	HasAES   bool
	HasPMULL bool
}{
	HasAES:   cpu.ARM64.HasAES,
	HasPMULL: cpu.ARM64.HasPMULL,
}

// S390X 包含 s390x 架构的 CPU 特性标志。
var S390X = struct {
	HasAES    bool
	HasAESCTR bool
	HasGHASH  bool
}{
	HasAES:    cpu.S390X.HasAES,
	HasAESCTR: cpu.S390X.HasAESCTR,
	HasGHASH:  cpu.S390X.HasGHASH,
}
