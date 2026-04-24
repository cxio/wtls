// 简化版 GODEBUG 设置读取器，兼容标准库 internal/godebug 的公开接口。
package godebug

import (
	"os"
	"strings"
	"sync"
)

// Setting 对应 GODEBUG 中的一个键。
type Setting struct {
	name string
}

// New 返回指定名称的 GODEBUG 设置。
func New(name string) *Setting {
	return &Setting{name: name}
}

// Value 返回 GODEBUG 中该设置的当前值，若未设置返回空字符串。
func (s *Setting) Value() string {
	return lookup(s.name)
}

// IncNonDefault 在标准库中统计非默认行为次数，此实现为空操作。
func (s *Setting) IncNonDefault() {}

var (
	once     sync.Once
	settings map[string]string
)

func parse() {
	settings = make(map[string]string)
	for _, kv := range strings.Split(os.Getenv("GODEBUG"), ",") {
		if idx := strings.IndexByte(kv, '='); idx > 0 {
			settings[kv[:idx]] = kv[idx+1:]
		}
	}
}

func lookup(name string) string {
	once.Do(parse)
	return settings[name]
}
