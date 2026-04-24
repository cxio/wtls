// 最小化 internal/testenv stub，供外部 fork 模块的测试使用。
package testenv

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// Builder 返回 CI 构建器名称；非 CI 环境返回空字符串。
func Builder() string {
	return os.Getenv("GO_BUILDER_NAME")
}

// GoToolPath 返回 go 工具链路径，找不到则跳过测试。
func GoToolPath(t testing.TB) string {
	t.Helper()
	path, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go tool not found: %v", err)
	}
	return path
}

// Executable 返回当前测试二进制文件的路径。
func Executable(t testing.TB) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

// MustHaveExecPath 若 path 不可执行则跳过测试。
func MustHaveExecPath(t testing.TB, path string) {
	t.Helper()
	if _, err := exec.LookPath(path); err != nil {
		t.Skipf("executable %q not found: %v", path, err)
	}
}

// MustHaveExternalNetwork 若无外网访问则跳过测试。
func MustHaveExternalNetwork(t testing.TB) {
	t.Helper()
	if os.Getenv("NO_EXTERNAL_NETWORK") != "" {
		t.Skip("external network not available")
	}
}

// CPUIsSlow 在慢速 CPU 架构（arm、wasm 等）上返回 true。
func CPUIsSlow() bool {
	switch runtime.GOARCH {
	case "arm", "mips", "mipsle", "mips64", "mips64le", "wasm":
		return true
	}
	return false
}

// Command 创建一个 exec.Cmd。
func Command(t testing.TB, name string, args ...string) *exec.Cmd {
	t.Helper()
	return exec.Command(name, args...)
}

// CleanCmdEnv 继承当前进程环境。
func CleanCmdEnv(cmd *exec.Cmd) *exec.Cmd {
	cmd.Env = os.Environ()
	return cmd
}
