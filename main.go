package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	shell32                   = windows.NewLazyDLL("shell32.dll")
	procShellExecuteW uintptr = shell32.NewProc("ShellExecuteW").Addr()
)

const (
	INTERFACE_NAME = "以太网" // ← 修改为你的网卡名称（中文系统通常为"以太网"）
)

type Profile struct {
	Name    string
	IP      string
	Netmask string // 点分十进制格式，如 255.255.254.0
	Gateway string
}

var profiles = []Profile{
	{Name: "test", IP: "192.168.51.232", Netmask: "255.255.255.0", Gateway: "192.168.51.1"},
	{Name: "work", IP: "172.16.100.57", Netmask: "255.255.254.0", Gateway: "172.16.101.254"},
}

// 检查是否具有管理员权限
func isAdministrator() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	// 获取当前进程令牌
	currentProcess := windows.CurrentProcess()
	var token windows.Token
	err = windows.OpenProcessToken(currentProcess, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	// 检查令牌是否属于管理员组
	return token.IsElevated()
}

// 直接调用 ShellExecuteW
func shellExecute(hwnd uintptr, verb, file, params, dir *uint16, showCmd int32) uintptr {
	ret, _, _ := syscall.Syscall6(procShellExecuteW, 6,
		hwnd,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(dir)),
		uintptr(showCmd))
	return ret
}

// 以管理员身份重启自身
func relaunchAsAdmin() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := ""
	if len(os.Args) > 1 {
		if os.Args[1] != "" {
			args = os.Args[1]
		} else {
			// 如果没有参数，显示帮助信息
			args = "help"
		}
	}

	verbPtr, _ := windows.UTF16PtrFromString(verb)
	exePtr, _ := windows.UTF16PtrFromString(exe)
	cwdPtr, _ := windows.UTF16PtrFromString(cwd)
	argPtr, _ := windows.UTF16PtrFromString(args)

	var showCmd int32 = 1 // SW_NORMAL
	ret := shellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if ret <= 32 {
		fmt.Println("❌ UAC 提权失败，请手动右键\"以管理员身份运行\"")
		os.Exit(1)
	}
	os.Exit(0)
}

// 执行 netsh 命令设置静态 IP
func setStaticIP(profile Profile) error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+INTERFACE_NAME,
		"static",
		profile.IP,
		profile.Netmask,
		profile.Gateway,
		"1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置 IP 失败: %v\n输出: %s", err, string(output))
	}
	fmt.Printf("✓ 已切换到 [%s]: %s/%s 网关:%s\n", profile.Name, profile.IP, profile.Netmask, profile.Gateway)
	return nil
}

// 恢复 DHCP
func setDHCP() error {
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+INTERFACE_NAME, "dhcp")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("恢复 DHCP 失败: %v", err)
	}
	fmt.Printf("✓ 已恢复 DHCP 自动获取\n")
	return nil
}

// 显示帮助
func showHelp() {
	fmt.Println("IP 切换工具 v1.0")
	fmt.Println("用法: ipswitch.exe <profile|dhcp>")
	fmt.Println("\n可用配置:")
	for _, p := range profiles {
		fmt.Printf("  %s: %s/%s 网关:%s\n", p.Name, p.IP, p.Netmask, p.Gateway)
	}
	fmt.Println("  dhcp: 恢复自动获取 IP")
}

func main() {
	// 检查管理员权限
	if !isAdministrator() {
		if len(os.Args) < 2 {
			showHelp()
			fmt.Println("\n⚠️  需要管理员权限，即将触发 UAC 提权...")
			relaunchAsAdmin()
		}
		relaunchAsAdmin()
	}

	// 解析参数
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	target := os.Args[1]
	if target == "dhcp" || target == "auto" {
		setDHCP()
		return
	}

	// 查找匹配的配置
	for _, p := range profiles {
		if p.Name == target {
			setStaticIP(p)
			return
		}
	}

	if target == "help" {
		showHelp()
		return
	}
	fmt.Printf("❌ 未找到配置 '%s'\n", target)
	showHelp()
	os.Exit(1)
}
