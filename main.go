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

// 设置 DNS 服务器
func setDNS(primaryDNS, secondaryDNS string) error {
	// 设置主 DNS
	cmd1 := exec.Command("netsh", "interface", "ip", "set", "dns",
		"name="+INTERFACE_NAME, "static", primaryDNS)
	if err := cmd1.Run(); err != nil {
		return fmt.Errorf("设置主 DNS 失败: %v", err)
	}

	// 设置备用 DNS
	cmd2 := exec.Command("netsh", "interface", "ip", "add", "dns",
		"name="+INTERFACE_NAME, secondaryDNS, "index=2")
	if err := cmd2.Run(); err != nil {
		return fmt.Errorf("设置备用 DNS 失败: %v", err)
	}

	fmt.Printf("✓ DNS 已设置为: %s, %s\n", primaryDNS, secondaryDNS)
	return nil
}

// 设置自定义 IP 配置
func setCustomIP(ip, netmask, gateway, primaryDNS, secondaryDNS string) error {
	// 先设置 IP 地址
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+INTERFACE_NAME,
		"static",
		ip,
		netmask,
		gateway,
		"1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置 IP 失败: %v\n输出: %s", err, string(output))
	}

	// 再设置 DNS
	if err := setDNS(primaryDNS, secondaryDNS); err != nil {
		return err
	}

	fmt.Printf("✓ 自定义 IP 配置已应用: %s/%s 网关:%s\n", ip, netmask, gateway)
	return nil
}

// 恢复 DHCP
func setDHCP() error {
	// 先恢复 IP 为 DHCP
	cmd1 := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+INTERFACE_NAME, "dhcp")
	if err := cmd1.Run(); err != nil {
		return fmt.Errorf("恢复 DHCP 失败: %v", err)
	}

	// 再恢复 DNS 为 DHCP
	cmd2 := exec.Command("netsh", "interface", "ip", "set", "dns",
		"name="+INTERFACE_NAME, "dhcp")
	if err := cmd2.Run(); err != nil {
		return fmt.Errorf("恢复 DNS DHCP 失败: %v", err)
	}

	fmt.Printf("✓ 已恢复 DHCP 自动获取\n")
	return nil
}

// 显示帮助
func showHelp() {
	fmt.Println("IP 切换工具 v1.0")
	fmt.Println("用法: ipswitch.exe <profile|dhcp|custom>")
	fmt.Println("\n可用配置:")
	for _, p := range profiles {
		fmt.Printf("  %s: %s/%s 网关:%s\n", p.Name, p.IP, p.Netmask, p.Gateway)
	}
	fmt.Println("  dhcp: 恢复自动获取 IP")
	fmt.Println("  custom: 手动输入 IP 配置")
}

// 获取用户输入
func getUserInput(prompt string) string {
	fmt.Print(prompt)
	var input string
	fmt.Scanln(&input)
	return input
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

	// 处理自定义 IP 配置
	if target == "custom" {
		fmt.Println("请输入自定义 IP 配置 (留空使用默认值):")
		ip := getUserInput("IP 地址: ")
		if ip == "" {
			fmt.Println("❌ IP 地址不能为空")
			os.Exit(1)
		}
		
		netmask := getUserInput("子网掩码 (默认 255.255.255.0): ")
		if netmask == "" {
			netmask = "255.255.255.0"
		}
		
		gateway := getUserInput("网关地址: ")
		if gateway == "" {
			fmt.Println("❌ 网关地址不能为空")
			os.Exit(1)
		}
		
		primaryDNS := getUserInput("主 DNS (默认 223.5.5.5): ")
		if primaryDNS == "" {
			primaryDNS = "223.5.5.5"
		}
		
		secondaryDNS := getUserInput("备用 DNS (默认 119.29.29.29): ")
		if secondaryDNS == "" {
			secondaryDNS = "119.29.29.29"
		}
		
		if err := setCustomIP(ip, netmask, gateway, primaryDNS, secondaryDNS); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 查找匹配的配置
	for _, p := range profiles {
		if p.Name == target {
			// 设置 IP
			if err := setStaticIP(p); err != nil {
				fmt.Printf("❌ %v\n", err)
				os.Exit(1)
			}
			// 设置默认 DNS
			if err := setDNS("223.5.5.5", "119.29.29.29"); err != nil {
				fmt.Printf("❌ %v\n", err)
				os.Exit(1)
			}
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
