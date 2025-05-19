//go:build linux
// +build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var debug bool

func main() {
	flag.BoolVar(&debug, "d", false, "enable debug logging")
	flag.Parse()

	fmt.Println("amicontained - A container introspection tool.")
	fmt.Println("Version:", getVersion())

	// Container Runtime
	runtime := getContainerRuntime()
	fmt.Printf("Container Runtime: %s\n", runtime)

	// Namespaces
	namespaces := []string{"pid"}
	fmt.Println("Has Namespaces:")
	for _, namespace := range namespaces {
		ns, err := hasNamespace(namespace)
		if err != nil {
			fmt.Printf("\t%s: error -> %v\n", namespace, err)
			continue
		}
		fmt.Printf("\t%s: %t\n", namespace, ns)
	}

	// User Namespaces
	userNS, userMappings := getUserNamespaceInfo()
	fmt.Printf("\tuser: %t\n", userNS)
	if len(userMappings) > 0 {
		fmt.Println("User Namespace Mappings:")
		for _, userMapping := range userMappings {
			fmt.Printf("\tContainer -> %d\tHost -> %d\tRange -> %d\n", userMapping.ContainerID, userMapping.HostID, userMapping.Range)
		}
	}

	// AppArmor Profile
	aaprof := getAppArmorProfile()
	fmt.Printf("AppArmor Profile: %s\n", aaprof)

	// Capabilities
	caps, err := getCapabilities()
	if err != nil && debug {
		log.Printf("getting capabilities failed: %v", err)
	}
	if len(caps) > 0 {
		fmt.Println("Capabilities:")
		for k, v := range caps {
			if len(v) > 0 {
				fmt.Printf("\t%s ->\n\t\t%s", k, strings.Join(v, "\n\t\t"))
			}
		}
	}

	// Seccomp
	seccompMode := getSeccompEnforcingMode()
	fmt.Printf("Seccomp: %s\n", seccompMode)

	seccompIter()

	// Docker.sock
	fmt.Println("Looking for Docker.sock")
	sockets, _ := getValidSockets("")
	if len(sockets) == 0 {
		fmt.Println("No Docker/OCI socket found.")
		fmt.Println("Possible reasons:")
		fmt.Println("  - The container is not running with the Docker/OCI socket mounted (e.g., -v /var/run/docker.sock:/var/run/docker.sock)")
		fmt.Println("  - The container runtime does not use a supported socket path")
		fmt.Println("  - Insufficient permissions to access the socket")
		fmt.Println("  - The host does not have a Docker/OCI runtime running")
	}
}

func getValidSockets(_ string) ([]string, error) {
	// List of common container socket paths
	socketPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/run/crio/crio.sock",
		"/run/podman/podman.sock",
	}
	sockets := []string{}
	for _, path := range socketPaths {
		info, err := os.Stat(path)
		if err != nil {
			if debug {
				log.Printf("Socket not found: %s (%v)", path, err)
			}
			continue
		}
		if info.Mode()&os.ModeSocket != 0 {
			resp, err := checkSock(path)
			if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode <= 299 {
				fmt.Println("Valid Docker/OCI Socket:", path)
				sockets = append(sockets, path)
				if resp != nil {
					errClose := resp.Body.Close()
					if errClose != nil && debug {
						log.Printf("Error closing response body: %v", errClose)
					}
				}
			} else if debug {
				log.Printf("Invalid Docker/OCI Socket: %s", path)
			}
		}
	}
	return sockets, nil
}

func checkSock(path string) (*http.Response, error) {
	if debug {
		log.Println("[-] Checking Sock for HTTP:", path)
	}
	// Use net.Dial for unix socket
	tr := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", path)
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   2 * time.Second,
	}
	resp, err := client.Get("http://unix/info")
	return resp, err
}

func seccompIter() {
	allowed := []string{}
	blocked := []string{}

	for id := 0; id <= unix.SYS_RSEQ; id++ {
		// Skip syscalls that may hang or terminate the process
		switch id {
		case unix.SYS_RT_SIGRETURN, unix.SYS_SELECT, unix.SYS_PAUSE, unix.SYS_PSELECT6, unix.SYS_PPOLL,
			unix.SYS_EXIT, unix.SYS_EXIT_GROUP, unix.SYS_CLONE, unix.SYS_FORK, unix.SYS_VFORK, unix.SYS_SECCOMP:
			continue
		}

		errCh := make(chan error, 1)
		go func(sysid int) {
			_, _, err := syscall.Syscall(uintptr(sysid), 0, 0, 0)
			errCh <- err
		}(id)

		var err error
		select {
		case err = <-errCh:
		case <-time.After(100 * time.Millisecond):
			// The syscall was allowed, but it didn't return
		}

		if err == syscall.EPERM || err == syscall.EACCES {
			blocked = append(blocked, syscallName(id))
		} else if err != syscall.EOPNOTSUPP {
			allowed = append(allowed, syscallName(id))
		}
	}

	if debug && len(allowed) > 0 {
		fmt.Printf("Allowed Syscalls (%d):\n", len(allowed))
		fmt.Printf("\t%s\n", strings.Join(allowed, "\n\t"))
	}

	if len(blocked) > 0 {
		fmt.Printf("Blocked Syscalls (%d):\n", len(blocked))
		fmt.Printf("\t%s\n", strings.Join(blocked, "\n\t"))
	}
}

func loadSyscallDescriptions(path string) map[int]string {
	descs := make(map[int]string)
	file, err := os.Open(path)
	if err != nil {
		return descs
	}
	defer func() {
		errClose := file.Close()
		if errClose != nil && debug {
			log.Printf("Error closing file: %v", errClose)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var num int
		var name, desc string
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		num, err = strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		name = fields[1]
		desc = strings.Join(fields[2:], " ")
		descs[num] = fmt.Sprintf("%s - %s", name, desc)
	}
	return descs
}

var syscallDescriptions = loadSyscallDescriptions("/syscalls_linux.tbl")

func syscallName(e int) string {
	if desc, ok := syscallDescriptions[e]; ok {
		return fmt.Sprintf("SYS_%d %s", e, desc)
	}
	return fmt.Sprintf("SYS_%d", e)
}

// Placeholder for version info, replace with actual version logic if needed.
func getVersion() string {
	return "dev"
}

// getContainerRuntime attempts to detect the container runtime.
func getContainerRuntime() string {
	// Check for Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker (/.dockerenv present)"
	}
	// Check for containerd
	if _, err := os.Stat("/run/containerd/containerd.sock"); err == nil {
		return "containerd (socket present)"
	}
	// Check for CRI-O
	if _, err := os.Stat("/run/crio/crio.sock"); err == nil {
		return "cri-o (socket present)"
	}
	// Check for Podman
	if _, err := os.Stat("/run/podman/podman.sock"); err == nil {
		return "podman (socket present)"
	}
	// Check cgroup info for container clues
	cgroupData, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		cgroupStr := string(cgroupData)
		details := []string{}
		if strings.Contains(cgroupStr, "docker") {
			details = append(details, "docker (cgroup)")
		}
		if strings.Contains(cgroupStr, "containerd") {
			details = append(details, "containerd (cgroup)")
		}
		if strings.Contains(cgroupStr, "crio") {
			details = append(details, "cri-o (cgroup)")
		}
		if strings.Contains(cgroupStr, "podman") {
			details = append(details, "podman (cgroup)")
		}
		if len(details) > 0 {
			return strings.Join(details, ", ")
		}
	}
	// Check for systemd-nspawn
	if _, err := os.Stat("/.containerenv"); err == nil {
		return "systemd-nspawn (/.containerenv present)"
	}
	// Check for LXC
	if _, err := os.Stat("/proc/1/environ"); err == nil {
		if data, err := os.ReadFile("/proc/1/environ"); err == nil {
			if strings.Contains(string(data), "container=lxc") {
				return "lxc (environ)"
			}
		}
	}
	return "unknown (no container runtime detected)"
}

// hasNamespace checks if the current process has the given namespace.
func hasNamespace(namespace string) (bool, error) {
	path := "/proc/self/ns/" + namespace
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return false, errors.New("not a namespace symlink")
	}
	ourNS, err := os.Readlink(path)
	if err != nil {
		return false, err
	}
	initNSPath := "/proc/1/ns/" + namespace
	initNS, err := os.Readlink(initNSPath)
	if err != nil {
		if os.IsPermission(err) {
			return false, errors.New("permission denied reading host namespace; try running as root")
		}
		return false, err
	}

	return ourNS != initNS, nil
}

type userMapping struct {
	ContainerID int
	HostID      int
	Range       int
}

// getUserNamespaceInfo returns if user namespace is enabled and the mappings.
func getUserNamespaceInfo() (bool, []userMapping) {
	const uidMapPath = "/proc/self/uid_map"
	file, err := os.Open(uidMapPath)
	if err != nil {
		return false, nil
	}
	defer func() {
		errClose := file.Close()
		if errClose != nil && debug {
			log.Printf("Error closing file: %v", errClose)
		}
	}()

	var mappings []userMapping
	var enabled bool
	buf := make([]byte, 4096)
	n, _ := file.Read(buf)
	lines := strings.Split(string(buf[:n]), "\n")
	for _, line := range lines {
		var cID, hID, rng int
		if _, err := fmt.Sscanf(line, "%d %d %d", &cID, &hID, &rng); err == nil {
			mappings = append(mappings, userMapping{ContainerID: cID, HostID: hID, Range: rng})
			if cID != 0 || hID != 0 || rng != 4294967295 { // 4294967295 is the default for no userns
				enabled = true
			}
		}
	}
	return enabled, mappings
}

// getAppArmorProfile returns the AppArmor profile name.
func getAppArmorProfile() string {
	const appArmorPath = "/proc/self/attr/current"
	data, err := os.ReadFile(appArmorPath)
	if err != nil {
		// AppArmor may not be enabled or supported (e.g., on WSL or some distros)
		if debug {
			out, _ := exec.Command("apparmor_parser", "--print-config").CombinedOutput()
			log.Printf("apparmor_parser --print-config:\n%s", out)

			out2, _ := exec.Command("apparmor_status", "--verbose").CombinedOutput()
			log.Printf("apparmor_status error: %v", out2)
		}
		return "unavailable"
	}
	profile := strings.TrimSpace(string(data))
	if profile == "" || profile == "unconfined" {
		return "unconfined"
	}
	return profile
}

// getCapabilities returns the process capabilities.
func getCapabilities() (map[string][]string, error) {
	caps := map[string][]string{}
	const statusPath = "/proc/self/status"
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return nil, err
	}
	capFields := map[string]string{
		"CapInh": "Inheritable",
		"CapPrm": "Permitted",
		"CapEff": "Effective",
		"CapBnd": "Bounding",
		"CapAmb": "Ambient",
	}
	for _, line := range strings.Split(string(data), "\n") {
		for field, name := range capFields {
			if strings.HasPrefix(line, field+":") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				capHex := fields[1]
				capVal, err := strconv.ParseUint(capHex, 16, 64)
				if err != nil {
					continue
				}
				capNames := decodeCapabilities(capVal)
				caps[name] = capNames
			}
		}
	}
	return caps, nil
}

// decodeCapabilities decodes a uint64 bitmask into a list of Linux capability names.
func decodeCapabilities(val uint64) []string {
	capList := []string{
		"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
		"CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
		"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
		"CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
		"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
		"CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
		"CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
		"CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
	}
	var names []string
	for i, name := range capList {
		if val&(1<<uint(i)) != 0 {
			names = append(names, name)
		}
	}
	return names
}

// getSeccompEnforcingMode returns the seccomp mode.
func getSeccompEnforcingMode() string {
	const statusPath = "/proc/self/status"
	data, err := os.ReadFile(statusPath)
	if err != nil {
		if debug {
			log.Printf("Error reading %s: %v", statusPath, err)
		}
		return "unknown"
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Seccomp:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return "unknown"
			}
			mode := fields[1]
			switch mode {
			case "0":
				return "disabled (0)"
			case "1":
				return "strict (1)"
			case "2":
				return "filter (2)"
			default:
				return "unknown (" + mode + ")"
			}
		}
	}
	return "unknown"
}
