# amicontained

[![make-all](https://github.com/tuxerrante/amicontained/workflows/make%20all/badge.svg)](https://github.com/tuxerrante/amicontained/actions?query=workflow%3A%22make+all%22)
[![make-image](https://github.com/tuxerrante/amicontained/workflows/make%20image/badge.svg)](https://github.com/tuxerrante/amicontained/actions?query=workflow%3A%22make+image%22)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=for-the-badge)](https://godoc.org/github.com/tuxerrante/amicontained)
[![Github All Releases](https://img.shields.io/github/downloads/tuxerrante/amicontained/total.svg?style=for-the-badge)](https://github.com/tuxerrante/amicontained/releases)

Container introspection tool. Find out what container runtime is being used as
well as features available.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Installation](#installation)
    - [Binaries](#binaries)
    - [Via Go](#via-go)
- [Usage](#usage)
- [Examples](#examples)
    - [docker](#docker)
    - [lxc](#lxc)
    - [systemd-nspawn](#systemd-nspawn)
    - [rkt](#rkt)
    - [unshare](#unshare)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Installation

#### Binaries

For installation instructions from binaries please visit the [Releases Page](https://github.com/tuxerrante/amicontained/releases).

#### Via Go

```bash
$ go get github.com/tuxerrante/amicontained
```

## Usage

```console
$ amicontained -h
amicontained -  A container introspection tool.

Usage: amicontained <command>

Flags:

  -d  enable debug logging (default: false)

Commands:

  version  Show the version information.
```

## Examples

#### docker

```console
$ docker run --rm -it ghcr.io/tuxerrante/amicontained
Container Runtime: docker
Has Namespaces:
        pid: true
        user: true
User Namespace Mappings:
	Container -> 0
	Host -> 886432
	Range -> 65536
AppArmor Profile: docker-default (enforce)
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Seccomp: filtering
Blocked Syscalls (57):
    MSGRCV PTRACE SYSLOG SETPGID SETSID USELIB USTAT SYSFS VHANGUP PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM CREATE_MODULE INIT_MODULE DELETE_MODULE GET_KERNEL_SYMS QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD_KEY REQUEST_KEY KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN FANOTIFY_INIT NAME_TO_HANDLE_AT OPEN_BY_HANDLE_AT CLOCK_ADJTIME SETNS PROCESS_VM_READV PROCESS_VM_WRITEV KCMP FINIT_MODULE

$ docker run --rm -it --pid host ghcr.io/tuxerrante/amicontained
Container Runtime: docker
Has Namespaces:
        pid: false
        user: false
AppArmor Profile: docker-default (enforce)
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Seccomp: filtering
Blocked Syscalls (57):
    MSGRCV PTRACE SYSLOG SETPGID SETSID USELIB USTAT SYSFS VHANGUP PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM CREATE_MODULE INIT_MODULE DELETE_MODULE GET_KERNEL_SYMS QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD_KEY REQUEST_KEY KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN FANOTIFY_INIT NAME_TO_HANDLE_AT OPEN_BY_HANDLE_AT CLOCK_ADJTIME SETNS PROCESS_VM_READV PROCESS_VM_WRITEV KCMP FINIT_MODULE

$ docker run --rm -it --security-opt "apparmor=unconfined" ghcr.io/tuxerrante/amicontained
Container Runtime: docker
Has Namespaces:
        pid: true
        user: false
AppArmor Profile: unconfined
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
Seccomp: filtering
Blocked Syscalls (57):
    MSGRCV PTRACE SYSLOG SETPGID SETSID USELIB USTAT SYSFS VHANGUP PIVOT_ROOT _SYSCTL ACCT SETTIMEOFDAY MOUNT UMOUNT2 SWAPON SWAPOFF REBOOT SETHOSTNAME SETDOMAINNAME IOPL IOPERM CREATE_MODULE INIT_MODULE DELETE_MODULE GET_KERNEL_SYMS QUERY_MODULE QUOTACTL NFSSERVCTL GETPMSG PUTPMSG AFS_SYSCALL TUXCALL SECURITY LOOKUP_DCOOKIE CLOCK_SETTIME VSERVER MBIND SET_MEMPOLICY GET_MEMPOLICY KEXEC_LOAD ADD_KEY REQUEST_KEY KEYCTL MIGRATE_PAGES UNSHARE MOVE_PAGES PERF_EVENT_OPEN FANOTIFY_INIT NAME_TO_HANDLE_AT OPEN_BY_HANDLE_AT CLOCK_ADJTIME SETNS PROCESS_VM_READV PROCESS_VM_WRITEV KCMP FINIT_MODULE


$ docker run -it --rm \
  --pid=host \
  --userns=host \
  --cap-add=ALL \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/tuxerrante/amicontained -- amicontained

amicontained - A container introspection tool.
Version: dev
Container Runtime: docker (/.dockerenv present)
Has Namespaces:
	pid: error -> permission denied reading host namespace; try running as root
	user: false
User Namespace Mappings:
	Container -> 0	Host -> 0	Range -> 4294967295
AppArmor Profile: docker-default (enforce)
Capabilities:
	Bounding ->
		CAP_CHOWN
		CAP_DAC_OVERRIDE
		CAP_FOWNER
		CAP_FSETID
		CAP_KILL
		CAP_SETGID
		CAP_SETUID
		CAP_SETPCAP
		CAP_NET_BIND_SERVICE
		CAP_NET_RAW
		CAP_SYS_CHROOT
		CAP_MKNOD
		CAP_AUDIT_WRITE
		CAP_SETFCAPSeccomp: filter (2)
Blocked Syscalls (64):
	SYS_70 msgrcv - Receive a message from a System V message queue
	SYS_103 syslog - System log
	SYS_105 setuid - Set user identity
	SYS_106 setgid - Set group identity
	SYS_109 setpgid - Set process group ID
	SYS_112 setsid - Create a session and set process group ID
	SYS_113 setreuid - Set real and effective user IDs
	SYS_114 setregid - Set real and effective group IDs
	SYS_116 setgroups - Set list of supplementary group IDs
	SYS_117 setresuid - Set real, effective and saved user IDs
	SYS_119 setresgid - Set real, effective and saved group IDs
	SYS_134 uselib - Load shared library (obsolete)
	SYS_136 ustat - Get filesystem statistics (obsolete)
	SYS_139 sysfs - Get file system type information
	SYS_153 vhangup - Simulate a hangup on the controlling terminal
	SYS_155 pivot_root - Change the root filesystem
	SYS_156 _sysctl - Read/write kernel parameters (obsolete)
	SYS_163 acct - Switch process accounting on or off
	SYS_164 settimeofday - Set system time and timezone
	SYS_165 mount - Mount a filesystem
	SYS_166 umount2 - Unmount a filesystem
	SYS_167 swapon - Start swapping to file/device
	SYS_168 swapoff - Stop swapping to file/device
	SYS_169 reboot - Reboot or enable/disable Ctrl-Alt-Del
	SYS_170 sethostname - Set system hostname
	SYS_171 setdomainname - Set NIS domain name
	SYS_172 iopl - Change I/O privilege level
	SYS_173 ioperm - Set port input/output permissions
	SYS_174 create_module - Create a loadable module entry (obsolete)
	SYS_175 init_module - Load a kernel module
	SYS_176 delete_module - Unload a kernel module
	SYS_177 get_kernel_syms - Get exported kernel symbols (obsolete)
	SYS_178 query_module - Query kernel module (obsolete)
	SYS_179 quotactl - Manipulate disk quotas
	SYS_180 nfsservctl - Kernel nfs daemon services
	SYS_181 getpmsg - Get a message from a STREAMS-based device (obsolete)
	SYS_182 putpmsg - Send a message to a STREAMS-based device (obsolete)
	SYS_183 afs_syscall - Reserved for AFS (obsolete)
	SYS_184 tuxcall - Reserved for TUX (obsolete)
	SYS_185 security - Kernel security
	SYS_212 lookup_dcookie - Retrieve a directory entry's cookie
	SYS_227 clock_settime - Set time of a specified clock
	SYS_236 vserver - Unused (was for virtual servers)
	SYS_237 mbind - Set memory policy for a memory range
	SYS_238 set_mempolicy - Set default NUMA memory policy
	SYS_239 get_mempolicy - Retrieve NUMA memory policy
	SYS_246 kexec_load - Load a new kernel for later execution
	SYS_248 add_key - Add a key to the kernel's key management facility
	SYS_249 request_key - Request a key from the kernel's key management facility
	SYS_250 keyctl - Key management facility operations
	SYS_256 migrate_pages - Move memory pages between nodes
	SYS_261 futimesat - Change file last access and modification times relative to a directory file descriptor
	SYS_272 unshare - Disassociate parts of the process execution context
	SYS_279 move_pages - Move individual pages of a process to another node
	SYS_280 utimensat - Change file timestamps with nanosecond precision
	SYS_298 perf_event_open - Set up performance monitoring
	SYS_300 fanotify_init - Initialize a fanotify group
	SYS_304 open_by_handle_at - Open a file via handle
	SYS_308 setns - Reassociate a thread with a namespace
	SYS_312 kcmp - Compare two processes to determine if they share a kernel resource
	SYS_313 finit_module - Load a kernel module from a file descriptor
	SYS_320 kexec_file_load - Load a new kernel for later execution (file-based)
	SYS_321 bpf - Perform a BPF operation
	SYS_323 userfaultfd - Create a userfaultfd object
Looking for Docker.sock
No Docker/OCI socket found.
Possible reasons:
  - The container is not running with the Docker/OCI socket mounted (e.g., -v /var/run/docker.sock:/var/run/docker.sock)
  - The container runtime does not use a supported socket path
  - Insufficient permissions to access the socket
  - The host does not have a Docker/OCI runtime running



$ docker run -it --rm   --pid=host   --userns=host   --cap-add=ALL   --security-opt seccomp=unconfined   --security-opt apparmor=unconfined   -v /var/run/docker.sock:/var/run/docker.sock   ghcr.io/tuxerrante/amicontained -- amicontained
amicontained - A container introspection tool.
Version: dev
Container Runtime: docker (/.dockerenv present)
Has Namespaces:
	pid: error -> permission denied reading host namespace; try running as root
	user: false
User Namespace Mappings:
	Container -> 0	Host -> 0	Range -> 4294967295
AppArmor Profile: unconfined
Capabilities:
	Bounding ->
		CAP_CHOWN
		CAP_DAC_OVERRIDE
		CAP_DAC_READ_SEARCH
		CAP_FOWNER
		CAP_FSETID
		CAP_KILL
		CAP_SETGID
		CAP_SETUID
		CAP_SETPCAP
		CAP_LINUX_IMMUTABLE
		CAP_NET_BIND_SERVICE
		CAP_NET_BROADCAST
		CAP_NET_ADMIN
		CAP_NET_RAW
		CAP_IPC_LOCK
		CAP_IPC_OWNER
		CAP_SYS_MODULE
		CAP_SYS_RAWIO
		CAP_SYS_CHROOT
		CAP_SYS_PTRACE
		CAP_SYS_PACCT
		CAP_SYS_ADMIN
		CAP_SYS_BOOT
		CAP_SYS_NICE
		CAP_SYS_RESOURCE
		CAP_SYS_TIME
		CAP_SYS_TTY_CONFIG
		CAP_MKNOD
		CAP_LEASE
		CAP_AUDIT_WRITE
		CAP_AUDIT_CONTROL
		CAP_SETFCAP
		CAP_MAC_OVERRIDE
		CAP_MAC_ADMIN
		CAP_SYSLOG
		CAP_WAKE_ALARM
		CAP_BLOCK_SUSPEND
		CAP_AUDIT_READSeccomp: disabled (0)
Blocked Syscalls (31):
	SYS_70 msgrcv - Receive a message from a System V message queue
	SYS_103 syslog - System log
	SYS_105 setuid - Set user identity
	SYS_106 setgid - Set group identity
	SYS_109 setpgid - Set process group ID
	SYS_112 setsid - Create a session and set process group ID
	SYS_113 setreuid - Set real and effective user IDs
	SYS_114 setregid - Set real and effective group IDs
	SYS_116 setgroups - Set list of supplementary group IDs
	SYS_117 setresuid - Set real, effective and saved user IDs
	SYS_119 setresgid - Set real, effective and saved group IDs
	SYS_153 vhangup - Simulate a hangup on the controlling terminal
	SYS_155 pivot_root - Change the root filesystem
	SYS_163 acct - Switch process accounting on or off
	SYS_164 settimeofday - Set system time and timezone
	SYS_167 swapon - Start swapping to file/device
	SYS_168 swapoff - Stop swapping to file/device
	SYS_169 reboot - Reboot or enable/disable Ctrl-Alt-Del
	SYS_170 sethostname - Set system hostname
	SYS_171 setdomainname - Set NIS domain name
	SYS_175 init_module - Load a kernel module
	SYS_176 delete_module - Unload a kernel module
	SYS_246 kexec_load - Load a new kernel for later execution
	SYS_261 futimesat - Change file last access and modification times relative to a directory file descriptor
	SYS_280 utimensat - Change file timestamps with nanosecond precision
	SYS_298 perf_event_open - Set up performance monitoring
	SYS_300 fanotify_init - Initialize a fanotify group
	SYS_304 open_by_handle_at - Open a file via handle
	SYS_313 finit_module - Load a kernel module from a file descriptor
	SYS_320 kexec_file_load - Load a new kernel for later execution (file-based)
	SYS_323 userfaultfd - Create a userfaultfd object
Looking for Docker.sock
No Docker/OCI socket found.
Possible reasons:
  - The container is not running with the Docker/OCI socket mounted (e.g., -v /var/run/docker.sock:/var/run/docker.sock)
  - The container runtime does not use a supported socket path
  - Insufficient permissions to access the socket
  - The host does not have a Docker/OCI runtime running


```

#### lxc

```console
$ lxc-attach -n xenial
root@xenial:/# amicontained
Container Runtime: lxc
Has Namespaces:
        pid: true
        user: true
User Namespace Mappings:
	Container -> 0	Host -> 100000	Range -> 65536
AppArmor Profile: none
Capabilities:
	BOUNDING -> chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_tty_config mknod lease audit_write audit_control setfcap syslog wake_alarm block_suspend audit_read

$ lxc-execute -n xenial -- /bin/amicontained
Container Runtime: lxc
Has Namespaces:
        pid: true
        user: true
User Namespace Mappings:
	Container -> 0	Host -> 100000	Range -> 65536
AppArmor Profile: none
Capabilities:
	BOUNDING -> chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_tty_config mknod lease audit_write audit_control setfcap syslog wake_alarm block_suspend audit_read
```

#### systemd-nspawn

```console
$ sudo systemd-nspawn --machine amicontained --directory nspawn-amicontained /usr/bin/amicontained
Spawning container amicontained on /home/tuxerrante/nspawn-amicontained.
Press ^] three times within 1s to kill container.
Timezone UTC does not exist in container, not updating container timezone.
Container Runtime: systemd-nspawn
Has Namespaces:
        pid: true
        user: false
AppArmor Profile: none
Capabilities:
	BOUNDING -> chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_raw ipc_owner sys_chroot sys_ptrace sys_admin sys_boot sys_nice sys_resource sys_tty_config mknod lease audit_write audit_control setfcap
Container amicontained exited successfully.
```

#### rkt

```console
$ sudo rkt --insecure-options=image run docker://ghcr.io/tuxerrante/amicontained
[  631.522121] amicontained[5]: Container Runtime: rkt
[  631.522471] amicontained[5]: Host PID Namespace: false
[  631.522617] amicontained[5]: AppArmor Profile: none
[  631.522768] amicontained[5]: User Namespace: false
[  631.522922] amicontained[5]: Capabilities:
[  631.523075] amicontained[5]: 	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

$ sudo rkt --insecure-options=image run  --private-users=true --no-overlay docker://ghcr.io/tuxerrante/amicontained
[  785.547050] amicontained[5]: Container Runtime: rkt
[  785.547360] amicontained[5]: Host PID Namespace: false
[  785.547567] amicontained[5]: AppArmor Profile: none
[  785.547717] amicontained[5]: User Namespace: true
[  785.547856] amicontained[5]: User Namespace Mappings:
[  785.548064] amicontained[5]: 	Container -> 0	Host -> 229834752	Range -> 65536
[  785.548335] amicontained[5]: Capabilities:
[  785.548537] amicontained[5]: 	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap
```

#### unshare

```console
$ sudo unshare --user -r
root@coreos:/home/jessie/.go/src/github.com/tuxerrante/amicontained# ./amicontained
Container Runtime: not-found
Has Namespaces:
        pid: false
        user: true
User Namespace Mappings:
	Container -> 0
	Host -> 0
	Range -> 1
AppArmor Profile: unconfined
Capabilities:
	BOUNDING -> chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read
```
