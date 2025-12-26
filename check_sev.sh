#!/bin/sh
# check_sev.sh — Auto-check AMD SEV(v1)/KVM hardware acceleration (POSIX sh)
# Usage:
#   sh check_sev.sh           # 自动判断在宿主或来宾中运行并检测
#   sh check_sev.sh --host    # 强制宿主模式
#   sh check_sev.sh --guest   # 强制来宾模式
# Exit codes:
#   0 = 脚本执行成功（不代表所有检查都通过）；1 = 参数错误

say() { printf "%s\n" "$*"; }
ok()  { say "[ OK ] $*"; }
bad() { say "[FAIL] $*"; }
info(){ say "[INFO] $*"; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }
grep_i() { grep -i "$@" 2>/dev/null; }

# -------- 通用工具 --------
flag_in_cpuinfo() {
    # $1 = 标志名（如 svm/hypervisor）
    if [ -r /proc/cpuinfo ]; then
        grep -qw "$1" /proc/cpuinfo && return 0
    fi
    return 1
}

dmesg_has() {
    if has_cmd dmesg; then
        dmesg 2>/dev/null | grep_i "$1" >/dev/null 2>&1 && return 0
    fi
    return 1
}

lsmod_has() {
    if has_cmd lsmod; then
        lsmod 2>/dev/null | grep -w "$1" >/dev/null 2>&1 && return 0
    fi
    # 退化：/sys/module 存在也视为已加载
    [ -d "/sys/module/$1" ] && return 0
    return 1
}

qemu_cmdline_has() {
    # 查带 SEV 关键参数的 qemu 进程
    if has_cmd ps; then
        ps ax 2>/dev/null | grep -E "qemu-system-x86_64|qemu-kvm" | grep -v grep | grep -q "$1" && return 0
    fi
    return 1
}

read_sysfs() {
    # 读取 sysfs 文件，返回值或空
    f="$1"
    [ -r "$f" ] && cat "$f" 2>/dev/null || true
}

# -------- 来宾侧检查（Guest）--------
check_guest() {
    say "=== 来宾(Guest)侧检测（SEV v1） ==="

    G_SEV=0; G_KVM=0; G_DMESG=0

    # 1) dmesg：SEV 激活日志（内核通常打印）
    if dmesg_has "AMD Secure Encrypted Virtualization (SEV) active"; then
        ok "dmesg 显示：SEV active（来宾已启用 SEV 内存加密）"
        G_DMESG=1
    else
        info "未在 dmesg 中找到显式的 'SEV active' 日志（不一定代表失败）"
    fi

    # 2) sysfs：SME/SEV 状态（SEV 来宾通常同时报告 SME active=1 且 sev=1）
    SME_ACTIVE="$(read_sysfs /sys/devices/system/cpu/sme/active)"
    SME_SEV="$(read_sysfs /sys/devices/system/cpu/sme/sev)"
    if [ "x$SME_ACTIVE" = "x1" ] && [ "x$SME_SEV" = "x1" ]; then
        ok "/sys/devices/system/cpu/sme/{active,sev} = 1（判定为 SEV 来宾）"
        G_SEV=1
    elif [ "x$SME_ACTIVE" = "x1" ] && [ -n "$SME_SEV" ]; then
        info "SME active=1，但 sev=${SME_SEV}（可能为 SME 或不同内核暴露方式）"
    else
        info "未检测到 SME/SEV sysfs 明确信息（某些发行版未暴露）"
    fi

    # 3) 处于虚拟化环境且 Hypervisor 为 KVM（硬件加速）
    HV_OK=0
    if has_cmd lscpu; then
        if lscpu 2>/dev/null | grep -i "Hypervisor vendor" | grep -iq "KVM"; then
            ok "lscpu：Hypervisor vendor = KVM"
            HV_OK=1
        fi
    fi
    if [ $HV_OK -eq 0 ]; then
        if flag_in_cpuinfo hypervisor; then
            ok "/proc/cpuinfo 含 hypervisor 标志（在虚拟化环境中）"
            HV_OK=1
        else
            info "无法从 lscpu/cpuinfo 明确识别 Hypervisor（可能工具缺失/受限）"
        fi
    fi
    [ $HV_OK -eq 1 ] && G_KVM=1

    # 4) 可选：CPU flags 中含 sev（仅作参考，不同内核/虚拟化层可能不暴露）
    if flag_in_cpuinfo sev; then
        ok "CPU flags 含 sev（参考指示）"
    fi

    say ""
    if [ $G_SEV -eq 1 ] && [ $G_KVM -eq 1 ]; then
        ok "结论：当前来宾 **很可能** 为已启用 **SEV(v1) + KVM 硬件虚拟化加速** 的机密虚拟机"
        return 0
    fi
    if [ $G_DMESG -eq 1 ] && [ $G_KVM -eq 1 ]; then
        ok "结论：dmesg 显示 SEV active 且运行在 KVM 上，基本可确认为 **SEV(v1) 硬件虚拟化来宾**"
        return 0
    fi
    bad "结论：尚不足以确认为 SEV(v1) 硬件虚拟化来宾（请核对内核/驱动/启动参数）"
    return 0
}

# -------- 宿主侧检查（Host）--------
check_host() {
    say "=== 宿主(Host)侧检测（SEV v1） ==="

    H_SVM=0; H_KVM=0; H_DEVKVM=0; H_SEV=0; H_QEMU=0

    # 1) CPU 支持 AMD 虚拟化（svm）
    if flag_in_cpuinfo svm; then
        ok "CPU flags 含 svm（支持 AMD-V）"
        H_SVM=1
    else
        bad "CPU 未暴露 svm 标志（可能 BIOS 未开 SVM/CPU 不支持）"
    fi

    # 2) /dev/kvm 存在（KVM 设备）
    if [ -e /dev/kvm ]; then
        ok "/dev/kvm 存在（KVM 设备可用）"
        H_DEVKVM=1
    else
        bad "未检测到 /dev/kvm（KVM 模块可能未加载）"
    fi

    # 3) KVM/AMD 模块与 dmesg
    if lsmod_has kvm_amd || lsmod_has kvm; then
        ok "KVM 模块已加载（kvm_amd/kvm）"
        H_KVM=1
    else
        bad "KVM 模块未加载"
    fi

    # 4) SEV 能力是否启用（多重信号综合判断）
    # 4.1 kvm_amd 参数：/sys/module/kvm_amd/parameters/sev == Y/1 表示启用
    SEV_PARAM="$(read_sysfs /sys/module/kvm_amd/parameters/sev)"
    if [ "x$SEV_PARAM" = "xY" ] || [ "x$SEV_PARAM" = "x1" ]; then
        ok "kvm_amd 参数 sev=${SEV_PARAM}（SEV 能力启用）"
        H_SEV=1
    fi
    # 4.2 dmesg 中的 SEV 提示
    if dmesg_has "SEV" || dmesg_has "Secure Encrypted Virtualization"; then
        ok "内核日志包含 SEV 相关信息（平台可能支持/已启用 SEV）"
        H_SEV=1
    fi

    # 5) 是否有以 SEV 模式运行的 qemu
    # 典型参数（旧）：-object sev-guest,id=sev0,... 与 -machine ...,memory-encryption=sev0
    # 新式（部分发行版）：-machine ...,confidential-guest-support=sev0
    if qemu_cmdline_has "-object sev-guest" || \
       qemu_cmdline_has "memory-encryption=sev" || \
       qemu_cmdline_has "confidential-guest-support=sev"; then
        ok "检测到带 SEV 参数的 QEMU 进程（当前正在运行 SEV 来宾）"
        H_QEMU=1
    else
        info "未发现带 SEV 参数的 QEMU 进程（可能当前未运行 SEV 来宾）"
    fi

    say ""
    if [ $H_SVM -eq 1 ] && [ $H_DEVKVM -eq 1 ] && [ $H_KVM -eq 1 ]; then
        ok "结论：宿主具备 **KVM 硬件虚拟化** 基本条件"
        if [ $H_SEV -eq 1 ]; then
            ok "宿主 **SEV 能力** 基本就绪（参数/日志显示已启用或可用）"
        else
            info "未能明确确认 SEV 启用（检查 BIOS 的 SEV/SME/PSP、内核版本与微码）"
        fi
        if [ $H_QEMU -eq 1 ]; then
            ok "当前已在运行至少一个 **SEV 来宾**"
        fi
        return 0
    fi

    bad "结论：宿主尚未满足 KVM/SEV 的全部前置条件（见上方失败项）"
    return 0
}

# -------- 模式选择 --------
MODE="auto"
[ $# -gt 0 ] && MODE="$1"

case "$MODE" in
    --host)
        check_host
        ;;
    --guest)
        check_guest
        ;;
    ""|--auto|auto)
        # 自动判定：若能看到 SME/SEV 来宾特征，则按来宾；否则优先宿主
        if [ -r /sys/devices/system/cpu/sme/active ] || dmesg_has "SEV active"; then
            info "自动判定：检测到 SME/SEV 线索，按【来宾】模式执行"
            check_guest
        else
            if [ -e /dev/kvm ] || qemu_cmdline_has "qemu"; then
                info "自动判定：检测到 /dev/kvm 或 qemu 进程，按【宿主】模式执行"
                check_host
            else
                info "自动判定：环境不明确，默认按【宿主】模式执行"
                check_host
            fi
        fi
        ;;
    *)
        say "用法: sh $0 [--auto|--host|--guest]"
        exit 1
        ;;
esac

exit 0
