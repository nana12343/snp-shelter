#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   sudo ./qemu_affinity.sh -p <QEMU_PID> --vcpu 8,9,10,11 --io 12 --main 7 --irq 13 [--qmp /tmp/qmp-sock] [--container <name>] [--tune-host]
#
# Notes:
# - 在宿主机运行；需要 root（设置 IRQ/affinity）。
# - --qmp 如果是容器内的路径，需配合 --container，让脚本用 docker exec 访问 QMP。
# - 只要能拿到 vCPU 的 TID，就能把“其余 QEMU 线程”一股脑绑到 --io 指定的核（含 iothread/main）。

QPID=""
VCPU_CPUS=""
IO_CPU=""
MAIN_CPU=""
IRQ_CPU=""
QMP_SOCK=""
CONTAINER=""
TUNE_HOST=0

die() { echo "ERR: $*" >&2; exit 1; }

need_root() {
  if [[ $(id -u) -ne 0 ]]; then die "run as root"; fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p|--pid)          QPID="$2"; shift 2;;
      --vcpu)            VCPU_CPUS="$2"; shift 2;;
      --io)              IO_CPU="$2"; shift 2;;
      --main)            MAIN_CPU="$2"; shift 2;;
      --irq)             IRQ_CPU="$2"; shift 2;;
      --qmp)             QMP_SOCK="$2"; shift 2;;
      --container)       CONTAINER="$2"; shift 2;;
      --tune-host)       TUNE_HOST=1; shift 1;;
      -h|--help)         grep -A200 "^# Usage" "$0"; exit 0;;
      *) die "unknown arg: $1";;
    esac
  done
  [[ -n "$QPID" ]] || die "missing --pid"
  [[ -n "$VCPU_CPUS" ]] || die "missing --vcpu <cpu_list>"
  [[ -n "$IO_CPU" ]]    || die "missing --io <cpu>"
  [[ -n "$MAIN_CPU" ]]  || die "missing --main <cpu>"
}

# ---- helpers ----
ps_threads() { ps -eLo pid,tid,psr,comm | awk -v p="$QPID" '$1==p{printf "%s %s %s %s\n",$1,$2,$3,$4}'; }
bind_one()   { local cpu="$1" tid="$2"; taskset -pc "$cpu" "$tid" >/dev/null; echo " bound TID $tid -> CPU $cpu"; }

# ---- get vCPU tids via QMP (preferred) ----
get_vcpu_tids_qmp() {
  [[ -n "$QMP_SOCK" ]] || return 1
  local out
  if [[ -n "$CONTAINER" ]]; then
    out=$(docker exec "$CONTAINER" bash -lc "printf '{\"execute\":\"qmp_capabilities\"}\n{\"execute\":\"query-cpus-fast\"}\n' | socat - UNIX-CONNECT:$QMP_SOCK" 2>/dev/null || true)
  else
    out=$(printf '{"execute":"qmp_capabilities"}\n{"execute":"query-cpus-fast"}\n' | socat - UNIX-CONNECT:"$QMP_SOCK" 2>/dev/null || true)
  fi
  grep -q '"return"' <<<"$out" || return 1
  # 提取 thread-id（就是 Linux TID）
  echo "$out" | sed -n 's/.*"thread-id":\s*\([0-9]\+\).*/\1/p' | sort -u
  return 0
}

# ---- fallback: get vCPU tids by thread name (needs debug-threads=on) ----
get_vcpu_tids_by_name() {
  ps -eLo pid,tid,comm | awk -v p="$QPID" '$1==p && $3 ~ /^CPU/{print $2}'
}

# ---- find other qemu tids (non-vcpu) ----
get_other_qemu_tids() {
  local all=$(ps -eLo pid,tid,comm | awk -v p="$QPID" '$1==p{print $2}')
  local v="$1"
  awk 'NR==FNR{vcpu[$1]=1;next} {if(!vcpu[$1]) print $1}' <(echo "$v") <(echo "$all") | sort -u
}

# ---- vhost/vsock kernel kthreads (bind to IO_CPU) ----
get_vhost_pids() {
  # vhost-<QPID> 命名的内核线程
  ps -eLo pid,tid,comm | awk -v tag="vhost-'$QPID'" '$3 ~ tag {print $1}' | sort -u
}

# ---- IRQ lines related to virtio/vhost/vsock ----
set_irq_affinity() {
  local cpu="$1"
  echo "Setting IRQ affinity to CPU $cpu for virtio/vhost/vsock..."
  # 取匹配的 IRQ 号（首列形如 "45:"）
  for irq in $(grep -iE 'virtio|vhost|vsock' /proc/interrupts | awk -F: '{print $1}'); do
    echo "$cpu" > /proc/irq/$irq/smp_affinity_list || true
    echo " irq $irq -> CPU $cpu"
  done
}

# ---- optional: host tuning ----
host_tune() {
  echo "Host tuning: governor=performance, THP=madvise, swappiness=1"
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g" 2>/dev/null || true; done
  echo madvise > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
  sysctl -w vm.swappiness=1 >/dev/null || true
}

main() {
  need_root
  parse_args "$@"

  echo "QEMU PID: $QPID"
  echo "Target CPUs: vCPU=[$VCPU_CPUS], IO=$IO_CPU, MAIN=$MAIN_CPU, IRQ=${IRQ_CPU:-skip}"
  echo "Collecting vCPU TIDs..."

  mapfile -t vcpu_tids < <(get_vcpu_tids_qmp || get_vcpu_tids_by_name || true)
  if [[ ${#vcpu_tids[@]} -eq 0 ]]; then
    echo "WARN: 未识别到 vCPU TID。请提供 --qmp 并确保 QEMU 使用 -name debug-threads=on" >&2
  else
    echo "vCPU TIDs: ${vcpu_tids[*]}"
  fi

  # 其他 QEMU 线程（含 iothread/main 等）
  other_tids=""
  if [[ ${#vcpu_tids[@]} -gt 0 ]]; then
    other_tids=$(get_other_qemu_tids "$(printf "%s\n" "${vcpu_tids[@]}")" || true)
  else
    other_tids=$(ps -eLo pid,tid,comm | awk -v p="$QPID" '$1==p{print $2}' | tail -n +2) # 全绑 IO_CPU（除主线程）
  fi

  echo "Binding vCPU threads..."
  # 轮询分配 vCPU → 指定 CPU 列表
  IFS=',' read -r -a vcpus <<< "$VCPU_CPUS"
  idx=0
  for tid in "${vcpu_tids[@]:-}"; do
    cpu="${vcpus[$((idx % ${#vcpus[@]}))]}"
    bind_one "$cpu" "$tid"
    idx=$((idx+1))
  done

  echo "Binding OTHER qemu threads (iothread/main etc.) -> CPU $IO_CPU ..."
  while read -r tid; do
    [[ -n "$tid" ]] && bind_one "$IO_CPU" "$tid"
  done <<< "$other_tids"

  echo "Binding QEMU main thread -> CPU $MAIN_CPU"
  bind_one "$MAIN_CPU" "$QPID"

  echo "Binding vhost/vsock kthreads (if any) -> CPU $IO_CPU"
  for kp in $(get_vhost_pids || true); do
    [[ -n "$kp" ]] && taskset -pc "$IO_CPU" "$kp" >/dev/null && echo " bound kthread $kp -> CPU $IO_CPU"
  done

  if [[ -n "${IRQ_CPU:-}" ]]; then
    set_irq_affinity "$IRQ_CPU"
  fi

  if [[ $TUNE_HOST -eq 1 ]]; then
    host_tune
  fi

  echo "Done. Verify with: ps -eLo pid,tid,psr,comm | grep $QPID"
}

main "$@"
