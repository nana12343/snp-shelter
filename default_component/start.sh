#!/bin/bash
set -euo pipefail

# 参数检查
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <ip_address> <memory_size>"
    exit 1
fi
ip_address=$1
memory_size=$2

# 清理旧文件
rm -f measurement.bin secret_* sev_* || true

# 杀死可能残留的进程
pidof qemu-system-x86_64 > /dev/null && kill -9 $(pidof qemu-system-x86_64) || true
pidof b_relay > /dev/null && kill -9 $(pidof b_relay) || true

# --- 导出 SEV PDH 并检查证书链 ---
sevctl export /tmp/sev.pdh
check_cert_chain "$ip_address"

# 必要文件检查（这里只需要 GODH 和 session）
for f in sev_godh.b64 sev_session.b64; do
    [ -f "$f" ] || { echo "Error: File $f not exist!"; exit 1; }
done

# QEMU 镜像检查
RAW=/mnt/fast/guest.raw
[ -f "$RAW" ] || { echo "ERR: $RAW not found (bind-mount 宿主机 /mnt/fast 到容器了吗？)"; exit 1; }

# 给 QEMU 锁内存权限
ulimit -l unlimited || true

# --- 启动 QEMU（暂停启动，便于 QMP 操作） ---

qemu-system-x86_64 \
  -enable-kvm \
  -cpu EPYC \
  -smp 4,sockets=1,cores=2,threads=2 \
  -m "$memory_size" \
  -object memory-backend-memfd,id=mem,size="$memory_size",share=on,prealloc=on \
  -numa node,memdev=mem \
  -overcommit mem-lock=on \
  -bios /usr/local/bin/OVMF.fd \
  -kernel /usr/local/bin/bzImage \
  -initrd /usr/local/bin/initrd.img \
  -append "root=/dev/ram rdinit=/init console=ttyS0,115200 clocksource=kvm-clock mitigations=off" \
  -nographic \
  -object sev-guest,id=sev0,cbitpos=47,reduced-phys-bits=1,policy=0x1,dh-cert-file=sev_godh.b64,session-file=sev_session.b64 \
  -machine confidential-guest-support=sev0 \
  -object iothread,id=ioth0 \
  -blockdev driver=file,filename=${RAW},aio=native,cache.direct=on,cache.no-flush=off,node-name=img0 \
  -device virtio-blk-pci,drive=img0,iothread=ioth0,queue-size=1024,num-queues=4 \
  -device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3 \
  -netdev bridge,id=net0,br=br0 \
  -device virtio-net-pci,netdev=net0 \
  -qmp unix:/tmp/qmp-sock,server,nowait \
  -S \
  > qemu.log 2>&1 &

sleep 2

# --- QMP 查询 measurement ---
for attempt in 1 2 3; do
    {
        echo '{"execute": "qmp_capabilities"}'
        echo '{"execute": "query-sev-launch-measure"}'
    } | socat - UNIX-CONNECT:/tmp/qmp-sock > measurement.bin

    grep -q '"data"' measurement.bin && break || sleep $((attempt * 5))
done

# --- 远程证明，生成 secret_header.b64 / secret_payload.b64 ---
remote_attestation "$ip_address"

# 等待 secret_* 生成
for i in {1..10}; do
  [ -f secret_header.b64 ] && [ -f secret_payload.b64 ] && break
  sleep 1
done
[ -f secret_header.b64 ] && [ -f secret_payload.b64 ] || { echo "Error: secret_* not exist after attestation!"; exit 1; }


# --- 注入 secret 并继续运行 ---
packet_header=$(<secret_header.b64)
secret=$(<secret_payload.b64)

command="{ \"execute\": \"sev-inject-launch-secret\", \"arguments\": { \"packet-header\": \"$packet_header\", \"secret\": \"$secret\" } }"

{
    echo '{ "execute": "qmp_capabilities" }'
    sleep 1
    echo "$command"
    sleep 1
    echo '{ "execute": "cont" }'
} | socat - UNIX-CONNECT:/tmp/qmp-sock
