package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * tcpsynbl — Count TCP SYN backlog completions per cgroup.
 *
 * Inspired by BCC's tcpsynbl. Counts completed TCP handshakes (SYN→ESTABLISHED)
 * per cgroup by probing tcp_v4_syn_recv_sock. High counts indicate the pod
 * is receiving many new connections; drops here indicate SYN queue overflow.
 *
 * Program:
 *   - kprobe/tcp_v4_syn_recv_sock — fires when SYN handshake completes
 *
 * Map: syn_count (LRU_HASH, cgroup_key -> counter)
 *
 * Kernel: 4.7+ (cgroup_id), any architecture
 */
fun tcpsynbl() = ebpf("tcpsynbl") {
    license("GPL")
    targetKernel("5.3")

    val synCount by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    kprobe("tcp_v4_syn_recv_sock") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = synCount.lookup(key)
        ifNonNull(entry) { e ->
            e[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(Counter) { it[Counter.count] = literal(1u, BpfScalar.U64) }
            synCount.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
