package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * tcpdrop — Count TCP packet drops per cgroup.
 *
 * Inspired by BCC's tcpdrop. Counts TCP packets dropped by the kernel,
 * useful for detecting network congestion or misconfiguration per pod.
 *
 * Programs:
 *   - kprobe/tcp_drop — count TCP drops per cgroup
 *
 * Map: tcp_drops (LRU_HASH, cgroup_key -> counter)
 *
 * Kernel: 4.7+ (tcp_drop function, cgroup_id), any architecture
 */
fun tcpdrop() = ebpf("tcpdrop") {
    license("GPL")

    val tcpDrops by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    kprobe("tcp_drop") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = tcpDrops.lookup(key)
        ifNonNull(entry) { e ->
            e[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(Counter) { it[Counter.count] = literal(1u, BpfScalar.U64) }
            tcpDrops.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
