package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * solisten — Count socket listen events per cgroup.
 *
 * Inspired by BCC's solisten. Counts listen() calls per cgroup,
 * useful for tracking how many listening sockets each pod creates
 * (service port exposure, connection acceptance readiness).
 *
 * Program:
 *   - kprobe/inet_listen — fires when a socket enters LISTEN state
 *
 * Map: listen_count (LRU_HASH, cgroup_key -> counter)
 *
 * Kernel: 4.7+ (cgroup_id), any architecture
 */
fun solisten() = ebpf("solisten") {
    license("GPL")

    val listenCount by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    kprobe("inet_listen") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = listenCount.lookup(key)
        ifNonNull(entry) { e ->
            e[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(Counter) { it[Counter.count] = literal(1u, BpfScalar.U64) }
            listenCount.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
