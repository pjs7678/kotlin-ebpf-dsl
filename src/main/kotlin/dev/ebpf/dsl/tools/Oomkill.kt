package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * oomkill — Track OOM kill events per cgroup.
 *
 * Inspired by BCC's oomkill. Counts OOM kill events per cgroup,
 * useful for detecting memory pressure in Kubernetes pods.
 *
 * Tracepoint:
 *   - oom/mark_victim — kernel selected a process for OOM killing
 *
 * Map: oom_kills (LRU_HASH, cgroup_key -> counter)
 *
 * Kernel: 4.7+ (cgroup_id helper), any architecture
 */
fun oomkill() = ebpf("oomkill") {
    license("GPL")

    val oomKills by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    tracepoint("oom", "mark_victim") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = oomKills.lookup(key)
        ifNonNull(entry) { e ->
            e[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(Counter) {
                it[Counter.count] = literal(1u, BpfScalar.U64)
            }
            oomKills.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
