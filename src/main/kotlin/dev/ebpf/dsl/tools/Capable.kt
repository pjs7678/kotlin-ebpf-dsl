package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * capable — Count security capability checks per cgroup.
 *
 * Inspired by BCC's capable. Counts how often the kernel checks security
 * capabilities per cgroup. High counts may indicate a container is
 * performing privileged operations or hitting permission denials.
 *
 * Program:
 *   - kprobe/cap_capable — fires on every capability check
 *
 * Maps:
 *   - cap_stats: LRU_HASH (cgroup_key -> cap_stats)
 *
 * Fields tracked:
 *   - checks: total capability check calls
 *
 * Kernel: 4.7+ (cgroup_id), any architecture
 */

object CapStats : BpfStruct("cap_stats") {
    val checks by u64()
}

fun capable() = ebpf("capable") {
    license("GPL")

    val capStats by lruHashMap(CgroupKey, CapStats, maxEntries = 10240)

    kprobe("cap_capable") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = capStats.lookup(key)
        ifNonNull(entry) { e ->
            e[CapStats.checks].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(CapStats) { it[CapStats.checks] = literal(1u, BpfScalar.U64) }
            capStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
