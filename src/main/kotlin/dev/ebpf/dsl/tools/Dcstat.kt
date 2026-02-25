package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * dcstat — Track directory entry cache (dcache) statistics per cgroup.
 *
 * Inspired by BCC's dcstat. Counts dcache lookups and slow-path lookups
 * per cgroup. The ratio of slow/refs indicates dcache miss rate.
 *
 * Programs:
 *   - kprobe/lookup_fast — dcache lookup (fast path, includes hits)
 *   - kprobe/d_lookup    — dcache slow path lookup (miss in fast path)
 *
 * Map: dc_stats (LRU_HASH, cgroup_key -> dc_stats)
 *
 * Kernel: 4.7+ (cgroup_id), any architecture
 */

object DcStats : BpfStruct("dc_stats") {
    val refs by u64()
    val slow by u64()
}

fun dcstat() = ebpf("dcstat") {
    license("GPL")

    val dcStats by lruHashMap(CgroupKey, DcStats, maxEntries = 10240)

    kprobe("lookup_fast") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = dcStats.lookup(key)
        ifNonNull(entry) { e ->
            e[DcStats.refs].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(DcStats) { it[DcStats.refs] = literal(1u, BpfScalar.U64) }
            dcStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    kprobe("d_lookup") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = dcStats.lookup(key)
        ifNonNull(entry) { e ->
            e[DcStats.slow].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(DcStats) { it[DcStats.slow] = literal(1u, BpfScalar.U64) }
            dcStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
