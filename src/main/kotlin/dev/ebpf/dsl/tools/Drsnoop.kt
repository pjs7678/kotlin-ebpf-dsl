package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * drsnoop — Track direct memory reclaim events per cgroup.
 *
 * Inspired by BCC's drsnoop. Counts direct reclaim begin/end events and
 * measures reclaim latency per cgroup. Direct reclaim is the synchronous
 * path where a process must wait for pages to be freed — high counts
 * indicate memory pressure causing application stalls.
 *
 * Tracepoints:
 *   - mm/mm_vmscan_direct_reclaim_begin — reclaim started
 *   - mm/mm_vmscan_direct_reclaim_end   — reclaim finished
 *
 * Maps:
 *   - reclaim_start: HASH (u64 pid_tgid -> u64 timestamp)
 *   - reclaim_stats: LRU_HASH (cgroup_key -> reclaim_stats)
 *
 * Kernel: 4.7+ (cgroup_id, vmscan tracepoints)
 */

object ReclaimStats : BpfStruct("reclaim_stats") {
    val count by u64()
    val totalNs by u64()
}

fun drsnoop() = ebpf("drsnoop") {
    license("GPL")

    val reclaimStart by scalarHashMap(BpfScalar.U64, BpfScalar.U64, maxEntries = 10240)
    val reclaimStats by lruHashMap(CgroupKey, ReclaimStats, maxEntries = 10240)

    tracepoint("mm", "mm_vmscan_direct_reclaim_begin") {
        val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
        val ts = declareVar("ts", ktimeGetNs())
        reclaimStart.update(pidTgid, ts, flags = BPF_ANY)
        returnValue(literal(0, BpfScalar.S32))
    }

    tracepoint("mm", "mm_vmscan_direct_reclaim_end") {
        val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
        val entry = reclaimStart.lookup(pidTgid)
        ifNonNull(entry) { e ->
            val deltaNs = declareVar("delta_ns", ktimeGetNs() - e.deref())
            reclaimStart.delete(pidTgid)

            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
            val stats = reclaimStats.lookup(key)
            ifNonNull(stats) { s ->
                s[ReclaimStats.count].atomicAdd(literal(1u, BpfScalar.U64))
                s[ReclaimStats.totalNs].atomicAdd(deltaNs)
            }.elseThen {
                val newVal = stackVar(ReclaimStats) {
                    it[ReclaimStats.count] = literal(1u, BpfScalar.U64)
                    it[ReclaimStats.totalNs] = deltaNs
                }
                reclaimStats.update(key, newVal, flags = BPF_NOEXIST)
            }
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
