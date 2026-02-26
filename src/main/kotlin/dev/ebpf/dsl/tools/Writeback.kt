package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * writeback — Track dirty page writeback events per cgroup.
 *
 * Inspired by BCC's writeback tools. Counts writeback start and completion
 * events per cgroup. High writeback counts may indicate I/O-heavy pods
 * causing memory pressure via dirty page accumulation.
 *
 * Tracepoints:
 *   - writeback/writeback_start   — kernel begins flushing dirty pages
 *   - writeback/writeback_written — kernel finished writing back pages
 *
 * Map: wb_stats (LRU_HASH, cgroup_key -> wb_stats)
 *
 * Kernel: 4.7+ (cgroup_id), any architecture
 */

object WbStats : BpfStruct("wb_stats") {
    val starts by u64()
    val completions by u64()
}

fun writeback() = ebpf("writeback") {
    license("GPL")
    targetKernel("5.3")

    val wbStats by lruHashMap(CgroupKey, WbStats, maxEntries = 10240)

    tracepoint("writeback", "writeback_start") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = wbStats.lookup(key)
        ifNonNull(entry) { e ->
            e[WbStats.starts].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(WbStats) { it[WbStats.starts] = literal(1u, BpfScalar.U64) }
            wbStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    tracepoint("writeback", "writeback_written") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = wbStats.lookup(key)
        ifNonNull(entry) { e ->
            e[WbStats.completions].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(WbStats) { it[WbStats.completions] = literal(1u, BpfScalar.U64) }
            wbStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
