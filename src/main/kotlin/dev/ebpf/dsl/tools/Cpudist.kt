package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar

/**
 * cpudist — Measure on-CPU time distribution per cgroup.
 *
 * Inspired by BCC's cpudist. Records per-cgroup histograms of how long
 * tasks run on the CPU before being switched out.
 *
 * Tracepoint:
 *   - sched/sched_switch — at switch-out, compute the previous task's on-CPU time
 *
 * Maps:
 *   - oncpu_ts:    HASH (u32 PID -> u64 timestamp) — switch-in time per PID
 *   - cpu_dist:    LRU_HASH (hist_key -> hist_value, 27-slot log2 histogram)
 *
 * At each sched_switch:
 *   1. Look up prev_pid's switch-in time, compute on-CPU delta, update histogram
 *   2. Record next_pid's switch-in time
 *
 * Kernel: 5.8+ (BTF, cgroup_id), any architecture
 */
fun cpudist() = ebpf("cpudist") {
    license("GPL")
    preamble(LOG2_PREAMBLE)

    val oncpuTs by scalarHashMap(BpfScalar.U32, BpfScalar.U64, maxEntries = 10240)
    val cpuDist by lruHashMap(HistKey, HistValue, maxEntries = 10240)

    tracepoint("sched", "sched_switch") {
        val prevPid = declareVar(
            "prev_pid",
            raw("((struct trace_event_raw_sched_switch *)ctx)->prev_pid", BpfScalar.U32)
        )
        val nextPid = declareVar(
            "next_pid",
            raw("((struct trace_event_raw_sched_switch *)ctx)->next_pid", BpfScalar.U32)
        )
        val now = declareVar("now", ktimeGetNs())
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

        // Compute on-CPU time for the task being switched out
        val tsp = oncpuTs.lookup(prevPid)
        ifNonNull(tsp) { e ->
            val varName = (e.expr as BpfExpr.VarRef).variable.name
            val deltaNs = declareVar("delta_ns", now - raw("*$varName", BpfScalar.U64))
            oncpuTs.delete(prevPid)

            val hkey = stackVar(HistKey) { it[HistKey.cgroupId] = cgroupId }
            val hval = cpuDist.lookup(hkey)
            ifNonNull(hval) { he ->
                val slot = declareVar("slot", raw("log2l(delta_ns) >= MAX_SLOTS ? MAX_SLOTS - 1 : log2l(delta_ns)", BpfScalar.U32))
                he[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
                he[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
                he[HistValue.sumNs].atomicAdd(deltaNs)
            }.elseThen {
                val slot2 = declareVar("slot2", raw("log2l(delta_ns) >= MAX_SLOTS ? MAX_SLOTS - 1 : log2l(delta_ns)", BpfScalar.U32))
                val newHval = stackVar(HistValue) {
                    it[HistValue.count] = literal(1u, BpfScalar.U64)
                    it[HistValue.sumNs] = deltaNs
                }
                val newHvalName = (newHval.expr as BpfExpr.VarRef).variable.name
                declareVar("_arr_set", raw("($newHvalName.slots[slot2] = 1ULL, (__s32)0)", BpfScalar.S32))
                cpuDist.update(hkey, newHval, flags = BPF_NOEXIST)
            }
        }

        // Record switch-in time for the next task
        oncpuTs.update(nextPid, now, flags = BPF_ANY)

        returnValue(literal(0, BpfScalar.S32))
    }
}
