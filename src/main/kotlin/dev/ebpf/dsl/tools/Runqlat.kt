package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * runqlat — Measure CPU run queue latency per cgroup.
 *
 * Inspired by BCC's runqlat. Records per-cgroup histograms of the time
 * tasks spend waiting in the CPU run queue (scheduler latency).
 *
 * Tracepoints:
 *   - sched/sched_wakeup  — records wakeup timestamp per PID
 *   - sched/sched_switch  — computes latency and updates histogram
 *
 * Maps:
 *   - wakeup_ts:    HASH (u32 PID -> u64 timestamp)
 *   - runq_latency: LRU_HASH (hist_key -> hist_value, 27-slot log2 histogram)
 *   - ctx_switches: LRU_HASH (cgroup_key -> counter)
 *
 * Kernel: 5.8+ (BTF, cgroup_id), any architecture
 */
fun runqlat() = ebpf("runqlat") {
    license("GPL")
    targetKernel("5.3")
    preamble(LOG2_PREAMBLE)

    val wakeupTs by scalarHashMap(BpfScalar.U32, BpfScalar.U64, maxEntries = 10240)
    val runqLatency by lruHashMap(HistKey, HistValue, maxEntries = 10240)
    val ctxSwitches by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    // Record wakeup timestamp per PID
    tracepoint("sched", "sched_wakeup") {
        val pid = declareVar(
            "pid",
            tracepointField("trace_event_raw_sched_wakeup_template", "pid", BpfScalar.U32)
        )
        val ts = declareVar("ts", ktimeGetNs())
        wakeupTs.update(pid, ts, flags = BPF_ANY)
        returnValue(literal(0, BpfScalar.S32))
    }

    // Compute latency on context switch
    tracepoint("sched", "sched_switch") {
        val nextPid = declareVar(
            "next_pid",
            tracepointField("trace_event_raw_sched_switch", "next_pid", BpfScalar.U32)
        )
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

        // Count context switches
        val ckey = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val cval = ctxSwitches.lookup(ckey)
        ifNonNull(cval) { e ->
            e[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(Counter) {
                it[Counter.count] = literal(1u, BpfScalar.U64)
            }
            ctxSwitches.update(ckey, newVal, flags = BPF_NOEXIST)
        }

        // Look up wakeup timestamp for next_pid
        val tsp = wakeupTs.lookup(nextPid)
        ifNonNull(tsp) { e ->
            val deltaNs = declareVar("delta_ns", ktimeGetNs() - e.deref())
            wakeupTs.delete(nextPid)

            // Update run-queue latency histogram
            val hkey = stackVar(HistKey) {
                it[HistKey.cgroupId] = cgroupId
            }
            val hval = runqLatency.lookup(hkey)
            ifNonNull(hval) { he ->
                val slot = declareVar("slot", histSlot(deltaNs, 27))
                he[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
                he[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
                he[HistValue.sumNs].atomicAdd(deltaNs)
            }.elseThen {
                val slot2 = declareVar("slot2", histSlot(deltaNs, 27))
                val newHval = stackVar(HistValue) {
                    it[HistValue.count] = literal(1u, BpfScalar.U64)
                    it[HistValue.sumNs] = deltaNs
                }
                declareVar("_arr_set", structArraySet(newHval, HistValue.slots, slot2, literal(1uL, BpfScalar.U64)))
                runqLatency.update(hkey, newHval, flags = BPF_NOEXIST)
            }
        }

        returnValue(literal(0, BpfScalar.S32))
    }
}
