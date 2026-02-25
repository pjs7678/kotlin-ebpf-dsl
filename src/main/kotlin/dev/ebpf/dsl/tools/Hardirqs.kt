package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar

/**
 * hardirqs — Measure hardware interrupt handling latency per cgroup.
 *
 * Inspired by BCC's hardirqs. Records a histogram of time spent in
 * hardware interrupt handlers, attributed to the cgroup of the interrupted task.
 *
 * Tracepoints:
 *   - irq/irq_handler_entry — record start timestamp keyed by pid_tgid
 *   - irq/irq_handler_exit  — compute latency and update histogram
 *
 * Maps:
 *   - irq_start:   HASH (u64 pid_tgid -> u64 timestamp)
 *   - irq_latency: LRU_HASH (hist_key -> hist_value, 27-slot log2 histogram)
 *   - irq_count:   LRU_HASH (cgroup_key -> counter)
 *
 * Note: cgroup_id reflects the interrupted task's cgroup, which shows
 * which pods are experiencing interrupt overhead.
 *
 * Kernel: 5.8+ (BTF, cgroup_id), any architecture
 */
fun hardirqs() = ebpf("hardirqs") {
    license("GPL")
    preamble(LOG2_PREAMBLE)

    val irqStart by scalarHashMap(BpfScalar.U64, BpfScalar.U64, maxEntries = 10240)
    val irqLatency by lruHashMap(HistKey, HistValue, maxEntries = 10240)
    val irqCount by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    tracepoint("irq", "irq_handler_entry") {
        val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
        val ts = declareVar("ts", ktimeGetNs())
        irqStart.update(pidTgid, ts, flags = BPF_ANY)
        returnValue(literal(0, BpfScalar.S32))
    }

    tracepoint("irq", "irq_handler_exit") {
        val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
        val entry = irqStart.lookup(pidTgid)
        ifNonNull(entry) { e ->
            val varName = (e.expr as BpfExpr.VarRef).variable.name
            val deltaNs = declareVar("delta_ns", ktimeGetNs() - raw("*$varName", BpfScalar.U64))
            irqStart.delete(pidTgid)

            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

            // Count total interrupts
            val ckey = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
            val cnt = irqCount.lookup(ckey)
            ifNonNull(cnt) { c ->
                c[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
            }.elseThen {
                val newCnt = stackVar(Counter) { it[Counter.count] = literal(1u, BpfScalar.U64) }
                irqCount.update(ckey, newCnt, flags = BPF_NOEXIST)
            }

            // Update latency histogram
            val hkey = stackVar(HistKey) { it[HistKey.cgroupId] = cgroupId }
            val hval = irqLatency.lookup(hkey)
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
                irqLatency.update(hkey, newHval, flags = BPF_NOEXIST)
            }
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
