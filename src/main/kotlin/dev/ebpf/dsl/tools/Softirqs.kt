package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * softirqs — Measure software interrupt handling latency per cgroup.
 *
 * Inspired by BCC's softirqs. Records a histogram of time spent in
 * software interrupt handlers, attributed to the cgroup of the current task.
 *
 * Tracepoints:
 *   - irq/softirq_entry — record start timestamp keyed by pid_tgid
 *   - irq/softirq_exit  — compute latency and update histogram
 *
 * Maps:
 *   - softirq_start:   HASH (u64 pid_tgid -> u64 timestamp)
 *   - softirq_latency: LRU_HASH (hist_key -> hist_value, 27-slot log2 histogram)
 *
 * Kernel: 5.8+ (BTF, cgroup_id), any architecture
 */
fun softirqs() = ebpf("softirqs") {
    license("GPL")
    preamble(LOG2_PREAMBLE)

    val softirqStart by scalarHashMap(BpfScalar.U64, BpfScalar.U64, maxEntries = 10240)
    val softirqLatency by lruHashMap(HistKey, HistValue, maxEntries = 10240)

    tracepoint("irq", "softirq_entry") {
        val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
        val ts = declareVar("ts", ktimeGetNs())
        softirqStart.update(pidTgid, ts, flags = BPF_ANY)
        returnValue(literal(0, BpfScalar.S32))
    }

    tracepoint("irq", "softirq_exit") {
        val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
        val entry = softirqStart.lookup(pidTgid)
        ifNonNull(entry) { e ->
            val deltaNs = declareVar("delta_ns", ktimeGetNs() - e.deref())
            softirqStart.delete(pidTgid)

            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val hkey = stackVar(HistKey) { it[HistKey.cgroupId] = cgroupId }
            val hval = softirqLatency.lookup(hkey)
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
                softirqLatency.update(hkey, newHval, flags = BPF_NOEXIST)
            }
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
