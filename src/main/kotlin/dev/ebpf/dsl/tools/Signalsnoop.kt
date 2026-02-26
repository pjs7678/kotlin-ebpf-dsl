package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * signalsnoop — Count signal delivery events per cgroup.
 *
 * Inspired by BCC's killsnoop. Counts signals delivered to processes
 * per cgroup. Useful for detecting pods receiving SIGTERM/SIGKILL
 * (graceful/forced shutdown) or SIGSEGV/SIGABRT (crashes).
 *
 * Tracepoint:
 *   - signal/signal_deliver — fires when a signal is delivered to a process
 *
 * Map: signal_count (LRU_HASH, cgroup_key -> counter)
 *
 * Kernel: 4.7+ (cgroup_id, signal tracepoints)
 */
fun signalsnoop() = ebpf("signalsnoop") {
    license("GPL")

    val signalCount by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    tracepoint("signal", "signal_deliver") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = signalCount.lookup(key)
        ifNonNull(entry) { e ->
            e[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(Counter) { it[Counter.count] = literal(1u, BpfScalar.U64) }
            signalCount.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
