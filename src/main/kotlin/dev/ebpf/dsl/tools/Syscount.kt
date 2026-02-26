package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar

/**
 * syscount — Count system calls per cgroup.
 *
 * Inspired by BCC's syscount. Counts the total number of system calls
 * per cgroup, useful for identifying noisy pods in Kubernetes.
 *
 * Raw tracepoint:
 *   - sys_enter — fires on every system call entry
 *
 * Map: syscall_count (PERCPU_HASH, cgroup_key -> counter)
 *
 * Uses PERCPU_HASH to avoid cross-CPU cache-line contention on this
 * extremely hot path (fires on every syscall). Userspace must sum
 * per-CPU values at read time.
 *
 * Kernel: 4.17+ (raw_tracepoint, cgroup_id)
 */
fun syscount() = ebpf("syscount") {
    license("GPL")
    targetKernel("5.3")

    val syscallCount by percpuHashMap(CgroupKey, Counter, maxEntries = 10240)

    rawTracepoint("sys_enter") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = syscallCount.lookup(key)
        ifNonNull(entry) { e ->
            e[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(Counter) { it[Counter.count] = literal(1u, BpfScalar.U64) }
            syscallCount.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
