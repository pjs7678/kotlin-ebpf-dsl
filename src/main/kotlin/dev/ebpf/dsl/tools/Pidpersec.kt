package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * pidpersec — Track new process creation rate per cgroup.
 *
 * Counts fork and exec events separately per cgroup. Unlike execsnoop
 * which also tracks exits, pidpersec focuses on creation rate — useful
 * for detecting fork bombs or pods with excessive process spawning.
 *
 * Tracepoints:
 *   - sched/sched_process_fork — new process forked
 *   - sched/sched_process_exec — new process exec'd
 *
 * Map: pid_stats (PERCPU_HASH, cgroup_key -> pid_stats)
 *
 * Uses PERCPU_HASH since fork/exec can be high-frequency during
 * fork bombs or batch job startup storms.
 *
 * Kernel: 4.7+ (cgroup_id), any architecture
 */

object PidStats : BpfStruct("pid_stats") {
    val forks by u64()
    val execs by u64()
}

fun pidpersec() = ebpf("pidpersec") {
    license("GPL")

    val pidStats by percpuHashMap(CgroupKey, PidStats, maxEntries = 10240)

    tracepoint("sched", "sched_process_fork") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = pidStats.lookup(key)
        ifNonNull(entry) { e ->
            e[PidStats.forks].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(PidStats) { it[PidStats.forks] = literal(1u, BpfScalar.U64) }
            pidStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    tracepoint("sched", "sched_process_exec") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
        val entry = pidStats.lookup(key)
        ifNonNull(entry) { e ->
            e[PidStats.execs].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(PidStats) { it[PidStats.execs] = literal(1u, BpfScalar.U64) }
            pidStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
