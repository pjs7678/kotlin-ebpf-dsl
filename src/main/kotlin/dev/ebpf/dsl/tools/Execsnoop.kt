package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * execsnoop — Track process execution events per cgroup.
 *
 * Inspired by BCC's execsnoop. Counts process exec, exit, and fork events
 * per cgroup, useful for monitoring pod-level process activity in Kubernetes.
 *
 * Tracepoints:
 *   - sched/sched_process_exec — process called execve()
 *   - sched/sched_process_exit — process exited
 *   - sched/sched_process_fork — process forked
 *
 * Map: exec_stats (LRU_HASH, cgroup_key -> exec_stats)
 *
 * Kernel: 4.7+ (cgroup_id helper), any architecture
 */

object ExecStats : BpfStruct("exec_stats") {
    val execs by u64()
    val exits by u64()
    val forks by u64()
}

fun execsnoop() = ebpf("execsnoop") {
    license("GPL")

    val execStats by lruHashMap(CgroupKey, ExecStats, maxEntries = 10240)

    tracepoint("sched", "sched_process_exec") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = execStats.lookup(key)
        ifNonNull(entry) { e ->
            e[ExecStats.execs].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(ExecStats) {
                it[ExecStats.execs] = literal(1u, BpfScalar.U64)
            }
            execStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    tracepoint("sched", "sched_process_exit") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = execStats.lookup(key)
        ifNonNull(entry) { e ->
            e[ExecStats.exits].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(ExecStats) {
                it[ExecStats.exits] = literal(1u, BpfScalar.U64)
            }
            execStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    tracepoint("sched", "sched_process_fork") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = execStats.lookup(key)
        ifNonNull(entry) { e ->
            e[ExecStats.forks].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(ExecStats) {
                it[ExecStats.forks] = literal(1u, BpfScalar.U64)
            }
            execStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }
}
