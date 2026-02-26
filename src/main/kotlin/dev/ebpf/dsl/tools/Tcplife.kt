package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.ir.BpfExpr
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * tcplife — Measure TCP connection duration per cgroup.
 *
 * Inspired by BCC's tcplife. Records per-cgroup histograms of TCP connection
 * lifetimes (time from ESTABLISHED to CLOSE) and connection counts.
 *
 * Tracepoint:
 *   - sock/inet_sock_set_state — fires on every TCP state transition
 *     - state -> ESTABLISHED (1): record start timestamp keyed by sport:dport
 *     - state -> CLOSE (7): compute connection duration, update histogram
 *
 * Maps:
 *   - conn_start:    HASH (u64 port_pair -> u64 timestamp)
 *   - conn_life:     LRU_HASH (hist_key -> hist_value, 27-slot log2 histogram)
 *   - conn_count:    LRU_HASH (cgroup_key -> counter)
 *
 * Note: Uses sport:dport pair as connection identifier. The port pair is
 * extracted from the tracepoint's __sport and __dport fields.
 *
 * Kernel: 5.8+ (BTF, cgroup_id, inet_sock_set_state tracepoint)
 */
fun tcplife() = ebpf("tcplife") {
    license("GPL")
    preamble(LOG2_PREAMBLE)

    val connStart by scalarHashMap(BpfScalar.U64, BpfScalar.U64, maxEntries = 10240)
    val connLife by lruHashMap(HistKey, HistValue, maxEntries = 10240)
    val connCount by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

    tracepoint("sock", "inet_sock_set_state") {
        val newstate = declareVar(
            "newstate",
            raw("((struct trace_event_raw_inet_sock_set_state *)ctx)->newstate", BpfScalar.S32)
        )
        val portPair = declareVar(
            "port_pair",
            raw(
                "((__u64)((struct trace_event_raw_inet_sock_set_state *)ctx)->__sport << 32) | " +
                    "(__u64)((struct trace_event_raw_inet_sock_set_state *)ctx)->__dport",
                BpfScalar.U64
            )
        )
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

        // TCP_ESTABLISHED = 1: record start time
        ifThen(newstate eq literal(1, BpfScalar.S32)) {
            val ts = declareVar("ts", ktimeGetNs())
            connStart.update(portPair, ts, flags = BPF_ANY)

            // Count connections
            val ckey = stackVar(CgroupKey) { it[CgroupKey.cgroupId] = cgroupId }
            val cnt = connCount.lookup(ckey)
            ifNonNull(cnt) { c ->
                c[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
            }.elseThen {
                val newCnt = stackVar(Counter) { it[Counter.count] = literal(1u, BpfScalar.U64) }
                connCount.update(ckey, newCnt, flags = BPF_NOEXIST)
            }
        }

        // TCP_CLOSE = 7: compute duration
        ifThen(newstate eq literal(7, BpfScalar.S32)) {
            val tsp = connStart.lookup(portPair)
            ifNonNull(tsp) { e ->
                val varName = (e.expr as BpfExpr.VarRef).variable.name
                val deltaNs = declareVar("delta_ns", ktimeGetNs() - raw("*$varName", BpfScalar.U64))
                connStart.delete(portPair)

                val hkey = stackVar(HistKey) { it[HistKey.cgroupId] = cgroupId }
                val hval = connLife.lookup(hkey)
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
                    connLife.update(hkey, newHval, flags = BPF_NOEXIST)
                }
            }
        }

        returnValue(literal(0, BpfScalar.S32))
    }
}
