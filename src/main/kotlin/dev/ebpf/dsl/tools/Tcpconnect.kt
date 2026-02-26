package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct

/**
 * tcpconnect — Track TCP connection stats per cgroup.
 *
 * Inspired by BCC's tcpconnect/tcplife/tcpretrans. Aggregates TCP traffic
 * metrics per cgroup: bytes sent/received, retransmits, connections, and RTT.
 *
 * Programs:
 *   - kprobe/tcp_sendmsg     — count bytes sent (3rd arg = size)
 *   - kprobe/tcp_recvmsg     — count bytes received (3rd arg = len)
 *   - tp/tcp/tcp_retransmit_skb  — count retransmissions
 *   - tp/sock/inet_sock_set_state — count new connections (state -> ESTABLISHED)
 *   - tp/tcp/tcp_probe       — track RTT with histogram
 *
 * Maps:
 *   - tcp_stats: LRU_HASH (cgroup_key -> tcp_stats)
 *   - rtt_hist:  LRU_HASH (hist_key -> hist_value, 27-slot log2 histogram)
 *
 * Kernel: 5.8+ (BTF, cgroup_id), any architecture
 */

object TcpStats : BpfStruct("tcp_stats") {
    val bytesSent by u64()
    val bytesReceived by u64()
    val retransmits by u64()
    val connections by u64()
    val rttSumUs by u64()
    val rttCount by u64()
}

fun tcpconnect() = ebpf("tcpconnect") {
    license("GPL")
    targetKernel("5.3")
    preamble(LOG2_PREAMBLE)

    val tcpStats by lruHashMap(CgroupKey, TcpStats, maxEntries = 10240)
    val rttHist by lruHashMap(HistKey, HistValue, maxEntries = 10240)

    // Track bytes sent
    kprobe("tcp_sendmsg") {
        val size = declareVar("size", kprobeParam(3, "size_t"))
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = tcpStats.lookup(key)
        ifNonNull(entry) { e ->
            e[TcpStats.bytesSent].atomicAdd(size)
        }.elseThen {
            val newVal = stackVar(TcpStats) {
                it[TcpStats.bytesSent] = size
            }
            tcpStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // Track bytes received
    kprobe("tcp_recvmsg") {
        val len = declareVar("len", kprobeParam(3, "size_t"))
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = tcpStats.lookup(key)
        ifNonNull(entry) { e ->
            e[TcpStats.bytesReceived].atomicAdd(len)
        }.elseThen {
            val newVal = stackVar(TcpStats) {
                it[TcpStats.bytesReceived] = len
            }
            tcpStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // Count retransmissions
    tracepoint("tcp", "tcp_retransmit_skb") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val entry = tcpStats.lookup(key)
        ifNonNull(entry) { e ->
            e[TcpStats.retransmits].atomicAdd(literal(1u, BpfScalar.U64))
        }.elseThen {
            val newVal = stackVar(TcpStats) {
                it[TcpStats.retransmits] = literal(1u, BpfScalar.U64)
            }
            tcpStats.update(key, newVal, flags = BPF_NOEXIST)
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // Count new TCP connections (state transition to ESTABLISHED)
    tracepoint("sock", "inet_sock_set_state") {
        val newstate = declareVar(
            "newstate",
            tracepointField("trace_event_raw_inet_sock_set_state", "newstate", BpfScalar.S32)
        )
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())

        ifThen(newstate eq literal(1, BpfScalar.S32)) { // TCP_ESTABLISHED
            val key = stackVar(CgroupKey) {
                it[CgroupKey.cgroupId] = cgroupId
            }
            val entry = tcpStats.lookup(key)
            ifNonNull(entry) { e ->
                e[TcpStats.connections].atomicAdd(literal(1u, BpfScalar.U64))
            }.elseThen {
                val newVal = stackVar(TcpStats) {
                    it[TcpStats.connections] = literal(1u, BpfScalar.U64)
                }
                tcpStats.update(key, newVal, flags = BPF_NOEXIST)
            }
        }
        returnValue(literal(0, BpfScalar.S32))
    }

    // Track RTT from tcp_probe
    tracepoint("tcp", "tcp_probe") {
        val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
        val srttUs = declareVar(
            "srtt_us",
            tracepointField("trace_event_raw_tcp_probe", "srtt", BpfScalar.U32)
        )

        // Update rtt_sum_us and rtt_count in tcp_stats
        val key = stackVar(CgroupKey) {
            it[CgroupKey.cgroupId] = cgroupId
        }
        val stats = tcpStats.lookup(key)
        ifNonNull(stats) { e ->
            e[TcpStats.rttSumUs].atomicAdd(srttUs)
            e[TcpStats.rttCount].atomicAdd(literal(1u, BpfScalar.U64))
        }

        // Update RTT histogram
        val rttNs = declareVar("rtt_ns", cTypeCast("__u64", srttUs, BpfScalar.U64) * literal(1000, BpfScalar.U64))
        val hkey = stackVar(HistKey) {
            it[HistKey.cgroupId] = cgroupId
        }
        val hval = rttHist.lookup(hkey)
        ifNonNull(hval) { he ->
            val slot = declareVar("slot", histSlot(rttNs, 27))
            he[HistValue.slots].at(slot).atomicAdd(literal(1u, BpfScalar.U64))
            he[HistValue.count].atomicAdd(literal(1u, BpfScalar.U64))
            he[HistValue.sumNs].atomicAdd(rttNs)
        }.elseThen {
            val slot2 = declareVar("slot2", histSlot(rttNs, 27))
            val newHval = stackVar(HistValue) {
                it[HistValue.count] = literal(1u, BpfScalar.U64)
                it[HistValue.sumNs] = rttNs
            }
            declareVar("_arr_set", structArraySet(newHval, HistValue.slots, slot2, literal(1uL, BpfScalar.U64)))
            rttHist.update(hkey, newHval, flags = BPF_NOEXIST)
        }

        returnValue(literal(0, BpfScalar.S32))
    }
}
