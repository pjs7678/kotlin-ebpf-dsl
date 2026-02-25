package dev.ebpf.dsl.e2e

import dev.ebpf.dsl.api.*
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Test

class NetworkProgramTest {
    object CounterKey : BpfStruct("counter_key") {
        val cgroupId by u64()
    }
    object TcpStats : BpfStruct("tcp_stats") {
        val bytesSent by u64()
        val bytesReceived by u64()
        val retransmits by u64()
        val connections by u64()
        val rttSumUs by u64()
        val rttCount by u64()
    }

    private fun buildNetProgram() = ebpf("net") {
        license("GPL")
        val tcpStatsMap by lruHashMap(CounterKey, TcpStats, maxEntries = 10240)

        kprobe("tcp_sendmsg") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(CounterKey) {
                it[CounterKey.cgroupId] = cgroupId
            }
            val entry = tcpStatsMap.lookup(key)
            ifNonNull(entry) { e ->
                e[TcpStats.bytesSent].atomicAdd(literal(100u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }

        kprobe("tcp_recvmsg") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            returnValue(literal(0, BpfScalar.S32))
        }

        tracepoint("tcp", "tcp_retransmit_skb") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            returnValue(literal(0, BpfScalar.S32))
        }
    }

    @Test
    fun `net program validates`() {
        assertThat(buildNetProgram().validate().errors).isEmpty()
    }

    @Test
    fun `generated C has multi-field struct`() {
        val c = buildNetProgram().generateC()
        assertThat(c).contains("__u64 bytes_sent;")
        assertThat(c).contains("__u64 bytes_received;")
        assertThat(c).contains("__u64 retransmits;")
        assertThat(c).contains("__u64 connections;")
        assertThat(c).contains("__u64 rtt_sum_us;")
        assertThat(c).contains("__u64 rtt_count;")
    }

    @Test
    fun `generated C has 3 programs`() {
        val c = buildNetProgram().generateC()
        assertThat(c).contains("SEC(\"kprobe/tcp_sendmsg\")")
        assertThat(c).contains("SEC(\"kprobe/tcp_recvmsg\")")
        assertThat(c).contains("SEC(\"tp/tcp/tcp_retransmit_skb\")")
    }

    @Test
    fun `generated Kotlin has TcpStats layout with 6 fields`() {
        val kt = buildNetProgram().generateKotlin("com.example.gen")
        assertThat(kt).contains("object TcpStatsLayout")
        assertThat(kt).contains("const val SIZE = 48") // 6 * 8
        assertThat(kt).contains("BYTES_SENT_OFFSET")
        assertThat(kt).contains("RTT_COUNT_OFFSET")
    }
}
