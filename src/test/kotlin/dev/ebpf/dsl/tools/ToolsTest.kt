package dev.ebpf.dsl.tools

import dev.ebpf.dsl.api.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/**
 * Tests for all BCC-style tools.
 * Validates each program and verifies the generated C output.
 */
class ToolsTest {

    // ── execsnoop ────────────────────────────────────────────────────────

    @Test
    fun `execsnoop validates successfully`() {
        val result = execsnoop().validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `execsnoop generates expected C`() {
        val c = execsnoop().generateC()
        assertThat(c).contains("SEC(\"tp/sched/sched_process_exec\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_process_exit\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_process_fork\")")
        assertThat(c).contains("struct exec_stats")
        assertThat(c).contains("__u64 execs;")
        assertThat(c).contains("__u64 exits;")
        assertThat(c).contains("__u64 forks;")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
        assertThat(c).contains("bpf_get_current_cgroup_id()")
        assertThat(c).contains("__sync_fetch_and_add")
    }

    @Test
    fun `execsnoop generates Kotlin reader`() {
        val kt = execsnoop().generateKotlin("dev.ebpf.tools")
        assertThat(kt).contains("object ExecStatsLayout")
        assertThat(kt).contains("fun readExecStats(")
        assertThat(kt).contains("const val SIZE = 24") // 3 * 8
    }

    // ── oomkill ──────────────────────────────────────────────────────────

    @Test
    fun `oomkill validates successfully`() {
        val result = oomkill().validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `oomkill generates expected C`() {
        val c = oomkill().generateC()
        assertThat(c).contains("SEC(\"tp/oom/mark_victim\")")
        assertThat(c).contains("struct counter")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
        assertThat(c).contains("bpf_get_current_cgroup_id()")
    }

    // ── runqlat ──────────────────────────────────────────────────────────

    @Test
    fun `runqlat validates successfully`() {
        val result = runqlat().validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `runqlat generates expected C`() {
        val c = runqlat().generateC()
        assertThat(c).contains("SEC(\"tp/sched/sched_wakeup\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_switch\")")
        assertThat(c).contains("log2l(")
        assertThat(c).contains("__u64 slots[27]")
        assertThat(c).contains("struct hist_value")
        assertThat(c).contains("struct trace_event_raw_sched_wakeup_template")
        assertThat(c).contains("struct trace_event_raw_sched_switch")
    }

    @Test
    fun `runqlat has 3 maps`() {
        val c = runqlat().generateC()
        // wakeup_ts (scalar HASH), runq_latency (LRU_HASH), ctx_switches (LRU_HASH)
        assertThat(c.split("SEC(\".maps\")")).hasSize(4) // 3 maps + 1 original
    }

    // ── tcpconnect ───────────────────────────────────────────────────────

    @Test
    fun `tcpconnect validates successfully`() {
        val result = tcpconnect().validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `tcpconnect generates expected C`() {
        val c = tcpconnect().generateC()
        assertThat(c).contains("SEC(\"kprobe/tcp_sendmsg\")")
        assertThat(c).contains("SEC(\"kprobe/tcp_recvmsg\")")
        assertThat(c).contains("SEC(\"tp/tcp/tcp_retransmit_skb\")")
        assertThat(c).contains("SEC(\"tp/sock/inet_sock_set_state\")")
        assertThat(c).contains("SEC(\"tp/tcp/tcp_probe\")")
        assertThat(c).contains("struct tcp_stats")
        assertThat(c).contains("__u64 bytes_sent;")
        assertThat(c).contains("__u64 retransmits;")
        assertThat(c).contains("__u64 rtt_sum_us;")
        assertThat(c).contains("PT_REGS_PARM3(ctx)")
    }

    @Test
    fun `tcpconnect has 5 programs`() {
        val c = tcpconnect().generateC()
        val secs = Regex("SEC\\(\"(kprobe|tp)/").findAll(c).count()
        assertThat(secs).isEqualTo(5)
    }

    // ── vfsstat ──────────────────────────────────────────────────────────

    @Test
    fun `vfsstat validates successfully`() {
        val result = vfsstat().validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `vfsstat generates expected C`() {
        val c = vfsstat().generateC()
        assertThat(c).contains("SEC(\"kprobe/vfs_read\")")
        assertThat(c).contains("SEC(\"kprobe/vfs_write\")")
        assertThat(c).contains("SEC(\"kprobe/vfs_open\")")
        assertThat(c).contains("SEC(\"kprobe/vfs_fsync\")")
        assertThat(c).contains("struct vfs_stats")
        assertThat(c).contains("__u64 reads;")
        assertThat(c).contains("__u64 writes;")
        assertThat(c).contains("__u64 opens;")
        assertThat(c).contains("__u64 fsyncs;")
    }

    @Test
    fun `vfsstat generates Kotlin reader`() {
        val kt = vfsstat().generateKotlin("dev.ebpf.tools")
        assertThat(kt).contains("object VfsStatsLayout")
        assertThat(kt).contains("const val SIZE = 32") // 4 * 8
    }

    // ── biolatency ───────────────────────────────────────────────────────

    @Test
    fun `biolatency validates successfully`() {
        val result = biolatency().validate()
        assertThat(result.errors).isEmpty()
    }

    @Test
    fun `biolatency generates expected C`() {
        val c = biolatency().generateC()
        assertThat(c).contains("SEC(\"kprobe/blk_mq_start_request\")")
        assertThat(c).contains("SEC(\"kprobe/blk_mq_end_request\")")
        assertThat(c).contains("struct req_key")
        assertThat(c).contains("struct req_info")
        assertThat(c).contains("__u64 req_ptr;")
        assertThat(c).contains("__u64 start_ts;")
        assertThat(c).contains("PT_REGS_PARM1(ctx)")
        assertThat(c).contains("log2l(")
        assertThat(c).contains("__u64 slots[27]")
    }

    @Test
    fun `biolatency has 3 maps`() {
        val c = biolatency().generateC()
        // req_info (HASH), bio_latency (LRU_HASH), bio_count (LRU_HASH)
        assertThat(c.split("SEC(\".maps\")")).hasSize(4) // 3 maps + 1 original
    }

    // ── hardirqs ──────────────────────────────────────────────────────────

    @Test
    fun `hardirqs validates successfully`() {
        assertThat(hardirqs().validate().errors).isEmpty()
    }

    @Test
    fun `hardirqs generates expected C`() {
        val c = hardirqs().generateC()
        assertThat(c).contains("SEC(\"tp/irq/irq_handler_entry\")")
        assertThat(c).contains("SEC(\"tp/irq/irq_handler_exit\")")
        assertThat(c).contains("log2l(")
        assertThat(c).contains("__u64 slots[27]")
        assertThat(c).contains("bpf_get_current_pid_tgid()")
    }

    // ── softirqs ─────────────────────────────────────────────────────────

    @Test
    fun `softirqs validates successfully`() {
        assertThat(softirqs().validate().errors).isEmpty()
    }

    @Test
    fun `softirqs generates expected C`() {
        val c = softirqs().generateC()
        assertThat(c).contains("SEC(\"tp/irq/softirq_entry\")")
        assertThat(c).contains("SEC(\"tp/irq/softirq_exit\")")
        assertThat(c).contains("log2l(")
    }

    // ── cachestat ────────────────────────────────────────────────────────

    @Test
    fun `cachestat validates successfully`() {
        assertThat(cachestat().validate().errors).isEmpty()
    }

    @Test
    fun `cachestat generates expected C`() {
        val c = cachestat().generateC()
        assertThat(c).contains("SEC(\"kprobe/mark_page_accessed\")")
        assertThat(c).contains("SEC(\"kprobe/add_to_page_cache_lru\")")
        assertThat(c).contains("SEC(\"kprobe/account_page_dirtied\")")
        assertThat(c).contains("SEC(\"kprobe/mark_buffer_dirty\")")
        assertThat(c).contains("struct cache_stats")
        assertThat(c).contains("__u64 accesses;")
        assertThat(c).contains("__u64 dirtied;")
    }

    @Test
    fun `cachestat generates Kotlin reader`() {
        val kt = cachestat().generateKotlin("dev.ebpf.tools")
        assertThat(kt).contains("object CacheStatsLayout")
        assertThat(kt).contains("const val SIZE = 32") // 4 * 8
    }

    // ── cpudist ──────────────────────────────────────────────────────────

    @Test
    fun `cpudist validates successfully`() {
        assertThat(cpudist().validate().errors).isEmpty()
    }

    @Test
    fun `cpudist generates expected C`() {
        val c = cpudist().generateC()
        assertThat(c).contains("SEC(\"tp/sched/sched_switch\")")
        assertThat(c).contains("struct trace_event_raw_sched_switch")
        assertThat(c).contains("prev_pid")
        assertThat(c).contains("next_pid")
        assertThat(c).contains("log2l(")
        assertThat(c).contains("__u64 slots[27]")
    }

    // ── dcstat ───────────────────────────────────────────────────────────

    @Test
    fun `dcstat validates successfully`() {
        assertThat(dcstat().validate().errors).isEmpty()
    }

    @Test
    fun `dcstat generates expected C`() {
        val c = dcstat().generateC()
        assertThat(c).contains("SEC(\"kprobe/lookup_fast\")")
        assertThat(c).contains("SEC(\"kprobe/d_lookup\")")
        assertThat(c).contains("struct dc_stats")
        assertThat(c).contains("__u64 refs;")
        assertThat(c).contains("__u64 slow;")
    }

    // ── tcpdrop ──────────────────────────────────────────────────────────

    @Test
    fun `tcpdrop validates successfully`() {
        assertThat(tcpdrop().validate().errors).isEmpty()
    }

    @Test
    fun `tcpdrop generates expected C`() {
        val c = tcpdrop().generateC()
        assertThat(c).contains("SEC(\"kprobe/tcp_drop\")")
        assertThat(c).contains("struct counter")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
    }

    // ── tcplife ──────────────────────────────────────────────────────────

    @Test
    fun `tcplife validates successfully`() {
        assertThat(tcplife().validate().errors).isEmpty()
    }

    @Test
    fun `tcplife generates expected C`() {
        val c = tcplife().generateC()
        assertThat(c).contains("SEC(\"tp/sock/inet_sock_set_state\")")
        assertThat(c).contains("struct trace_event_raw_inet_sock_set_state")
        assertThat(c).contains("__sport")
        assertThat(c).contains("__dport")
        assertThat(c).contains("log2l(")
        assertThat(c).contains("__u64 slots[27]")
    }

    @Test
    fun `tcplife has 3 maps`() {
        val c = tcplife().generateC()
        // conn_start (scalar HASH), conn_life (LRU_HASH), conn_count (LRU_HASH)
        assertThat(c.split("SEC(\".maps\")")).hasSize(4)
    }

    // ── syscount ─────────────────────────────────────────────────────────

    @Test
    fun `syscount validates successfully`() {
        assertThat(syscount().validate().errors).isEmpty()
    }

    @Test
    fun `syscount generates expected C`() {
        val c = syscount().generateC()
        assertThat(c).contains("SEC(\"raw_tp/sys_enter\")")
        assertThat(c).contains("struct counter")
        assertThat(c).contains("BPF_MAP_TYPE_PERCPU_HASH")
        assertThat(c).contains("bpf_get_current_cgroup_id()")
    }

    // ── capable ──────────────────────────────────────────────────────────

    @Test
    fun `capable validates successfully`() {
        assertThat(capable().validate().errors).isEmpty()
    }

    @Test
    fun `capable generates expected C`() {
        val c = capable().generateC()
        assertThat(c).contains("SEC(\"kprobe/cap_capable\")")
        assertThat(c).contains("struct cap_stats")
        assertThat(c).contains("__u64 checks;")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
    }

    // ── filelife ─────────────────────────────────────────────────────────

    @Test
    fun `filelife validates successfully`() {
        assertThat(filelife().validate().errors).isEmpty()
    }

    @Test
    fun `filelife generates expected C`() {
        val c = filelife().generateC()
        assertThat(c).contains("SEC(\"kprobe/vfs_create\")")
        assertThat(c).contains("SEC(\"kprobe/vfs_unlink\")")
        assertThat(c).contains("struct file_stats")
        assertThat(c).contains("__u64 creates;")
        assertThat(c).contains("__u64 deletes;")
    }

    // ── slabtop ──────────────────────────────────────────────────────────

    @Test
    fun `slabtop validates successfully`() {
        assertThat(slabtop().validate().errors).isEmpty()
    }

    @Test
    fun `slabtop generates expected C`() {
        val c = slabtop().generateC()
        assertThat(c).contains("SEC(\"kprobe/kmem_cache_alloc\")")
        assertThat(c).contains("SEC(\"kprobe/kmem_cache_free\")")
        assertThat(c).contains("struct slab_stats")
        assertThat(c).contains("__u64 allocs;")
        assertThat(c).contains("__u64 frees;")
        assertThat(c).contains("BPF_MAP_TYPE_PERCPU_HASH")
    }

    // ── writeback ────────────────────────────────────────────────────────

    @Test
    fun `writeback validates successfully`() {
        assertThat(writeback().validate().errors).isEmpty()
    }

    @Test
    fun `writeback generates expected C`() {
        val c = writeback().generateC()
        assertThat(c).contains("SEC(\"tp/writeback/writeback_start\")")
        assertThat(c).contains("SEC(\"tp/writeback/writeback_written\")")
        assertThat(c).contains("struct wb_stats")
        assertThat(c).contains("__u64 starts;")
        assertThat(c).contains("__u64 completions;")
    }

    // ── bitesize ──────────────────────────────────────────────────────────

    @Test
    fun `bitesize validates successfully`() {
        assertThat(bitesize().validate().errors).isEmpty()
    }

    @Test
    fun `bitesize generates expected C`() {
        val c = bitesize().generateC()
        assertThat(c).contains("SEC(\"kprobe/blk_mq_start_request\")")
        assertThat(c).contains("__data_len")
        assertThat(c).contains("log2l(")
        assertThat(c).contains("__u64 slots[27]")
    }

    // ── drsnoop ──────────────────────────────────────────────────────────

    @Test
    fun `drsnoop validates successfully`() {
        assertThat(drsnoop().validate().errors).isEmpty()
    }

    @Test
    fun `drsnoop generates expected C`() {
        val c = drsnoop().generateC()
        assertThat(c).contains("SEC(\"tp/mm/mm_vmscan_direct_reclaim_begin\")")
        assertThat(c).contains("SEC(\"tp/mm/mm_vmscan_direct_reclaim_end\")")
        assertThat(c).contains("struct reclaim_stats")
        assertThat(c).contains("__u64 total_ns;")
    }

    // ── signalsnoop ──────────────────────────────────────────────────────

    @Test
    fun `signalsnoop validates successfully`() {
        assertThat(signalsnoop().validate().errors).isEmpty()
    }

    @Test
    fun `signalsnoop generates expected C`() {
        val c = signalsnoop().generateC()
        assertThat(c).contains("SEC(\"tp/signal/signal_deliver\")")
        assertThat(c).contains("struct counter")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
    }

    // ── solisten ─────────────────────────────────────────────────────────

    @Test
    fun `solisten validates successfully`() {
        assertThat(solisten().validate().errors).isEmpty()
    }

    @Test
    fun `solisten generates expected C`() {
        val c = solisten().generateC()
        assertThat(c).contains("SEC(\"kprobe/inet_listen\")")
        assertThat(c).contains("struct counter")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
    }

    // ── pidpersec ────────────────────────────────────────────────────────

    @Test
    fun `pidpersec validates successfully`() {
        assertThat(pidpersec().validate().errors).isEmpty()
    }

    @Test
    fun `pidpersec generates expected C`() {
        val c = pidpersec().generateC()
        assertThat(c).contains("SEC(\"tp/sched/sched_process_fork\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_process_exec\")")
        assertThat(c).contains("struct pid_stats")
        assertThat(c).contains("__u64 forks;")
        assertThat(c).contains("__u64 execs;")
        assertThat(c).contains("BPF_MAP_TYPE_PERCPU_HASH")
    }

    // ── tcpsynbl ─────────────────────────────────────────────────────────

    @Test
    fun `tcpsynbl validates successfully`() {
        assertThat(tcpsynbl().validate().errors).isEmpty()
    }

    @Test
    fun `tcpsynbl generates expected C`() {
        val c = tcpsynbl().generateC()
        assertThat(c).contains("SEC(\"kprobe/tcp_v4_syn_recv_sock\")")
        assertThat(c).contains("struct counter")
        assertThat(c).contains("BPF_MAP_TYPE_LRU_HASH")
    }

    // ── cross-tool ───────────────────────────────────────────────────────

    @Test
    fun `all tools generate valid C without errors`() {
        for (tool in ToolRegistry.all()) {
            val program = tool.build()
            val result = program.validate()
            assertThat(result.errors)
                .describedAs("${tool.name} should have no validation errors")
                .isEmpty()

            val c = program.generateC()
            assertThat(c)
                .describedAs("${tool.name} should generate non-empty C")
                .isNotBlank()
                .contains("SEC(\"license\")")
                .contains("SEC(\".maps\")")
        }
    }

    @Test
    fun `all tools generate valid Kotlin readers`() {
        for (tool in ToolRegistry.all()) {
            val program = tool.build()
            val kt = program.generateKotlin("dev.ebpf.tools")
            assertThat(kt)
                .describedAs("${tool.name} should generate non-empty Kotlin")
                .isNotBlank()
                .contains("MapReader")
                .contains("Layout")
        }
    }

    // ── ToolRegistry ──────────────────────────────────────────────────────

    @Test
    fun `registry contains all 24 tools`() {
        assertThat(ToolRegistry.all()).hasSize(24)
        assertThat(ToolRegistry.names()).containsExactly(
            "execsnoop", "oomkill", "runqlat", "tcpconnect",
            "vfsstat", "biolatency", "hardirqs", "softirqs",
            "cachestat", "cpudist", "dcstat", "tcpdrop",
            "tcplife", "syscount", "capable", "filelife",
            "slabtop", "writeback", "bitesize", "drsnoop",
            "signalsnoop", "solisten", "pidpersec", "tcpsynbl",
        )
    }

    @Test
    fun `registry byName returns correct tool`() {
        val tool = ToolRegistry.byName("biolatency")
        assertThat(tool).isNotNull
        assertThat(tool!!.description).contains("Block I/O")
        assertThat(tool.hookTypes).containsExactly("kprobe")

        val program = tool.build()
        assertThat(program.name).isEqualTo("biolatency")
    }

    @Test
    fun `registry byName returns null for unknown`() {
        assertThat(ToolRegistry.byName("nonexistent")).isNull()
    }

    @Test
    fun `registry byHookType filters correctly`() {
        val kprobeTools = ToolRegistry.byHookType("kprobe")
        assertThat(kprobeTools.map { it.name })
            .contains("vfsstat", "biolatency", "cachestat", "dcstat", "tcpdrop",
                "capable", "filelife", "slabtop", "bitesize", "solisten", "tcpsynbl")
            .doesNotContain("execsnoop", "oomkill")

        val tpTools = ToolRegistry.byHookType("tracepoint")
        assertThat(tpTools.map { it.name })
            .contains("execsnoop", "oomkill", "runqlat", "hardirqs", "softirqs",
                "cpudist", "tcplife", "writeback", "drsnoop", "signalsnoop", "pidpersec")

        val rawTpTools = ToolRegistry.byHookType("raw_tracepoint")
        assertThat(rawTpTools.map { it.name }).containsExactly("syscount")
    }

    @Test
    fun `registry tool names match program names`() {
        for (tool in ToolRegistry.all()) {
            val program = tool.build()
            assertThat(program.name)
                .describedAs("${tool.name} registry name should match program name")
                .isEqualTo(tool.name)
        }
    }

    @Test
    fun `every tool has a non-empty description`() {
        for (tool in ToolRegistry.all()) {
            assertThat(tool.description)
                .describedAs("${tool.name} should have a description")
                .isNotBlank()
        }
    }
}
