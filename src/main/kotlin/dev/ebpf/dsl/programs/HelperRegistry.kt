package dev.ebpf.dsl.programs

import dev.ebpf.dsl.kernel.KernelVersion
import dev.ebpf.dsl.types.BpfScalar
import kotlin.reflect.KClass

object HelperRegistry {

    private val helpers = mutableMapOf<String, BpfHelper>()
    private val helpersById = mutableMapOf<Int, BpfHelper>()

    private val TRACING: Set<KClass<out ProgramType>> = setOf(
        ProgramType.Tracepoint::class,
        ProgramType.RawTracepoint::class,
        ProgramType.Kprobe::class,
        ProgramType.Kretprobe::class,
        ProgramType.Fentry::class,
        ProgramType.Fexit::class,
        ProgramType.Lsm::class,
    )

    private val NETWORKING: Set<KClass<out ProgramType>> = setOf(
        ProgramType.Xdp::class,
        ProgramType.TcClassifier::class,
        ProgramType.CgroupSkb::class,
        ProgramType.SocketFilter::class,
        ProgramType.SockOps::class,
    )

    init {
        // ── Universal helpers (available everywhere) ──────────────────────
        register(BpfHelper(
            id = 1, name = "bpf_map_lookup_elem",
            returnType = BpfScalar.U64, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
        ))
        register(BpfHelper(
            id = 2, name = "bpf_map_update_elem",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
        ))
        register(BpfHelper(
            id = 3, name = "bpf_map_delete_elem",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
        ))
        register(BpfHelper(
            id = 5, name = "bpf_ktime_get_ns",
            returnType = BpfScalar.U64, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
        ))
        register(BpfHelper(
            id = 6, name = "bpf_trace_printk",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
        ))
        register(BpfHelper(
            id = 8, name = "bpf_get_smp_processor_id",
            returnType = BpfScalar.U32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
        ))
        register(BpfHelper(
            id = 12, name = "bpf_tail_call",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
        ))

        // ── Legacy tracing helper (pre-5.5 fallback) ────────────────────
        register(BpfHelper(
            id = 4, name = "bpf_probe_read",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = true, availableIn = TRACING,
        ))

        // ── Tracing-only helpers ──────────────────────────────────────────
        register(BpfHelper(
            id = 14, name = "bpf_get_current_pid_tgid",
            returnType = BpfScalar.U64, paramTypes = emptyList(),
            gplOnly = false, availableIn = TRACING,
        ))
        register(BpfHelper(
            id = 15, name = "bpf_get_current_uid_gid",
            returnType = BpfScalar.U64, paramTypes = emptyList(),
            gplOnly = false, availableIn = TRACING,
        ))
        register(BpfHelper(
            id = 16, name = "bpf_get_current_comm",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = TRACING,
        ))
        register(BpfHelper(
            id = 80, name = "bpf_get_current_cgroup_id",
            returnType = BpfScalar.U64, paramTypes = emptyList(),
            gplOnly = false, availableIn = TRACING,
            minKernel = KernelVersion.V5_3,
        ))
        register(BpfHelper(
            id = 35, name = "bpf_get_current_task",
            returnType = BpfScalar.U64, paramTypes = emptyList(),
            gplOnly = false, availableIn = TRACING,
        ))
        register(BpfHelper(
            id = 158, name = "bpf_get_current_task_btf",
            returnType = BpfScalar.U64, paramTypes = emptyList(),
            gplOnly = true, availableIn = TRACING,
            minKernel = KernelVersion.V5_10,
        ))
        register(BpfHelper(
            id = 113, name = "bpf_probe_read_kernel",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = true, availableIn = TRACING,
            minKernel = KernelVersion.V5_5,
        ))
        register(BpfHelper(
            id = 112, name = "bpf_probe_read_user",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = true, availableIn = TRACING,
            minKernel = KernelVersion.V5_5,
        ))
        register(BpfHelper(
            id = 67, name = "bpf_get_stack",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = TRACING,
        ))
        register(BpfHelper(
            id = 27, name = "bpf_get_stackid",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = TRACING,
        ))
        register(BpfHelper(
            id = 109, name = "bpf_send_signal",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = TRACING,
            minKernel = KernelVersion.V5_3,
        ))

        // ── Networking helpers ────────────────────────────────────────────
        register(BpfHelper(
            id = 44, name = "bpf_xdp_adjust_head",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = setOf(ProgramType.Xdp::class),
        ))
        register(BpfHelper(
            id = 65, name = "bpf_xdp_adjust_tail",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = setOf(ProgramType.Xdp::class),
        ))
        register(BpfHelper(
            id = 23, name = "bpf_redirect",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = setOf(ProgramType.Xdp::class, ProgramType.TcClassifier::class),
        ))
        register(BpfHelper(
            id = 26, name = "bpf_skb_load_bytes",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = setOf(
                ProgramType.TcClassifier::class,
                ProgramType.CgroupSkb::class,
                ProgramType.SocketFilter::class,
            ),
        ))
        register(BpfHelper(
            id = 9, name = "bpf_skb_store_bytes",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = setOf(ProgramType.TcClassifier::class),
        ))
        register(BpfHelper(
            id = 28, name = "bpf_csum_diff",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = NETWORKING,
        ))

        // ── Ring buffer helpers (universal, kernel 5.8+) ─────────────────
        register(BpfHelper(
            id = 130, name = "bpf_ringbuf_output",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
            minKernel = KernelVersion.V5_8,
        ))
        register(BpfHelper(
            id = 131, name = "bpf_ringbuf_reserve",
            returnType = BpfScalar.U64, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
            minKernel = KernelVersion.V5_8,
        ))
        register(BpfHelper(
            id = 132, name = "bpf_ringbuf_submit",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
            minKernel = KernelVersion.V5_8,
        ))
        register(BpfHelper(
            id = 133, name = "bpf_ringbuf_discard",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
            minKernel = KernelVersion.V5_8,
        ))

        // ── Perf helper (universal) ──────────────────────────────────────
        register(BpfHelper(
            id = 25, name = "bpf_perf_event_output",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
        ))

        // ── Spin lock helpers (universal, kernel 5.1+) ───────────────────
        register(BpfHelper(
            id = 93, name = "bpf_spin_lock",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
            minKernel = KernelVersion.V5_1,
        ))
        register(BpfHelper(
            id = 94, name = "bpf_spin_unlock",
            returnType = BpfScalar.S32, paramTypes = emptyList(),
            gplOnly = false, availableIn = emptySet(),
            minKernel = KernelVersion.V5_1,
        ))
    }

    private fun register(helper: BpfHelper) {
        require(helper.name !in helpers) { "Duplicate helper name: ${helper.name}" }
        require(helper.id !in helpersById) { "Duplicate helper id: ${helper.id}" }
        helpers[helper.name] = helper
        helpersById[helper.id] = helper
    }

    fun findByName(name: String): BpfHelper? = helpers[name]

    fun findById(id: Int): BpfHelper? = helpersById[id]

    fun all(): Collection<BpfHelper> = helpers.values
}
