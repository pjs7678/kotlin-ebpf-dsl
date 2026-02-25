package dev.ebpf.dsl.samples

import dev.ebpf.dsl.api.*
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import dev.ebpf.dsl.validation.ValidationResult
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

/**
 * Sample programs demonstrating the Kotlin eBPF DSL.
 * Each test builds a real-world eBPF program, validates it,
 * generates C + Kotlin, and prints the output.
 */
class SampleProgramsTest {

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Sample 1: Process Lifecycle Tracker
    // Tracks process exec and exit events per cgroup
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    object ProcKey : BpfStruct("proc_key") {
        val cgroupId by u64()
    }

    object ProcStats : BpfStruct("proc_stats") {
        val execs by u64()
        val exits by u64()
        val forks by u64()
    }

    private fun buildProcessTracker() = ebpf("proc_track") {
        license("GPL")

        val procStats by lruHashMap(ProcKey, ProcStats, maxEntries = 4096)

        tracepoint("sched", "sched_process_exec") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(ProcKey) {
                it[ProcKey.cgroupId] = cgroupId
            }
            val entry = procStats.lookup(key)
            ifNonNull(entry) { e ->
                e[ProcStats.execs].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }

        tracepoint("sched", "sched_process_exit") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(ProcKey) {
                it[ProcKey.cgroupId] = cgroupId
            }
            val entry = procStats.lookup(key)
            ifNonNull(entry) { e ->
                e[ProcStats.exits].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }

        tracepoint("sched", "sched_process_fork") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(ProcKey) {
                it[ProcKey.cgroupId] = cgroupId
            }
            val entry = procStats.lookup(key)
            ifNonNull(entry) { e ->
                e[ProcStats.forks].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }
    }

    @Test
    fun `sample 1 - process lifecycle tracker`() {
        val program = buildProcessTracker()
        val result = program.validate()
        assertThat(result.errors).isEmpty()

        val c = program.generateC()
        println("═══ Sample 1: Process Lifecycle Tracker ═══")
        println(c)
        println()

        // Verify key structures
        assertThat(c).contains("struct proc_stats {")
        assertThat(c).contains("__u64 execs;")
        assertThat(c).contains("__u64 exits;")
        assertThat(c).contains("__u64 forks;")
        assertThat(c).contains("SEC(\"tp/sched/sched_process_exec\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_process_exit\")")
        assertThat(c).contains("SEC(\"tp/sched/sched_process_fork\")")
        assertThat(c).contains("__sync_fetch_and_add")
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Sample 2: File I/O Latency Histogram
    // Measures VFS read/write latency with per-cgroup histograms
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    object LatKey : BpfStruct("lat_key") {
        val cgroupId by u64()
    }

    object LatHist : BpfStruct("lat_hist") {
        val slots by array(BpfScalar.U64, 27)
        val count by u64()
        val sumNs by u64()
    }

    object TidTs : BpfStruct("tid_ts") {
        val timestamp by u64()
    }

    private fun buildFileIoLatency() = ebpf("file_io_lat") {
        license("GPL")

        val startTs by hashMap(LatKey, TidTs, maxEntries = 10240, mapName = "start_ts")
        val readLatency by lruHashMap(LatKey, LatHist, maxEntries = 4096, mapName = "read_lat")
        val writeLatency by lruHashMap(LatKey, LatHist, maxEntries = 4096, mapName = "write_lat")

        kprobe("vfs_read") {
            val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
            val ts = declareVar("ts", ktimeGetNs())
            returnValue(literal(0, BpfScalar.S32))
        }

        kretprobe("vfs_read") {
            val pidTgid = declareVar("pid_tgid", getCurrentPidTgid())
            val now = declareVar("now", ktimeGetNs())
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(LatKey) {
                it[LatKey.cgroupId] = cgroupId
            }
            val entry = readLatency.lookup(key)
            ifNonNull(entry) { e ->
                e[LatHist.count].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }

        kprobe("vfs_write") {
            val ts = declareVar("ts", ktimeGetNs())
            returnValue(literal(0, BpfScalar.S32))
        }

        kretprobe("vfs_write") {
            val now = declareVar("now", ktimeGetNs())
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(LatKey) {
                it[LatKey.cgroupId] = cgroupId
            }
            val entry = writeLatency.lookup(key)
            ifNonNull(entry) { e ->
                e[LatHist.count].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }
    }

    @Test
    fun `sample 2 - file IO latency histogram`() {
        val program = buildFileIoLatency()
        val result = program.validate()
        assertThat(result.errors).isEmpty()

        val c = program.generateC()
        println("═══ Sample 2: File I/O Latency Histogram ═══")
        println(c)
        println()

        assertThat(c).contains("__u64 slots[27];")
        assertThat(c).contains("SEC(\"kprobe/vfs_read\")")
        assertThat(c).contains("SEC(\"kretprobe/vfs_read\")")
        assertThat(c).contains("SEC(\"kprobe/vfs_write\")")
        assertThat(c).contains("SEC(\"kretprobe/vfs_write\")")
        assertThat(c).contains("struct pt_regs *ctx")

        // Check Kotlin reader
        val kt = program.generateKotlin("com.example.fileio")
        println("═══ Kotlin MapReader for File I/O ═══")
        println(kt)
        println()
        assertThat(kt).contains("object LatHistLayout")
        assertThat(kt).contains("const val SIZE = 232")
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Sample 3: DNS Query Snooper (XDP program)
    // A simple XDP program skeleton that shows non-tracing program types
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    object PktCount : BpfStruct("pkt_count") {
        val packets by u64()
        val bytes by u64()
    }

    private fun buildXdpCounter() = ebpf("xdp_counter") {
        license("GPL")

        val stats by percpuArray(PktCount, maxEntries = 1, mapName = "stats")

        xdp {
            // Simple packet counter using raw() for packet access
            val key = literal(0u, BpfScalar.U32)
            val len = declareVar("len", raw("(long)(ctx->data_end - ctx->data)", BpfScalar.U64))
            returnAction(XDP_PASS)
        }
    }

    @Test
    fun `sample 3 - XDP packet counter`() {
        val program = buildXdpCounter()
        val result = program.validate()
        assertThat(result.errors).isEmpty()

        val c = program.generateC()
        println("═══ Sample 3: XDP Packet Counter ═══")
        println(c)
        println()

        assertThat(c).contains("SEC(\"xdp\")")
        assertThat(c).contains("struct xdp_md *ctx")
        assertThat(c).contains("BPF_MAP_TYPE_PERCPU_ARRAY")
        assertThat(c).contains("return 2;") // XDP_PASS
        assertThat(c).contains("(long)(ctx->data_end - ctx->data)") // raw escape hatch
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Sample 4: OOM Kill Monitor (minimal — kpod-metrics style)
    // Shows the simplest possible useful eBPF program
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    object CgroupKey : BpfStruct("cgroup_key") {
        val cgroupId by u64()
    }

    object Counter : BpfStruct("counter") {
        val count by u64()
    }

    private fun buildOomMonitor() = ebpf("oom_mon") {
        license("GPL")

        val oomKills by lruHashMap(CgroupKey, Counter, maxEntries = 10240)

        tracepoint("oom", "mark_victim") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val key = stackVar(CgroupKey) {
                it[CgroupKey.cgroupId] = cgroupId
            }
            val entry = oomKills.lookup(key)
            ifNonNull(entry) { e ->
                e[Counter.count].atomicAdd(literal(1u, BpfScalar.U64))
            }
            returnValue(literal(0, BpfScalar.S32))
        }
    }

    @Test
    fun `sample 4 - OOM kill monitor (minimal)`() {
        val program = buildOomMonitor()
        val result = program.validate()
        assertThat(result.errors).isEmpty()

        val c = program.generateC()
        println("═══ Sample 4: OOM Kill Monitor (minimal) ═══")
        println(c)
        println()

        val kt = program.generateKotlin("com.example.oom")
        println("═══ Kotlin MapReader for OOM Monitor ═══")
        println(kt)
        println()
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Sample 5: Bounded Loop & Conditional Logic
    // Shows control flow features
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    object BucketKey : BpfStruct("bucket_key") {
        val cgroupId by u64()
    }

    object HistData : BpfStruct("hist_data") {
        val buckets by array(BpfScalar.U64, 16)
        val total by u64()
        val overflow by u64()
    }

    private fun buildControlFlowSample() = ebpf("ctrl_flow") {
        license("GPL")

        val hist by lruHashMap(BucketKey, HistData, maxEntries = 2048)

        tracepoint("sched", "sched_switch") {
            val cgroupId = declareVar("cgroup_id", getCurrentCgroupId())
            val ts = declareVar("ts", ktimeGetNs())

            // Conditional: only process if timestamp > 0
            ifThen(ts gt literal(0u, BpfScalar.U64)) {
                val key = stackVar(BucketKey) {
                    it[BucketKey.cgroupId] = cgroupId
                }
                val entry = hist.lookup(key)
                ifNonNull(entry) { e ->
                    e[HistData.total].atomicAdd(literal(1u, BpfScalar.U64))

                    // Bounded loop: iterate over buckets
                    boundedLoop(literal(16u, BpfScalar.U32)) { i ->
                        // loop body placeholder
                    }
                }
            }

            returnValue(literal(0, BpfScalar.S32))
        }
    }

    @Test
    fun `sample 5 - bounded loop and conditional logic`() {
        val program = buildControlFlowSample()
        val result = program.validate()
        assertThat(result.errors).isEmpty()

        val c = program.generateC()
        println("═══ Sample 5: Bounded Loop & Conditionals ═══")
        println(c)
        println()

        assertThat(c).contains("if (")
        assertThat(c).contains("#pragma unroll")
        assertThat(c).contains("for (")
        assertThat(c).contains("__u64 buckets[16];")
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Sample 6: Validation Error Demo
    // Shows what happens when validation catches errors
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    fun `sample 6 - validation catches XDP helper misuse`() {
        val program = ebpf("bad_xdp") {
            license("GPL")
            xdp {
                // ERROR: getCurrentCgroupId is not available in XDP programs
                val cg = declareVar("cg", getCurrentCgroupId())
                returnAction(XDP_PASS)
            }
        }
        val result = program.validate()

        println("═══ Sample 6: Validation Error Demo ═══")
        for (diag in result.diagnostics) {
            println("${diag.level} [${diag.code}]: ${diag.message}")
        }
        println()

        assertThat(result.errors).isNotEmpty()
        assertThat(result.errors[0].code).isEqualTo("helper-unavailable")
    }

    object HugeStruct : BpfStruct("huge") {
        val data by array(BpfScalar.U64, 60) // 480 bytes
    }

    @Test
    fun `sample 6b - validation catches stack overflow`() {
        val program = ebpf("stack_boom") {
            license("GPL")
            tracepoint("sched", "sched_switch") {
                val a = stackVar(HugeStruct) {}
                val b = stackVar(HugeStruct) {} // 480 + 480 = 960 > 512
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = program.validate()

        println("═══ Sample 6b: Stack Overflow Detection ═══")
        for (diag in result.diagnostics) {
            println("${diag.level} [${diag.code}]: ${diag.message}")
        }
        println()

        assertThat(result.errors).anyMatch { it.code == "stack-overflow" }
    }

    @Test
    fun `sample 6c - validation warns on anti-patterns`() {
        val program = ebpf("anti") {
            license("GPL")
            // WARNING: large HASH map without LRU
            val bigMap by hashMap(CgroupKey, Counter, maxEntries = 100000, mapName = "big_map")
            tracepoint("sched", "sched_switch") {
                val a = literal(100u, BpfScalar.U64)
                val b = declareVar("b", ktimeGetNs())
                // WARNING: division by unchecked variable
                val c = declareVar("c", a / b)
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = program.validate()

        println("═══ Sample 6c: Anti-Pattern Warnings ═══")
        for (diag in result.diagnostics) {
            println("${diag.level} [${diag.code}]: ${diag.message}")
        }
        println()

        assertThat(result.warnings).anyMatch { it.code == "prefer-lru-hash" }
        assertThat(result.warnings).anyMatch { it.code == "unchecked-divisor" }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Sample 7: Full emit() — write files to disk
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    @Test
    fun `sample 7 - emit generates files on disk`(@TempDir dir: Path) {
        val program = buildOomMonitor()
        program.validate().throwOnError()
        program.emit(
            OutputConfig(
                cDir = dir.resolve("bpf").toString(),
                kotlinDir = dir.resolve("kotlin").toString(),
                kotlinPackage = "com.example.oom",
            )
        )

        val cFile = dir.resolve("bpf/oom_mon.bpf.c")
        val ktFile = dir.resolve("kotlin/com/example/oom/OomMonMapReader.kt")

        assertThat(cFile).exists()
        assertThat(ktFile).exists()

        println("═══ Sample 7: Generated Files ═══")
        println("C file: $cFile (${java.nio.file.Files.size(cFile)} bytes)")
        println("Kotlin file: $ktFile (${java.nio.file.Files.size(ktFile)} bytes)")
        println()
        println("── C Output ──")
        println(java.nio.file.Files.readString(cFile))
        println()
        println("── Kotlin Output ──")
        println(java.nio.file.Files.readString(ktFile))
    }
}
