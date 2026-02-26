package dev.ebpf.dsl.kernel

import dev.ebpf.dsl.api.BpfLicense
import dev.ebpf.dsl.api.BpfProgramModel
import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import dev.ebpf.dsl.tools.ToolRegistry
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable
import java.io.File

/**
 * Generates C fixture files for e2e compilation testing.
 * Run with: E2E_OUTPUT_DIR=/tmp/ebpf-e2e ./gradlew test --tests "*.GenerateE2eFixtures"
 */
@EnabledIfEnvironmentVariable(named = "E2E_OUTPUT_DIR", matches = ".+")
class GenerateE2eFixtures {

    private val outputDir = File(System.getenv("E2E_OUTPUT_DIR") ?: "/tmp/ebpf-e2e")

    object K : BpfStruct("k") { val id by u32() }
    object V : BpfStruct("v") { val count by u64() }

    // ── Tools at their declared targetKernel (5.3) ──────────────────────

    @Test
    fun `generate all tools at declared targetKernel`() {
        val dir = File(outputDir, "tools-declared")
        dir.mkdirs()
        for (tool in ToolRegistry.all()) {
            val model = tool.build()
            val result = model.validate()
            assert(result.errors.isEmpty()) {
                "Tool ${tool.name} has validation errors: ${result.errors}"
            }
            File(dir, "${tool.name}.bpf.c").writeText(model.generateC())
        }
        println("Generated ${ToolRegistry.all().size} tools at declared targetKernel → $dir")
    }

    // ── Synthetic programs at each kernel boundary ──────────────────────

    @Test
    fun `generate programs for kernel 4_18`() {
        val dir = File(outputDir, "kernel-4.18")
        dir.mkdirs()

        // Basic kprobe with hash map — should work on 4.18
        val basic = ebpf("basic_kprobe") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            val m by hashMap(K, V, 1024)
            kprobe("vfs_read") {
                val pid = declareVar("pid", getCurrentPidTgid())
                val ts = declareVar("ts", ktimeGetNs())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, basic)

        // Tracepoint
        val tp = ebpf("basic_tracepoint") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            val m by lruHashMap(K, V, 10240)
            tracepoint("sched", "sched_process_exec") {
                val pid = declareVar("pid", getCurrentPidTgid())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, tp)

        // Kretprobe
        val kret = ebpf("basic_kretprobe") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            kretprobe("vfs_read") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, kret)

        // XDP
        val xdp = ebpf("basic_xdp") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            xdp {
                returnAction(XDP_PASS)
            }
        }
        writeAndValidate(dir, xdp)

        println("Generated 4 programs for kernel 4.18 → $dir")
    }

    @Test
    fun `generate programs for kernel 5_2`() {
        val dir = File(outputDir, "kernel-5.2")
        dir.mkdirs()

        // BTF boundary — should use vmlinux.h
        val btf = ebpf("btf_kprobe") {
            license(BpfLicense.GPL)
            targetKernel("5.2")
            val m by hashMap(K, V, 1024)
            kprobe("vfs_read") {
                val pid = declareVar("pid", getCurrentPidTgid())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, btf)
        println("Generated 1 program for kernel 5.2 → $dir")
    }

    @Test
    fun `generate programs for kernel 5_3`() {
        val dir = File(outputDir, "kernel-5.3")
        dir.mkdirs()

        // cgroup_id available
        val cg = ebpf("cgroup_tracing") {
            license(BpfLicense.GPL)
            targetKernel("5.3")
            val m by lruHashMap(K, V, 10240)
            tracepoint("sched", "sched_process_exec") {
                val pid = declareVar("pid", getCurrentPidTgid())
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, cg)
        println("Generated 1 program for kernel 5.3 → $dir")
    }

    @Test
    fun `generate programs for kernel 5_5`() {
        val dir = File(outputDir, "kernel-5.5")
        dir.mkdirs()

        val fentry = ebpf("fentry_fexit") {
            license(BpfLicense.GPL)
            targetKernel("5.5")
            val m by lruHashMap(K, V, 10240)
            fentry("vfs_read") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
            fexit("vfs_read") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, fentry)

        val prk = ebpf("probe_read_kernel") {
            license(BpfLicense.GPL)
            targetKernel("5.5")
            kprobe("vfs_read") {
                val data = declareVar("data", probeReadKernel(getCurrentTask(), BpfScalar.U64))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, prk)
        println("Generated 2 programs for kernel 5.5 → $dir")
    }

    @Test
    fun `generate programs for kernel 5_8`() {
        val dir = File(outputDir, "kernel-5.8")
        dir.mkdirs()

        val rb = ebpf("ringbuf_program") {
            license(BpfLicense.GPL)
            targetKernel("5.8")
            val rb by ringBuf(256 * 1024)
            val m by lruHashMap(K, V, 10240)
            tracepoint("sched", "sched_process_exec") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, rb)
        println("Generated 1 program for kernel 5.8 → $dir")
    }

    @Test
    fun `generate programs for kernel 5_10`() {
        val dir = File(outputDir, "kernel-5.10")
        dir.mkdirs()

        val btf_task = ebpf("task_btf") {
            license(BpfLicense.GPL)
            targetKernel("5.10")
            kprobe("vfs_read") {
                val task = declareVar("task", getCurrentTaskBtf())
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, btf_task)
        println("Generated 1 program for kernel 5.10 → $dir")
    }

    @Test
    fun `generate programs for kernel 5_15`() {
        val dir = File(outputDir, "kernel-5.15")
        dir.mkdirs()

        val all = ebpf("all_features") {
            license(BpfLicense.GPL)
            targetKernel("5.15")
            val rb by ringBuf(256 * 1024)
            val m by lruHashMap(K, V, 10240)
            fentry("vfs_read") {
                val cg = declareVar("cg", getCurrentCgroupId())
                val task = declareVar("task", getCurrentTaskBtf())
                val data = declareVar("data", probeReadKernel(getCurrentTask(), BpfScalar.U64))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        writeAndValidate(dir, all)
        println("Generated 1 program for kernel 5.15 → $dir")
    }

    private fun writeAndValidate(dir: File, model: BpfProgramModel) {
        val result = model.validate()
        assert(result.errors.filter { it.code == "kernel-version" }.isEmpty()) {
            "Kernel version errors for ${model.name}: ${result.errors}"
        }
        val c = model.generateC()
        File(dir, "${model.name}.bpf.c").writeText(c)
    }
}
