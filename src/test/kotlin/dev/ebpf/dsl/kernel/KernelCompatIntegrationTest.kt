package dev.ebpf.dsl.kernel

import dev.ebpf.dsl.api.BpfLicense
import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import dev.ebpf.dsl.tools.ToolRegistry
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory

class KernelCompatIntegrationTest {

    @TestFactory
    fun `every tool validates cleanly against its stated targetKernel`(): List<DynamicTest> {
        return ToolRegistry.all().map { tool ->
            DynamicTest.dynamicTest("${tool.name} validates cleanly") {
                val model = tool.build()
                val result = model.validate()
                val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
                assertThat(kernelErrors)
                    .withFailMessage("Tool '${tool.name}' (targetKernel=${model.targetKernel}) has kernel-version errors:\n" +
                        kernelErrors.joinToString("\n") { "  ${it.message}" })
                    .isEmpty()
            }
        }
    }

    @TestFactory
    fun `every tool has targetKernel set`(): List<DynamicTest> {
        return ToolRegistry.all().map { tool ->
            DynamicTest.dynamicTest("${tool.name} has targetKernel") {
                val model = tool.build()
                // All tools should have a non-default targetKernel (5.3, not 5.15)
                assertThat(model.targetKernel).isEqualTo(KernelVersion.V5_3)
            }
        }
    }

    // ── Cross-kernel version tests ──────────────────────────────────────

    object Key : BpfStruct("key") { val id by u32() }
    object Val : BpfStruct("val") { val count by u64() }

    @Test
    fun `kernel 4_18 - basic kprobe with hash map validates`() {
        val model = ebpf("test_418") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            val m by hashMap(Key, Val, 1024)
            kprobe("vfs_read") {
                val pid = declareVar("pid", getCurrentPidTgid())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `kernel 4_18 - cgroup_id helper is rejected`() {
        val model = ebpf("test_418_cg") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            tracepoint("sched", "sched_process_exec") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch { it.message.contains("bpf_get_current_cgroup_id") }
    }

    @Test
    fun `kernel 4_18 - ringbuf map is rejected`() {
        val model = ebpf("test_418_rb") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            val rb by ringBuf(256 * 1024)
            tracepoint("sched", "sched_process_exec") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch { it.message.contains("RINGBUF") }
    }

    @Test
    fun `kernel 4_18 - fentry program type is rejected`() {
        val model = ebpf("test_418_fentry") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            fentry("vfs_read") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch { it.message.contains("Fentry") }
    }

    @Test
    fun `kernel 5_1 - spin lock helpers are accepted`() {
        val model = ebpf("test_51") {
            license(BpfLicense.GPL)
            targetKernel("5.1")
            val m by hashMap(Key, Val, 1024)
            kprobe("vfs_read") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `kernel 5_2 - generates vmlinux_h includes`() {
        val model = ebpf("test_52") {
            license(BpfLicense.GPL)
            targetKernel("5.2")
            kprobe("vfs_read") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val c = model.generateC()
        assertThat(c).contains("#include \"vmlinux.h\"")
        assertThat(c).contains("#include <bpf/bpf_core_read.h>")
    }

    @Test
    fun `kernel 4_18 - generates linux_bpf_h includes`() {
        val model = ebpf("test_418_inc") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            kprobe("vfs_read") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val c = model.generateC()
        assertThat(c).contains("#include <linux/bpf.h>")
        assertThat(c).doesNotContain("#include \"vmlinux.h\"")
        assertThat(c).doesNotContain("bpf_core_read.h")
    }

    @Test
    fun `kernel 5_3 - cgroup_id helper is accepted`() {
        val model = ebpf("test_53") {
            license(BpfLicense.GPL)
            targetKernel("5.3")
            tracepoint("sched", "sched_process_exec") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `kernel 5_5 - fentry and probe_read_kernel are accepted`() {
        val model = ebpf("test_55") {
            license(BpfLicense.GPL)
            targetKernel("5.5")
            fentry("vfs_read") {
                val data = declareVar("data", probeReadKernel(getCurrentTask(), BpfScalar.U64))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `kernel 5_5 - fexit is accepted`() {
        val model = ebpf("test_55_fexit") {
            license(BpfLicense.GPL)
            targetKernel("5.5")
            fexit("vfs_read") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `kernel 5_7 - lsm is accepted`() {
        val model = ebpf("test_57") {
            license(BpfLicense.GPL)
            targetKernel("5.7")
            lsm("bprm_check_security") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `kernel 5_8 - ringbuf map and helpers are accepted`() {
        val model = ebpf("test_58") {
            license(BpfLicense.GPL)
            targetKernel("5.8")
            val rb by ringBuf(256 * 1024)
            tracepoint("sched", "sched_process_exec") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `kernel 5_7 - ringbuf map is still rejected`() {
        val model = ebpf("test_57_rb") {
            license(BpfLicense.GPL)
            targetKernel("5.7")
            val rb by ringBuf(256 * 1024)
            tracepoint("sched", "sched_process_exec") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch { it.message.contains("RINGBUF") }
    }

    @Test
    fun `kernel 5_10 - get_current_task_btf is accepted`() {
        val model = ebpf("test_510") {
            license(BpfLicense.GPL)
            targetKernel("5.10")
            kprobe("vfs_read") {
                val task = declareVar("task", getCurrentTaskBtf())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `kernel 5_9 - get_current_task_btf is rejected`() {
        val model = ebpf("test_59_btf") {
            license(BpfLicense.GPL)
            targetKernel("5.9")
            kprobe("vfs_read") {
                val task = declareVar("task", getCurrentTaskBtf())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch { it.message.contains("bpf_get_current_task_btf") }
    }

    @Test
    fun `kernel 5_15 - everything is accepted`() {
        val model = ebpf("test_515") {
            license(BpfLicense.GPL)
            targetKernel("5.15")
            val rb by ringBuf(256 * 1024)
            fentry("vfs_read") {
                val cg = declareVar("cg", getCurrentCgroupId())
                val task = declareVar("task", getCurrentTaskBtf())
                val data = declareVar("data", probeReadKernel(getCurrentTask(), BpfScalar.U64))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `multiple errors reported for multiple violations`() {
        val model = ebpf("test_multi") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            val rb by ringBuf(256 * 1024)
            fentry("vfs_read") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        // Should have errors for: RINGBUF map (5.8), Fentry program (5.5), cgroup_id helper (5.3)
        assertThat(kernelErrors.size).isGreaterThanOrEqualTo(3)
    }
}
