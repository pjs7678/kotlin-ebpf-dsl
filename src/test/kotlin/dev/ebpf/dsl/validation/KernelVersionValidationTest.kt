package dev.ebpf.dsl.validation

import dev.ebpf.dsl.api.BpfLicense
import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.api.validate
import dev.ebpf.dsl.kernel.KernelVersion
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class KernelVersionValidationTest {

    object Key : BpfStruct("key") { val id by u32() }
    object Val : BpfStruct("val") { val count by u64() }

    @Test
    fun `helper used below minKernel produces error`() {
        // bpf_get_current_cgroup_id requires kernel 5.3+
        val model = ebpf("test") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            tracepoint("sched", "sched_process_exec") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        assertThat(result.errors).isNotEmpty()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch {
            it.message.contains("bpf_get_current_cgroup_id") && it.message.contains("5.3")
        }
    }

    @Test
    fun `map type used below minKernel produces error`() {
        val model = ebpf("test") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            val rb by ringBuf(256 * 1024)
            tracepoint("sched", "sched_process_exec") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        assertThat(result.errors).isNotEmpty()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch { it.message.contains("RINGBUF") && it.message.contains("5.8") }
    }

    @Test
    fun `program type used below minKernel produces error`() {
        val model = ebpf("test") {
            license(BpfLicense.GPL)
            targetKernel("4.18")
            fentry("vfs_read") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        assertThat(result.errors).isNotEmpty()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch { it.message.contains("Fentry") && it.message.contains("5.5") }
    }

    @Test
    fun `everything at or above minKernel produces no kernel errors`() {
        val model = ebpf("test") {
            license(BpfLicense.GPL)
            targetKernel("5.15")
            val rb by ringBuf(256 * 1024)
            fentry("vfs_read") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `default targetKernel 5_15 allows all current features`() {
        val model = ebpf("test") {
            license(BpfLicense.GPL)
            val rb by ringBuf(256 * 1024)
            fentry("vfs_read") {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        assertThat(model.targetKernel).isEqualTo(KernelVersion.V5_15)
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).isEmpty()
    }

    @Test
    fun `probe_read_kernel below 5_5 produces error`() {
        val model = ebpf("test") {
            license(BpfLicense.GPL)
            targetKernel("5.2")
            kprobe("vfs_read") {
                val data = declareVar("data", probeReadKernel(getCurrentTask(), BpfScalar.U64))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch {
            it.message.contains("bpf_probe_read_kernel") && it.message.contains("5.5")
        }
    }

    @Test
    fun `lsm program below 5_7 produces error`() {
        val model = ebpf("test") {
            license(BpfLicense.GPL)
            targetKernel("5.5")
            lsm("bprm_check_security") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
        assertThat(kernelErrors).anyMatch { it.message.contains("Lsm") && it.message.contains("5.7") }
    }
}
