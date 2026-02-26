package dev.ebpf.dsl.kernel

import dev.ebpf.dsl.api.BpfLicense
import dev.ebpf.dsl.api.BpfProgramModel
import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import dev.ebpf.dsl.maps.MapType
import dev.ebpf.dsl.programs.HelperRegistry
import dev.ebpf.dsl.programs.ProgramType
import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import dev.ebpf.dsl.validation.SemanticAnalyzer
import dev.ebpf.dsl.validation.TypeChecker
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory

/**
 * Comprehensive boundary tests for every kernel version threshold.
 * For each feature (helper, map type, program type), tests:
 *   - Exactly at minKernel → ACCEPTED (no kernel-version error)
 *   - One minor version below minKernel → REJECTED (kernel-version error)
 */
class KernelBoundaryTest {

    object K : BpfStruct("k") { val id by u32() }
    object V : BpfStruct("v") { val count by u64() }

    // ── Helper: boundary tests via parameterized dynamic tests ──────────

    /**
     * Tests that each helper with a non-default minKernel is:
     *   - accepted at exactly its minKernel
     *   - rejected at one version below
     */
    @Nested
    inner class HelperBoundaryTests {

        @Test
        fun `cgroup_id accepted at 5_3`() {
            val model = ebpf("test") {
                license(BpfLicense.GPL)
                targetKernel("5.3")
                tracepoint("sched", "sched_switch") {
                    val cg = declareVar("cg", getCurrentCgroupId())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = TypeChecker(model).check()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `cgroup_id rejected at 5_2`() {
            val model = ebpf("test") {
                license(BpfLicense.GPL)
                targetKernel("5.2")
                tracepoint("sched", "sched_switch") {
                    val cg = declareVar("cg", getCurrentCgroupId())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = TypeChecker(model).check()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" })
                .anyMatch { it.message.contains("bpf_get_current_cgroup_id") }
        }

        @Test
        fun `probe_read_kernel accepted at 5_5`() {
            val model = ebpf("test") {
                license(BpfLicense.GPL)
                targetKernel("5.5")
                kprobe("vfs_read") {
                    val data = declareVar("data", probeReadKernel(getCurrentTask(), BpfScalar.U64))
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = TypeChecker(model).check()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `probe_read_kernel rejected at 5_4`() {
            val model = ebpf("test") {
                license(BpfLicense.GPL)
                targetKernel("5.4")
                kprobe("vfs_read") {
                    val data = declareVar("data", probeReadKernel(getCurrentTask(), BpfScalar.U64))
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = TypeChecker(model).check()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" })
                .anyMatch { it.message.contains("bpf_probe_read_kernel") }
        }

        @Test
        fun `get_current_task_btf accepted at 5_10`() {
            val model = ebpf("test") {
                license(BpfLicense.GPL)
                targetKernel("5.10")
                kprobe("vfs_read") {
                    val task = declareVar("task", getCurrentTaskBtf())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = TypeChecker(model).check()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `get_current_task_btf rejected at 5_9`() {
            val model = ebpf("test") {
                license(BpfLicense.GPL)
                targetKernel("5.9")
                kprobe("vfs_read") {
                    val task = declareVar("task", getCurrentTaskBtf())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = TypeChecker(model).check()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" })
                .anyMatch { it.message.contains("bpf_get_current_task_btf") }
        }

        @Test
        fun `baseline helpers accepted at 4_18`() {
            val model = ebpf("test") {
                license(BpfLicense.GPL)
                targetKernel("4.18")
                kprobe("vfs_read") {
                    val pid = declareVar("pid", getCurrentPidTgid())
                    val ts = declareVar("ts", ktimeGetNs())
                    val cpu = declareVar("cpu", smpProcessorId())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = TypeChecker(model).check()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `all non-default helpers have correct minKernel`() {
            val nonDefault = HelperRegistry.all().filter { it.minKernel > KernelVersion.V4_18 }
            // Should include: cgroup_id(5.3), send_signal(5.3), probe_read_kernel(5.5),
            //   probe_read_user(5.5), task_btf(5.10), ringbuf_*(5.8), spin_*(5.1)
            assertThat(nonDefault.map { it.name }).containsExactlyInAnyOrder(
                "bpf_get_current_cgroup_id",
                "bpf_send_signal",
                "bpf_probe_read_kernel",
                "bpf_probe_read_user",
                "bpf_get_current_task_btf",
                "bpf_ringbuf_output",
                "bpf_ringbuf_reserve",
                "bpf_ringbuf_submit",
                "bpf_ringbuf_discard",
                "bpf_spin_lock",
                "bpf_spin_unlock",
            )
        }
    }

    // ── Map type: boundary tests ────────────────────────────────────────

    @Nested
    inner class MapTypeBoundaryTests {

        @Test
        fun `ringbuf accepted at 5_8`() {
            val model = ebpf("test_rb") {
                license(BpfLicense.GPL)
                targetKernel("5.8")
                val rb by ringBuf(256 * 1024)
                kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `ringbuf rejected at 5_7`() {
            val model = ebpf("test_rb") {
                license(BpfLicense.GPL)
                targetKernel("5.7")
                val rb by ringBuf(256 * 1024)
                kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" })
                .anyMatch { it.message.contains("RINGBUF") }
        }

        @Test
        fun `hash map accepted at 4_18`() {
            val model = ebpf("test_hash") {
                license(BpfLicense.GPL)
                targetKernel("4.18")
                val m by hashMap(K, V, 1024)
                kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `lru_hash map accepted at 4_18`() {
            val model = ebpf("test_lru") {
                license(BpfLicense.GPL)
                targetKernel("4.18")
                val m by lruHashMap(K, V, 1024)
                kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `percpu_array accepted at 4_18`() {
            val model = ebpf("test_pa") {
                license(BpfLicense.GPL)
                targetKernel("4.18")
                val m by percpuArray(V, 256)
                kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `cgroup_storage minKernel is 4_19`() {
            // CGROUP_STORAGE not exposed via builder, but metadata is correct
            assertThat(MapType.CGROUP_STORAGE.minKernel).isEqualTo(KernelVersion(4, 19))
        }

        @Test
        fun `all baseline maps have 4_18 minKernel`() {
            val baseline = MapType.entries.filter {
                it != MapType.RINGBUF && it != MapType.CGROUP_STORAGE
            }
            for (mt in baseline) {
                assertThat(mt.minKernel)
                    .withFailMessage("${mt.name} should be 4.18 but is ${mt.minKernel}")
                    .isEqualTo(KernelVersion.V4_18)
            }
        }
    }

    // ── Program type: boundary tests ────────────────────────────────────

    @Nested
    inner class ProgramTypeBoundaryTests {

        @Test
        fun `fentry accepted at 5_5`() {
            val model = ebpf("test_fentry") {
                license(BpfLicense.GPL)
                targetKernel("5.5")
                fentry("vfs_read") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `fentry rejected at 5_4`() {
            val model = ebpf("test_fentry") {
                license(BpfLicense.GPL)
                targetKernel("5.4")
                fentry("vfs_read") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" })
                .anyMatch { it.message.contains("Fentry") }
        }

        @Test
        fun `fexit accepted at 5_5`() {
            val model = ebpf("test_fexit") {
                license(BpfLicense.GPL)
                targetKernel("5.5")
                fexit("vfs_read") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `fexit rejected at 5_4`() {
            val model = ebpf("test_fexit") {
                license(BpfLicense.GPL)
                targetKernel("5.4")
                fexit("vfs_read") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" })
                .anyMatch { it.message.contains("Fexit") }
        }

        @Test
        fun `lsm accepted at 5_7`() {
            val model = ebpf("test_lsm") {
                license(BpfLicense.GPL)
                targetKernel("5.7")
                lsm("bprm_check_security") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" }).isEmpty()
        }

        @Test
        fun `lsm rejected at 5_6`() {
            val model = ebpf("test_lsm") {
                license(BpfLicense.GPL)
                targetKernel("5.6")
                lsm("bprm_check_security") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            assertThat(result.diagnostics.filter { it.code == "kernel-version" })
                .anyMatch { it.message.contains("Lsm") }
        }

        @Test
        fun `baseline program types accepted at 4_18`() {
            // Tracepoint, RawTracepoint, Kprobe, Kretprobe, Xdp, TcClassifier, etc.
            val model = ebpf("test_baseline") {
                license(BpfLicense.GPL)
                targetKernel("4.18")
                tracepoint("sched", "sched_switch") { returnValue(literal(0, BpfScalar.S32)) }
                kprobe("vfs_read") { returnValue(literal(0, BpfScalar.S32)) }
                kretprobe("vfs_read") { returnValue(literal(0, BpfScalar.S32)) }
                xdp { returnAction(XDP_PASS) }
                tcClassifier { returnValue(literal(0, BpfScalar.S32)) }
            }
            val result = SemanticAnalyzer(model).analyze()
            val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
            assertThat(kernelErrors).isEmpty()
        }
    }

    // ── Code generation: boundary tests for include headers ─────────────

    @Nested
    inner class CodeGenBoundaryTests {

        @Test
        fun `kernel 5_1 - pre-BTF includes`() {
            val model = ebpf("test_51") {
                license(BpfLicense.GPL)
                targetKernel("5.1")
                kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val c = model.generateC()
            assertThat(c).contains("#include <linux/bpf.h>")
            assertThat(c).contains("#include <bpf/bpf_helpers.h>")
            assertThat(c).contains("#include <bpf/bpf_tracing.h>")
            assertThat(c).doesNotContain("vmlinux.h")
            assertThat(c).doesNotContain("bpf_core_read.h")
        }

        @Test
        fun `kernel 5_2 - BTF includes`() {
            val model = ebpf("test_52") {
                license(BpfLicense.GPL)
                targetKernel("5.2")
                kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
            }
            val c = model.generateC()
            assertThat(c).contains("#include \"vmlinux.h\"")
            assertThat(c).contains("#include <bpf/bpf_helpers.h>")
            assertThat(c).contains("#include <bpf/bpf_tracing.h>")
            assertThat(c).contains("#include <bpf/bpf_core_read.h>")
            assertThat(c).doesNotContain("<linux/bpf.h>")
        }

        @TestFactory
        fun `all kernel versions at or above 5_2 use vmlinux_h`(): List<DynamicTest> {
            val versions = listOf("5.2", "5.3", "5.5", "5.7", "5.8", "5.10", "5.13", "5.15", "6.0", "6.1")
            return versions.map { ver ->
                DynamicTest.dynamicTest("kernel $ver uses vmlinux.h") {
                    val model = ebpf("test") {
                        license(BpfLicense.GPL)
                        targetKernel(ver)
                        kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
                    }
                    val c = model.generateC()
                    assertThat(c).contains("#include \"vmlinux.h\"")
                    assertThat(c).contains("#include <bpf/bpf_core_read.h>")
                }
            }
        }

        @TestFactory
        fun `all kernel versions below 5_2 use linux_bpf_h`(): List<DynamicTest> {
            val versions = listOf("4.18", "4.19", "5.0", "5.1")
            return versions.map { ver ->
                DynamicTest.dynamicTest("kernel $ver uses linux/bpf.h") {
                    val model = ebpf("test") {
                        license(BpfLicense.GPL)
                        targetKernel(ver)
                        kprobe("test") { returnValue(literal(0, BpfScalar.S32)) }
                    }
                    val c = model.generateC()
                    assertThat(c).contains("#include <linux/bpf.h>")
                    assertThat(c).doesNotContain("vmlinux.h")
                }
            }
        }
    }

    // ── Full validate() pipeline tests at each kernel version ───────────

    @Nested
    inner class FullPipelineTests {

        @Test
        fun `kernel 4_18 - minimal valid program`() {
            val model = ebpf("minimal_418") {
                license(BpfLicense.GPL)
                targetKernel("4.18")
                val m by hashMap(K, V, 1024)
                kprobe("vfs_read") {
                    val pid = declareVar("pid", getCurrentPidTgid())
                    val ts = declareVar("ts", ktimeGetNs())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = model.validate()
            val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
            assertThat(kernelErrors).isEmpty()
        }

        @Test
        fun `kernel 4_19 - cgroup_storage map accepted`() {
            // CGROUP_STORAGE requires 4.19 — not directly testable via builder
            // but we verify the MapType.minKernel metadata is correct
            assertThat(MapType.CGROUP_STORAGE.minKernel).isEqualTo(KernelVersion(4, 19))
        }

        @Test
        fun `kernel 5_3 - full tracing with cgroup_id`() {
            val model = ebpf("tracing_53") {
                license(BpfLicense.GPL)
                targetKernel("5.3")
                val m by lruHashMap(K, V, 10240)
                tracepoint("sched", "sched_process_exec") {
                    val pid = declareVar("pid", getCurrentPidTgid())
                    val cg = declareVar("cg", getCurrentCgroupId())
                    val ts = declareVar("ts", ktimeGetNs())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = model.validate()
            val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
            assertThat(kernelErrors).isEmpty()
        }

        @Test
        fun `kernel 5_5 - fentry with probe_read`() {
            val model = ebpf("fentry_55") {
                license(BpfLicense.GPL)
                targetKernel("5.5")
                fentry("vfs_read") {
                    val cg = declareVar("cg", getCurrentCgroupId())
                    val data = declareVar("data", probeReadKernel(getCurrentTask(), BpfScalar.U64))
                    returnValue(literal(0, BpfScalar.S32))
                }
                fexit("vfs_read") {
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = model.validate()
            val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
            assertThat(kernelErrors).isEmpty()
        }

        @Test
        fun `kernel 5_7 - lsm program`() {
            val model = ebpf("lsm_57") {
                license(BpfLicense.GPL)
                targetKernel("5.7")
                lsm("bprm_check_security") {
                    val cg = declareVar("cg", getCurrentCgroupId())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = model.validate()
            val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
            assertThat(kernelErrors).isEmpty()
        }

        @Test
        fun `kernel 5_8 - ringbuf with all helpers`() {
            val model = ebpf("ringbuf_58") {
                license(BpfLicense.GPL)
                targetKernel("5.8")
                val rb by ringBuf(256 * 1024)
                val m by lruHashMap(K, V, 10240)
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
        fun `kernel 5_10 - task_btf helper`() {
            val model = ebpf("btf_510") {
                license(BpfLicense.GPL)
                targetKernel("5.10")
                kprobe("vfs_read") {
                    val task = declareVar("task", getCurrentTaskBtf())
                    val cg = declareVar("cg", getCurrentCgroupId())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = model.validate()
            val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
            assertThat(kernelErrors).isEmpty()
        }

        @Test
        fun `kernel 5_15 - everything combined`() {
            val model = ebpf("all_515") {
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
                lsm("bprm_check_security") {
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = model.validate()
            val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
            assertThat(kernelErrors).isEmpty()
        }

        @Test
        fun `kernel 6_1 - future kernel accepts everything`() {
            val model = ebpf("future_61") {
                license(BpfLicense.GPL)
                targetKernel("6.1")
                val rb by ringBuf(256 * 1024)
                fentry("vfs_read") {
                    val cg = declareVar("cg", getCurrentCgroupId())
                    val task = declareVar("task", getCurrentTaskBtf())
                    returnValue(literal(0, BpfScalar.S32))
                }
            }
            val result = model.validate()
            val kernelErrors = result.diagnostics.filter { it.code == "kernel-version" }
            assertThat(kernelErrors).isEmpty()
        }
    }

    // ── Metadata correctness tests ──────────────────────────────────────

    @Nested
    inner class MetadataTests {

        @Test
        fun `all helpers have reasonable minKernel`() {
            for (helper in HelperRegistry.all()) {
                assertThat(helper.minKernel)
                    .withFailMessage("${helper.name} has invalid minKernel ${helper.minKernel}")
                    .isGreaterThanOrEqualTo(KernelVersion.V4_18)
                    .isLessThanOrEqualTo(KernelVersion(6, 0))
            }
        }

        @Test
        fun `all map types have reasonable minKernel`() {
            for (mapType in MapType.entries) {
                assertThat(mapType.minKernel)
                    .withFailMessage("${mapType.name} has invalid minKernel ${mapType.minKernel}")
                    .isGreaterThanOrEqualTo(KernelVersion.V4_18)
                    .isLessThanOrEqualTo(KernelVersion(6, 0))
            }
        }

        @Test
        fun `specific helper minKernel values are correct`() {
            fun helper(name: String) = HelperRegistry.findByName(name)!!
            assertThat(helper("bpf_map_lookup_elem").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(helper("bpf_get_current_pid_tgid").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(helper("bpf_ktime_get_ns").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(helper("bpf_probe_read").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(helper("bpf_get_stack").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(helper("bpf_perf_event_output").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(helper("bpf_spin_lock").minKernel).isEqualTo(KernelVersion.V5_1)
            assertThat(helper("bpf_spin_unlock").minKernel).isEqualTo(KernelVersion.V5_1)
            assertThat(helper("bpf_get_current_cgroup_id").minKernel).isEqualTo(KernelVersion.V5_3)
            assertThat(helper("bpf_send_signal").minKernel).isEqualTo(KernelVersion.V5_3)
            assertThat(helper("bpf_probe_read_kernel").minKernel).isEqualTo(KernelVersion.V5_5)
            assertThat(helper("bpf_probe_read_user").minKernel).isEqualTo(KernelVersion.V5_5)
            assertThat(helper("bpf_ringbuf_output").minKernel).isEqualTo(KernelVersion.V5_8)
            assertThat(helper("bpf_ringbuf_reserve").minKernel).isEqualTo(KernelVersion.V5_8)
            assertThat(helper("bpf_ringbuf_submit").minKernel).isEqualTo(KernelVersion.V5_8)
            assertThat(helper("bpf_ringbuf_discard").minKernel).isEqualTo(KernelVersion.V5_8)
            assertThat(helper("bpf_get_current_task_btf").minKernel).isEqualTo(KernelVersion.V5_10)
        }

        @Test
        fun `specific map type minKernel values are correct`() {
            assertThat(MapType.HASH.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(MapType.ARRAY.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(MapType.LRU_HASH.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(MapType.PERCPU_HASH.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(MapType.PERCPU_ARRAY.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(MapType.CGROUP_STORAGE.minKernel).isEqualTo(KernelVersion(4, 19))
            assertThat(MapType.RINGBUF.minKernel).isEqualTo(KernelVersion.V5_8)
        }

        @Test
        fun `specific program type minKernel values are correct`() {
            assertThat(ProgramType.Tracepoint("a", "b").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.RawTracepoint("a").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.Kprobe("a").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.Kretprobe("a").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.Xdp.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.TcClassifier.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.CgroupSkb("ingress").minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.SockOps.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.SocketFilter.minKernel).isEqualTo(KernelVersion.V4_18)
            assertThat(ProgramType.Fentry("a").minKernel).isEqualTo(KernelVersion.V5_5)
            assertThat(ProgramType.Fexit("a").minKernel).isEqualTo(KernelVersion.V5_5)
            assertThat(ProgramType.Lsm("a").minKernel).isEqualTo(KernelVersion.V5_7)
            assertThat(ProgramType.Iter("a").minKernel).isEqualTo(KernelVersion.V5_9)
            assertThat(ProgramType.SchedClassifier("a").minKernel).isEqualTo(KernelVersion.V4_18)
        }
    }
}
