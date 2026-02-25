package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import dev.ebpf.dsl.validation.ValidationException
import dev.ebpf.dsl.validation.ValidationResult
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class ValidationIntegrationTest {

    object K : BpfStruct("k") {
        val id by u64()
    }

    object V : BpfStruct("v") {
        val count by u64()
    }

    @Test
    fun `validate runs both phases`() {
        val model = ebpf("ok") {
            license("GPL")
            val m by lruHashMap(K, V, maxEntries = 1024)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        assertThat(result).isInstanceOf(ValidationResult.Success::class.java)
    }

    @Test
    fun `validate catches type errors and semantic errors together`() {
        // XDP + getCurrentCgroupId = type error (helper-unavailable)
        // + unreachable code = semantic error
        val model = ebpf("bad") {
            license("GPL")
            xdp {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnAction(XDP_PASS)
                val x = declareVar("x", ktimeGetNs()) // unreachable
            }
        }
        val result = model.validate()
        assertThat(result.errors).hasSizeGreaterThanOrEqualTo(2)
    }

    @Test
    fun `throwOnError throws on failure`() {
        val model = ebpf("bad") {
            license("GPL")
            xdp {
                val cg = declareVar("cg", getCurrentCgroupId())
                returnAction(XDP_PASS)
            }
        }
        assertThatThrownBy { model.validate().throwOnError() }
            .isInstanceOf(ValidationException::class.java)
    }

    @Test
    fun `warnings dont block validation`() {
        val model = ebpf("warn") {
            license("GPL")
            val m by hashMap(K, V, maxEntries = 100000)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val result = model.validate()
        assertThat(result).isInstanceOf(ValidationResult.WithWarnings::class.java)
        assertThat(result.warnings).isNotEmpty()
        // throwOnError should NOT throw for warnings only
        result.throwOnError() // should not throw
    }

    @Test
    fun `validate with no programs succeeds`() {
        val model = ebpf("empty") {
            license("GPL")
        }
        val result = model.validate()
        assertThat(result).isInstanceOf(ValidationResult.Success::class.java)
    }

    @Test
    fun `validate collects diagnostics from both phases`() {
        // Type error from TypeChecker + warning from SemanticAnalyzer
        val model = ebpf("mixed") {
            license("GPL")
            val m by hashMap(K, V, maxEntries = 100000) // warning: prefer-lru-hash
            xdp {
                val cg = declareVar("cg", getCurrentCgroupId()) // error: helper-unavailable
                returnAction(XDP_PASS)
            }
        }
        val result = model.validate()
        assertThat(result).isInstanceOf(ValidationResult.Failed::class.java)
        assertThat(result.errors).anyMatch { it.code == "helper-unavailable" }
        assertThat(result.warnings).anyMatch { it.code == "prefer-lru-hash" }
    }
}
