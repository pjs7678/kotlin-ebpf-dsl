package dev.ebpf.dsl.types

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class BpfScalarTest {

    @Test
    fun `U8 has size 1, unsigned, cName __u8`() {
        assertThat(BpfScalar.U8.size).isEqualTo(1)
        assertThat(BpfScalar.U8.signed).isFalse()
        assertThat(BpfScalar.U8.cName).isEqualTo("__u8")
    }

    @Test
    fun `S64 has size 8, signed, cName __s64`() {
        assertThat(BpfScalar.S64.size).isEqualTo(8)
        assertThat(BpfScalar.S64.signed).isTrue()
        assertThat(BpfScalar.S64.cName).isEqualTo("__s64")
    }

    @Test
    fun `Bool has size 1, cName bool`() {
        assertThat(BpfScalar.Bool.size).isEqualTo(1)
        assertThat(BpfScalar.Bool.cName).isEqualTo("bool")
    }

    @Test
    fun `all 9 scalars have distinct cNames`() {
        val allScalars = listOf(
            BpfScalar.U8, BpfScalar.U16, BpfScalar.U32, BpfScalar.U64,
            BpfScalar.S8, BpfScalar.S16, BpfScalar.S32, BpfScalar.S64,
            BpfScalar.Bool,
        )
        val cNames = allScalars.map { it.cName }.toSet()
        assertThat(cNames).hasSize(9)
    }

    @Test
    fun `alignment equals size for all scalars`() {
        val allScalars = listOf(
            BpfScalar.U8, BpfScalar.U16, BpfScalar.U32, BpfScalar.U64,
            BpfScalar.S8, BpfScalar.S16, BpfScalar.S32, BpfScalar.S64,
            BpfScalar.Bool,
        )
        allScalars.forEach { scalar ->
            assertThat(scalar.alignment)
                .describedAs("alignment of ${scalar.cName}")
                .isEqualTo(scalar.size)
        }
    }
}
