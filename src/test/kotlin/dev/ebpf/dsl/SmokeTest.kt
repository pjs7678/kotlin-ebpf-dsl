package dev.ebpf.dsl

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SmokeTest {
    @Test
    fun `library loads`() {
        assertThat(EbpfDsl.VERSION).isNotBlank()
    }
}
