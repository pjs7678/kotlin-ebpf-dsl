package dev.ebpf.dsl.kernel

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KernelVersionTest {

    @Test
    fun `parse valid version string`() {
        val v = KernelVersion.parse("5.8")
        assertEquals(5, v.major)
        assertEquals(8, v.minor)
        assertEquals("5.8", v.toString())
    }

    @Test
    fun `parse rejects invalid format`() {
        assertThrows<IllegalArgumentException> { KernelVersion.parse("5") }
        assertThrows<IllegalArgumentException> { KernelVersion.parse("5.8.1") }
        assertThrows<IllegalArgumentException> { KernelVersion.parse("abc.def") }
        assertThrows<IllegalArgumentException> { KernelVersion.parse("") }
    }

    @Test
    fun `constructor creates correct version`() {
        val v = KernelVersion(4, 18)
        assertEquals(4, v.major)
        assertEquals(18, v.minor)
    }

    @Test
    fun `comparison works correctly`() {
        assertTrue(KernelVersion.V4_18 < KernelVersion.V5_2)
        assertTrue(KernelVersion.V5_8 > KernelVersion.V5_5)
        assertTrue(KernelVersion.V5_15 >= KernelVersion.V5_15)
        assertTrue(KernelVersion.V5_2 <= KernelVersion.V5_3)
        assertEquals(0, KernelVersion.parse("5.8").compareTo(KernelVersion.V5_8))
    }

    @Test
    fun `companion constants match expected values`() {
        assertEquals("4.18", KernelVersion.V4_18.toString())
        assertEquals("5.1", KernelVersion.V5_1.toString())
        assertEquals("5.2", KernelVersion.V5_2.toString())
        assertEquals("5.3", KernelVersion.V5_3.toString())
        assertEquals("5.5", KernelVersion.V5_5.toString())
        assertEquals("5.7", KernelVersion.V5_7.toString())
        assertEquals("5.8", KernelVersion.V5_8.toString())
        assertEquals("5.9", KernelVersion.V5_9.toString())
        assertEquals("5.10", KernelVersion.V5_10.toString())
        assertEquals("5.13", KernelVersion.V5_13.toString())
        assertEquals("5.15", KernelVersion.V5_15.toString())
    }

    @Test
    fun `toString formats correctly`() {
        assertEquals("4.18", KernelVersion(4, 18).toString())
        assertEquals("6.0", KernelVersion(6, 0).toString())
    }

    @Test
    fun `ordering across major versions`() {
        assertTrue(KernelVersion(4, 99) < KernelVersion(5, 0))
        assertTrue(KernelVersion(6, 0) > KernelVersion(5, 99))
    }
}
