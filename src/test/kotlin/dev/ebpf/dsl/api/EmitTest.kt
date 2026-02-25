package dev.ebpf.dsl.api

import dev.ebpf.dsl.types.BpfScalar
import dev.ebpf.dsl.types.BpfStruct
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class EmitTest {
    object K : BpfStruct("k") { val id by u64() }
    object V : BpfStruct("v") { val count by u64() }

    @Test
    fun `emit writes C and Kotlin files`(@TempDir dir: Path) {
        val model = ebpf("mem") {
            license("GPL")
            val m by lruHashMap(K, V, maxEntries = 100)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        model.emit(OutputConfig(
            cDir = dir.resolve("bpf").toString(),
            kotlinDir = dir.resolve("kotlin").toString(),
            kotlinPackage = "com.example.gen",
        ))
        assertThat(dir.resolve("bpf/mem.bpf.c")).exists()
        val kotlinFile = dir.resolve("kotlin/com/example/gen/MemMapReader.kt")
        assertThat(kotlinFile).exists()
    }

    @Test
    fun `generateC returns C source string`() {
        val model = ebpf("test") {
            license("GPL")
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val c = model.generateC()
        assertThat(c).contains("SEC(\"tp/oom/mark_victim\")")
    }

    @Test
    fun `generateKotlin returns Kotlin source string`() {
        val model = ebpf("test") {
            license("GPL")
            val m by lruHashMap(K, V, maxEntries = 100)
            tracepoint("oom", "mark_victim") {
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val kt = model.generateKotlin("com.example")
        assertThat(kt).contains("package com.example")
    }
}
