package dev.ebpf.dsl.api

import dev.ebpf.dsl.codegen.CCodeGenerator
import dev.ebpf.dsl.codegen.KotlinCodeGenerator
import java.io.File

data class OutputConfig(
    val cDir: String,
    val kotlinDir: String,
    val kotlinPackage: String,
    val targetKernel: String = "5.15",
    /** Fully-qualified class name of the BPF bridge to import in generated readers. */
    val bridgeImport: String? = null,
)

fun BpfProgramModel.generateC(): String = CCodeGenerator(this).generate()

fun BpfProgramModel.generateKotlin(pkg: String, bridgeImport: String? = null): String =
    KotlinCodeGenerator(this, pkg, bridgeImport).generate()

fun BpfProgramModel.emit(config: OutputConfig) {
    // Write C file
    val cFile = File(config.cDir, "${name}.bpf.c")
    cFile.parentFile.mkdirs()
    cFile.writeText(generateC())

    // Write Kotlin file
    val packageDir = config.kotlinPackage.replace('.', '/')
    val className = name.split("_").joinToString("") { it.replaceFirstChar { c -> c.uppercaseChar() } } + "MapReader"
    val ktFile = File(config.kotlinDir, "$packageDir/$className.kt")
    ktFile.parentFile.mkdirs()
    ktFile.writeText(generateKotlin(config.kotlinPackage, config.bridgeImport))
}
