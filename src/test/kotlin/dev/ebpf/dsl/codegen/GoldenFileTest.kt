package dev.ebpf.dsl.codegen

import dev.ebpf.dsl.api.generateC
import dev.ebpf.dsl.api.validate
import dev.ebpf.dsl.tools.ToolRegistry
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

/**
 * Golden file snapshot test — captures exact C output of all programs.
 *
 * Run with `UPDATE_GOLDEN=1 ./gradlew test` to regenerate golden files.
 * Normal test runs assert the generated C matches the golden file exactly.
 */
class GoldenFileTest {

    private val goldenDir: Path = Path.of("src/test/resources/golden")
    private val updateGolden = System.getenv("UPDATE_GOLDEN") == "1"

    @Test
    fun `all tools match golden files`() {
        val failures = mutableListOf<String>()

        for (tool in ToolRegistry.all()) {
            val model = tool.build()
            val result = model.validate()
            assertThat(result.errors)
                .describedAs("${tool.name} should have no validation errors")
                .isEmpty()

            val generated = model.generateC()
            val goldenFile = goldenDir.resolve("${tool.name}.bpf.c")

            if (updateGolden) {
                Files.createDirectories(goldenDir)
                Files.writeString(goldenFile, generated)
                continue
            }

            if (!Files.exists(goldenFile)) {
                failures.add("${tool.name}: golden file missing. Run with UPDATE_GOLDEN=1 to generate.")
                continue
            }

            val expected = Files.readString(goldenFile)
            if (generated != expected) {
                failures.add("${tool.name}: generated C differs from golden file")
            }
        }

        if (!updateGolden) {
            assertThat(failures)
                .describedAs("Golden file mismatches")
                .isEmpty()
        }
    }
}
