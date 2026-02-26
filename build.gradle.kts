plugins {
    kotlin("jvm") version "2.1.10"
}

group = "dev.ebpf"
version = "0.1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.assertj:assertj-core:3.27.3")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        showStandardStreams = true
    }
    // Pass E2E_OUTPUT_DIR and UPDATE_GOLDEN through to test JVM
    listOf("E2E_OUTPUT_DIR", "UPDATE_GOLDEN").forEach { key ->
        System.getenv(key)?.let { environment(key, it) }
    }
}
