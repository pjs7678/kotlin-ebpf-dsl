package dev.ebpf.dsl.kernel

@JvmInline
value class KernelVersion(private val encoded: Int) : Comparable<KernelVersion> {
    constructor(major: Int, minor: Int) : this((major shl 16) or minor)

    val major: Int get() = encoded shr 16
    val minor: Int get() = encoded and 0xFFFF

    override fun compareTo(other: KernelVersion): Int = encoded.compareTo(other.encoded)
    override fun toString(): String = "$major.$minor"

    companion object {
        fun parse(s: String): KernelVersion {
            val parts = s.split(".")
            require(parts.size == 2) { "Expected 'major.minor' format, got: '$s'" }
            val major = parts[0].toIntOrNull() ?: throw IllegalArgumentException("Invalid major version: '${parts[0]}'")
            val minor = parts[1].toIntOrNull() ?: throw IllegalArgumentException("Invalid minor version: '${parts[1]}'")
            return KernelVersion(major, minor)
        }

        val V4_18 = KernelVersion(4, 18)
        val V5_1 = KernelVersion(5, 1)
        val V5_2 = KernelVersion(5, 2)
        val V5_3 = KernelVersion(5, 3)
        val V5_5 = KernelVersion(5, 5)
        val V5_7 = KernelVersion(5, 7)
        val V5_8 = KernelVersion(5, 8)
        val V5_9 = KernelVersion(5, 9)
        val V5_10 = KernelVersion(5, 10)
        val V5_13 = KernelVersion(5, 13)
        val V5_15 = KernelVersion(5, 15)
    }
}
