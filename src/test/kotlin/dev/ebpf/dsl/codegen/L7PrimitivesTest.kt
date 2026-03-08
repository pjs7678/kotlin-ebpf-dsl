package dev.ebpf.dsl.codegen

import dev.ebpf.dsl.api.ebpf
import dev.ebpf.dsl.types.BpfScalar
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class L7PrimitivesTest {

    @Test
    fun `probeReadBuf generates memset and bpf_probe_read_kernel`() {
        val model = ebpf("test") {
            license("GPL")
            kprobe("udp_sendmsg") {
                val ptr = kprobeParam(1, "const char *")
                val buf = probeReadBuf(ptr, 64)
                val b = declareVar("first_byte", buf.byte(0))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("char __buf_0[64];")
        assertThat(code).contains("__builtin_memset(&__buf_0, 0, sizeof(__buf_0));")
        assertThat(code).contains("bpf_probe_read_kernel(&__buf_0, 64, (const void *)(const char *)PT_REGS_PARM1(ctx));")
        assertThat(code).contains("__u8 first_byte = ((__u8)__buf_0[0]);")
    }

    @Test
    fun `probeReadUser generates bpf_probe_read_user`() {
        val model = ebpf("test") {
            license("GPL")
            kprobe("tcp_sendmsg") {
                val ptr = kprobeParam(1, "const char *")
                val buf = probeReadUser(ptr, 32)
                val b = declareVar("byte", buf.byte(0))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("bpf_probe_read_user(&__buf_0, 32, (const void *)(const char *)PT_REGS_PARM1(ctx));")
    }

    @Test
    fun `BufferHandle u16be generates ntohs`() {
        val model = ebpf("test") {
            license("GPL")
            kprobe("udp_sendmsg") {
                val ptr = kprobeParam(1, "const char *")
                val buf = probeReadBuf(ptr, 64)
                val port = declareVar("port", buf.u16be(0))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("__u16 port = __bpf_ntohs((*(__u16 *)&__buf_0[0]));")
    }

    @Test
    fun `BufferHandle u16le generates raw deref`() {
        val model = ebpf("test") {
            license("GPL")
            kprobe("udp_sendmsg") {
                val ptr = kprobeParam(1, "const char *")
                val buf = probeReadBuf(ptr, 64)
                val val16 = declareVar("val16", buf.u16le(2))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("__u16 val16 = (*(__u16 *)&__buf_0[2]);")
    }

    @Test
    fun `BufferHandle u32be generates ntohl`() {
        val model = ebpf("test") {
            license("GPL")
            kprobe("udp_sendmsg") {
                val ptr = kprobeParam(1, "const char *")
                val buf = probeReadBuf(ptr, 64)
                val len = declareVar("len", buf.u32be(4))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("__u32 len = __bpf_ntohl((*(__u32 *)&__buf_0[4]));")
    }

    @Test
    fun `BufferHandle u32le generates raw deref`() {
        val model = ebpf("test") {
            license("GPL")
            kprobe("udp_sendmsg") {
                val ptr = kprobeParam(1, "const char *")
                val buf = probeReadBuf(ptr, 64)
                val val32 = declareVar("val32", buf.u32le(0))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("__u32 val32 = (*(__u32 *)&__buf_0[0]);")
    }

    @Test
    fun `kretprobeReturnValue generates PT_REGS_RC`() {
        val model = ebpf("test") {
            license("GPL")
            kretprobe("udp_recvmsg") {
                val retval = declareVar("retval", kretprobeReturnValue(BpfScalar.S32))
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("SEC(\"kretprobe/udp_recvmsg\")")
        assertThat(code).contains("__s32 retval = (__s32)PT_REGS_RC(ctx);")
    }

    @Test
    fun `getSocketCookie generates helper call`() {
        val model = ebpf("test") {
            license("GPL")
            kprobe("tcp_sendmsg") {
                val cookie = declareVar("cookie", getSocketCookie())
                returnValue(literal(0, BpfScalar.S32))
            }
        }
        val code = CCodeGenerator(model).generate()
        assertThat(code).contains("__u64 cookie = bpf_get_socket_cookie();")
    }
}
