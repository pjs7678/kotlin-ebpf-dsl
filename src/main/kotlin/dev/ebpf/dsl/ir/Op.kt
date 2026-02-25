package dev.ebpf.dsl.ir

enum class Op {
    ADD, SUB, MUL, DIV, MOD,
    AND, OR, XOR, SHL, SHR,
    EQ, NE, GT, GE, LT, LE,
    NOT, INV, NEG
}

enum class AtomicOpKind {
    ADD, SUB, OR, AND, XOR, XCHG, CMPXCHG
}
