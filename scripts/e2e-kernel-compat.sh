#!/usr/bin/env bash
#
# E2E kernel compatibility test for kotlin-ebpf-dsl.
#
# Generates C BPF programs at each kernel version target, copies them into
# minikube, and compiles them with clang -target bpf to verify the generated
# code is syntactically correct and compiles cleanly.
#
# Usage:
#   ./scripts/e2e-kernel-compat.sh
#
# Prerequisites:
#   - minikube running (minikube start)
#   - JAVA_HOME set or default openjdk@21 installed
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
E2E_OUTPUT_DIR="${E2E_OUTPUT_DIR:-/tmp/ebpf-e2e}"
JAVA_HOME="${JAVA_HOME:-/opt/homebrew/Cellar/openjdk@21/21.0.10/libexec/openjdk.jdk/Contents/Home}"
REMOTE_DIR="/tmp/ebpf-e2e"

export JAVA_HOME

# ── Colors ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

# ── Step 1: Check minikube ─────────────────────────────────────────
info "Checking minikube status..."
if ! minikube status >/dev/null 2>&1; then
    fail "minikube is not running. Start it with: minikube start"
    exit 1
fi
KERNEL_VERSION=$(minikube ssh "uname -r" 2>/dev/null | tr -d '\r')
ok "minikube running, kernel: $KERNEL_VERSION"

# ── Step 2: Generate C fixtures ────────────────────────────────────
info "Generating C fixture files from DSL..."
rm -rf "$E2E_OUTPUT_DIR"
mkdir -p "$E2E_OUTPUT_DIR"

cd "$PROJECT_DIR"
E2E_OUTPUT_DIR="$E2E_OUTPUT_DIR" ./gradlew cleanTest test \
    --tests "*.GenerateE2eFixtures" \
    --quiet 2>&1 | tail -20

FIXTURE_COUNT=$(find "$E2E_OUTPUT_DIR" -name "*.bpf.c" | wc -l | tr -d ' ')
ok "Generated $FIXTURE_COUNT C fixture files in $E2E_OUTPUT_DIR"

# ── Step 3: Install build tools in minikube ────────────────────────
info "Installing clang and libbpf-dev in minikube..."
minikube ssh "sudo apt-get update -qq 2>&1 | tail -1"
minikube ssh "sudo apt-get install -y clang libbpf-dev bpftool 2>&1 | tail -5"

# Verify clang is available
CLANG_PATH=$(minikube ssh "which clang 2>/dev/null" 2>/dev/null | tr -d '\r\n')
if [ -z "$CLANG_PATH" ]; then
    fail "clang installation failed inside minikube"
    exit 1
fi
CLANG_VERSION=$(minikube ssh "clang --version 2>/dev/null | head -1" 2>/dev/null | tr -d '\r')
ok "clang installed: $CLANG_VERSION"

# ── Step 4: Generate vmlinux.h inside minikube ─────────────────────
info "Generating vmlinux.h from BTF..."
minikube ssh "sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h 2>/dev/null || true" 2>/dev/null

if minikube ssh "test -s /tmp/vmlinux.h" 2>/dev/null; then
    ok "vmlinux.h generated from BTF"
else
    warn "bpftool not available or BTF dump failed, will try without vmlinux.h for >=5.2 programs"
fi

# ── Step 5: Copy fixture files into minikube ───────────────────────
info "Copying fixture files into minikube..."
minikube ssh "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR" 2>/dev/null

# Copy each subdirectory
for dir in "$E2E_OUTPUT_DIR"/*/; do
    dirname=$(basename "$dir")
    minikube ssh "mkdir -p $REMOTE_DIR/$dirname" 2>/dev/null
    for f in "$dir"*.bpf.c; do
        [ -f "$f" ] || continue
        minikube cp "$f" "$REMOTE_DIR/$dirname/$(basename "$f")" 2>/dev/null
    done
done
ok "Fixture files copied to minikube:$REMOTE_DIR"

# ── Step 6: Compile each fixture ───────────────────────────────────
info "Compiling BPF programs inside minikube..."

TOTAL=0
PASSED=0
FAILED=0
FAILED_FILES=""

# Copy vmlinux.h into each fixture directory that needs it (>= 5.2)
minikube ssh "
if [ -f /tmp/vmlinux.h ]; then
    for dir in $REMOTE_DIR/*/; do
        dirname=\$(basename \"\$dir\")
        case \$dirname in
            kernel-4.18|kernel-4.19) ;; # Pre-BTF, no vmlinux.h needed
            *) cp /tmp/vmlinux.h \"\$dir\" ;;
        esac
    done
fi
" 2>/dev/null

# Create a compilation script inside minikube
minikube ssh "cat > /tmp/compile-bpf.sh << 'SCRIPT'
#!/bin/bash
set -e

REMOTE_DIR=/tmp/ebpf-e2e
TOTAL=0
PASSED=0
FAILED=0
FAILED_FILES=""

# Detect architecture for -D__TARGET_ARCH_*
ARCH=\$(uname -m)
case \$ARCH in
    aarch64) TARGET_ARCH=arm64 ;;
    x86_64)  TARGET_ARCH=x86 ;;
    *)       TARGET_ARCH=\$ARCH ;;
esac

for dir in \$REMOTE_DIR/*/; do
    dirname=\$(basename \"\$dir\")
    echo \"=== Compiling: \$dirname ===\"

    for f in \"\$dir\"*.bpf.c; do
        [ -f \"\$f\" ] || continue
        fname=\$(basename \"\$f\")
        ofile=\"\${f%.c}.o\"
        TOTAL=\$((TOTAL + 1))

        # Include the fixture's own directory (for vmlinux.h) + system includes
        INCLUDES=\"-I\$(dirname \$f) -I/usr/include -I/usr/include/\$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo aarch64-linux-gnu)\"

        # Compile
        if clang -target bpf \
            -D__TARGET_ARCH_\$TARGET_ARCH \
            \$INCLUDES \
            -O2 -g \
            -c \"\$f\" -o \"\$ofile\" 2>/tmp/compile-err.txt; then
            echo \"  ✓ \$fname\"
            PASSED=\$((PASSED + 1))
        else
            echo \"  ✗ \$fname\"
            cat /tmp/compile-err.txt | head -20
            FAILED=\$((FAILED + 1))
            FAILED_FILES=\"\$FAILED_FILES \$dirname/\$fname\"
        fi
    done
done

echo ""
echo "═══════════════════════════════════════════"
echo " Results: \$PASSED/\$TOTAL passed, \$FAILED failed"
echo "═══════════════════════════════════════════"
if [ \$FAILED -gt 0 ]; then
    echo "Failed files:\$FAILED_FILES"
    exit 1
fi
SCRIPT
chmod +x /tmp/compile-bpf.sh" 2>/dev/null

# Run the compilation
echo ""
COMPILE_OUTPUT=$(minikube ssh "bash /tmp/compile-bpf.sh" 2>&1)
COMPILE_EXIT=$?
echo "$COMPILE_OUTPUT"

if [ $COMPILE_EXIT -eq 0 ]; then
    ok "All BPF programs compiled successfully!"
else
    fail "Some BPF programs failed to compile"
fi

# ── Step 7: Try loading representative programs (optional) ─────────
info "Attempting to load representative BPF programs..."
minikube ssh "cat > /tmp/load-bpf.sh << 'SCRIPT'
#!/bin/bash

REMOTE_DIR=/tmp/ebpf-e2e
LOADED=0
LOAD_FAILED=0

# Only try loading programs that the current kernel supports (6.8 supports everything)
# We'll try a representative from each kernel target
PROGRAMS=(
    \"kernel-5.2/btf_kprobe.bpf.o\"
    \"kernel-5.3/cgroup_tracing.bpf.o\"
    \"kernel-5.8/ringbuf_program.bpf.o\"
    \"kernel-5.15/all_features.bpf.o\"
)

for prog in \"\${PROGRAMS[@]}\"; do
    ofile=\"\$REMOTE_DIR/\$prog\"
    [ -f \"\$ofile\" ] || continue
    echo -n \"  Loading \$prog... \"

    # Try to load with bpftool (requires root)
    if sudo bpftool prog load \"\$ofile\" /sys/fs/bpf/test_prog 2>/tmp/load-err.txt; then
        echo \"✓ loaded\"
        sudo rm -f /sys/fs/bpf/test_prog
        LOADED=\$((LOADED + 1))
    else
        # Loading may fail for legitimate reasons (missing attach point, etc.)
        ERR=\$(cat /tmp/load-err.txt | head -1)
        echo \"⚠ \$ERR\"
        LOAD_FAILED=\$((LOAD_FAILED + 1))
    fi
done

echo ""
echo \"Load test: \$LOADED succeeded, \$LOAD_FAILED had issues (may be expected)\"
SCRIPT
chmod +x /tmp/load-bpf.sh" 2>/dev/null

LOAD_OUTPUT=$(minikube ssh "sudo bash /tmp/load-bpf.sh" 2>&1)
echo "$LOAD_OUTPUT"

# ── Summary ────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo -e " ${CYAN}E2E Kernel Compatibility Test Summary${NC}"
echo "═══════════════════════════════════════════════════════════════"
echo " Minikube kernel:  $KERNEL_VERSION"
echo " Fixture files:    $FIXTURE_COUNT"
echo " Kernel targets:   4.18, 5.2, 5.3, 5.5, 5.8, 5.10, 5.15"
echo "═══════════════════════════════════════════════════════════════"

exit $COMPILE_EXIT
