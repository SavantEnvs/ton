#!/usr/bin/env bash
#
# mayhem/build.sh — build TON's fuzz harnesses, their standalone reproducers, and the
# oracle binaries that mayhem/test.sh runs.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The org base
# image (ghcr.io/savantenvs/base) exports the build contract we consume here:
#   CC, CXX, LIB_FUZZING_ENGINE, SANITIZER_FLAGS, DEBUG_FLAGS, STANDALONE_FUZZ_MAIN, SRC.
#
# TWO independent CMake trees, on purpose:
#   mayhem-build-fuzz/  sanitized + coverage-instrumented; the FUZZED code (ton_crypto_core,
#                       tdutils, tdactor, tddb_utils) is built with $SANITIZER_FLAGS,
#                       $DEBUG_FLAGS and -fsanitize=fuzzer-no-link, so ASan/UBSan and SanCov
#                       see the library, not just the harness translation unit.
#   mayhem-build-test/  the project's NORMAL flags, no sanitizers, no -gdwarf-3; produces
#                       upstream's own test-cells / test-bigint binaries and the KAT probe.
#                       Keeping it separate is what makes test.sh an honest oracle.
# Both directory names match upstream's `**/*build*/` .gitignore rule, so a `git clean -ffdX`
# removes them and this script rebuilds everything from committed sources + in-image content.
#
# NOTHING here touches the network: the handful of git submodules TON needs are materialised
# once by mayhem/Dockerfile and survive `git clean -ffdX` (they are tracked gitlinks, not
# ignored files). Everything else comes from apt packages baked into the image:
#   OpenSSL, zlib and secp256k1 are taken from the distro instead of TON's bundled copies
#   (TON honours -DOPENSSL_CRYPTO_LIBRARY / -DZLIB_FOUND / -DSECP256K1_LIBRARY), which also
#   keeps the build off the autotools path for those three.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SRC:=/mayhem}"
# `=` (not `:=`) on SANITIZER_FLAGS so an explicit EMPTY value from the Dockerfile
# (--build-arg SANITIZER_FLAGS=) really does build with no sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS is independent of the sanitizer off-switch and MUST keep DWARF < 4: Mayhem's
# triage cannot read DWARF >= 4 and clang-19's plain `-g` emits DWARF-5. It is applied AFTER
# $SANITIZER_FLAGS so its -gdwarf-3 wins over the -g the base carries.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
# Empty by default; appended to the ORACLE build only (never the fuzz build).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

OUT="$SRC"
FUZZ_BUILD="$SRC/mayhem-build-fuzz"
TEST_BUILD="$SRC/mayhem-build-test"
LIBDIR="/usr/lib/$(uname -m)-linux-gnu"
TARGETS="boc_fuzzer boc_multi_fuzzer"

# TON_ONLY_TONLIB drops the validator/RocksDB half of the tree; USE_QUIC=OFF keeps the build
# off the bundled OpenSSL. Everything the BOC parser needs still gets built.
COMMON_CMAKE=(
  -G Ninja
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_C_COMPILER="$CC"
  -DCMAKE_CXX_COMPILER="$CXX"
  -DTON_ONLY_TONLIB=ON
  -DTON_USE_ROCKSDB=OFF
  -DTON_USE_ABSEIL=OFF
  -DTON_USE_JEMALLOC=OFF
  -DUSE_QUIC=OFF
  -DPORTABLE=1
  -DTON_ARCH=
  -DOPENSSL_FOUND=TRUE
  -DOPENSSL_CRYPTO_LIBRARY="$LIBDIR/libcrypto.so"
  -DOPENSSL_INCLUDE_DIR=/usr/include
  -DZLIB_FOUND=TRUE
  -DZLIB_LIBRARY="$LIBDIR/libz.so"
  -DZLIB_INCLUDE_DIR=/usr/include
  -DSECP256K1_LIBRARY="$LIBDIR/libsecp256k1.a"
  -DSECP256K1_INCLUDE_DIR=/usr/include
)

SYS_LIBS=(-lcrypto -lz -lsecp256k1 -lpthread -ldl -lm)

incs_for() {   # include search path for a given build tree
  local b="$1"
  printf '%s\n' -I"$SRC" -I"$SRC/crypto" -I"$SRC/tdutils" -I"$SRC/tddb" -I"$SRC/tdactor" \
                -I"$SRC/tl" -I"$b" -I"$b/tdutils"
}

archives_in() {   # every static archive the tree produced, newline separated
  find "$1" -name '*.a' -print | sort
}

# ---------------------------------------------------------------------------------
# 1) ORACLE BUILD — the project's normal flags. Produces upstream's own test binaries
#    (so mayhem/test.sh only RUNS things) plus the KAT probe.
# ---------------------------------------------------------------------------------
echo ">>> configuring the oracle build (normal flags)"
cmake "${COMMON_CMAKE[@]}" -S "$SRC" -B "$TEST_BUILD" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"

echo ">>> building the oracle binaries"
ninja -C "$TEST_BUILD" -j"$MAYHEM_JOBS" ton_crypto_core test-cells test-bigint

for t in test-cells test-bigint; do
  [ -x "$TEST_BUILD/$t" ] || { echo "build.sh: oracle binary $t was not produced" >&2; exit 1; }
done

echo ">>> building the KAT probe"
mapfile -t TEST_INCS < <(incs_for "$TEST_BUILD")
mapfile -t TEST_ARCHIVES < <(archives_in "$TEST_BUILD")
"$CXX" -std=c++20 -O1 $COVERAGE_FLAGS "${TEST_INCS[@]}" \
  "$SRC/mayhem/kat/boc_kat.cpp" \
  -Wl,--start-group "${TEST_ARCHIVES[@]}" -Wl,--end-group \
  "${SYS_LIBS[@]}" \
  -o "$OUT/boc_kat"

# The anti-reward-hack sabotage check neuters DYNAMICALLY linked project binaries; a
# statically linked probe would survive it and silently weaken the oracle. Fail the build
# rather than ship that.
file "$OUT/boc_kat" | grep -q 'dynamically linked' \
  || { echo "build.sh: boc_kat is not dynamically linked — the oracle would survive sabotage" >&2; exit 1; }

# ---------------------------------------------------------------------------------
# 2) FUZZ BUILD — sanitized + SanCov-instrumented library, then one fuzzer and one
#    standalone reproducer per harness.
# ---------------------------------------------------------------------------------
# -fsanitize=fuzzer-no-link is appended UNCONDITIONALLY (including when SANITIZER_FLAGS is
# empty): $SANITIZER_FLAGS carries no coverage flags, so without it the fuzzed library has no
# SanCov instrumentation and every Mayhem run records 0 edges while building and smoking fine.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"

echo ">>> configuring the fuzz build (sanitized + instrumented)"
cmake "${COMMON_CMAKE[@]}" -S "$SRC" -B "$FUZZ_BUILD" \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" \
  -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS"

echo ">>> building the instrumented TON cell/BOC library"
ninja -C "$FUZZ_BUILD" -j"$MAYHEM_JOBS" ton_crypto_core

mapfile -t FUZZ_INCS < <(incs_for "$FUZZ_BUILD")
mapfile -t FUZZ_ARCHIVES < <(archives_in "$FUZZ_BUILD")

# The leak-detector off switch, linked into every sanitized binary below.
echo ">>> compiling mayhem/lsan_off.c"
# shellcheck disable=SC2086
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$FUZZ_BUILD/lsan_off.o"

# $STANDALONE_FUZZ_MAIN is a C file; compile it as C so its LLVMFuzzerTestOneInput reference
# keeps C linkage (clang++ would mangle it and miss the harness's extern "C" definition).
echo ">>> compiling the standalone run-once driver"
# shellcheck disable=SC2086
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_BUILD/standalone_main.o"

for t in $TARGETS; do
  echo ">>> linking $t"
  # The harness TU is listed FIRST so its compilation unit lands at .debug_info offset 0 and
  # the DWARF-version check reads a -gdwarf-3 CU.
  # shellcheck disable=SC2086
  "$CXX" -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${FUZZ_INCS[@]}" \
    "$SRC/mayhem/$t.cpp" "$FUZZ_BUILD/lsan_off.o" \
    -Wl,--start-group "${FUZZ_ARCHIVES[@]}" -Wl,--end-group \
    "${SYS_LIBS[@]}" \
    -o "$OUT/$t"

  echo ">>> linking $t-standalone"
  # shellcheck disable=SC2086
  "$CXX" -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS "${FUZZ_INCS[@]}" \
    "$SRC/mayhem/$t.cpp" "$FUZZ_BUILD/standalone_main.o" "$FUZZ_BUILD/lsan_off.o" \
    -Wl,--start-group "${FUZZ_ARCHIVES[@]}" -Wl,--end-group \
    "${SYS_LIBS[@]}" \
    -o "$OUT/$t-standalone"

  [ -x "$OUT/$t" ] && [ -x "$OUT/$t-standalone" ] \
    || { echo "build.sh: $t did not produce both binaries" >&2; exit 1; }
done

echo ">>> build.sh done:"
ls -l "$OUT/boc_kat" $(for t in $TARGETS; do echo "$OUT/$t" "$OUT/$t-standalone"; done)
