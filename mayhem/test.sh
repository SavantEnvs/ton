#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the functional oracle for this integration. Nothing is compiled here;
# mayhem/build.sh already produced every binary with the project's NORMAL flags.
#
# The oracle has three layers, all of them BEHAVIOURAL (values are asserted, never just an
# exit status), so a patch that "fixes" a bug by turning the program into a no-op FAILS:
#
#   1. mayhem/kat/boc_kat — known-answer probe over the exact API the fuzz targets drive
#      (std_boc_deserialize / std_boc_serialize / *_multi / CellStorageStat). Every value is
#      compared against a literal below. Two of the expectations are derivable WITHOUT TON:
#      a TON cell hash is sha256 over the cell's two descriptor bytes followed by its data, so
#        empty cell                    -> sha256(00 00)
#                                      == 96a296d2…cfc7
#        "Hello, world!" (104b, 0 refs)-> sha256(00 1a 48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21)
#                                      == 7eb1e431…2941
#      which is what makes them a real known-answer test rather than a snapshot of today's output.
#   2. upstream's own crypto/test/test-cells suite, run against upstream's committed golden
#      answers (test/regression-tests.ans) — this is the project's real assertion suite for the
#      cell/BOC code, and its per-test count is asserted, not just its exit code.
#   3. upstream's crypto/test/test-bigint suite, whose computed check lines are counted.
#
# A neutered binary prints nothing, so every layer collapses to zero matches and this script
# exits non-zero. Output contract: a CTRF (https://ctrf.io) summary, on stdout and on disk.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

TEST_BUILD="$SRC/mayhem-build-test"
KAT="$SRC/boc_kat"
REGRESSION="$SRC/test/regression-tests.ans"
# Upstream's tester wants a writable place for its answer cache; keep it out of the image dir.
export HOME="${HOME:-/tmp}"

PASSED=0
FAILED=0

note()  { printf '  %s\n' "$*"; }
ok()    { PASSED=$((PASSED + 1)); printf '  ok   %s\n' "$*"; }
bad()   { FAILED=$((FAILED + 1)); printf '  FAIL %s\n' "$*"; }

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# ---------------------------------------------------------------------------------
# Layer 1 — known-answer probe over the fuzzed API.
# ---------------------------------------------------------------------------------
echo "== KAT probe (boc_kat) =="
KAT_OUT=""
if [ ! -x "$KAT" ]; then
  bad "boc_kat missing at $KAT (mayhem/build.sh should have produced it)"
else
  KAT_OUT="$("$KAT" 2>&1)"
  note "boc_kat exited $? with $(printf '%s' "$KAT_OUT" | grep -c '^KAT ') KAT line(s)"
fi

# Every expectation is unconditional: a missing line is a FAILURE, never a skip.
EXPECTED=(
  'KAT empty_root_hash=96A296D224F285C67BEE93C30F8A309157F0DAA35DC5B87E410B78630A09CFC7'
  'KAT empty_stat=cells=1,bits=0'
  'KAT hello_hash=7EB1E4312DA1F8FEE787782CBFA8C1921C2A108E1591669471CC7EF808172941'
  'KAT hello_shape=bits=104,refs=0'
  'KAT hello_boc=B5EE9C7201010101000F00001A48656C6C6F2C20776F726C6421'
  'KAT hello_roundtrip_hash=7EB1E4312DA1F8FEE787782CBFA8C1921C2A108E1591669471CC7EF808172941'
  'KAT two_stat=cells=2,bits=120'
  'KAT two_root_hash=9F5FC74988F1CA4E51F64EAF94DB85CA092260705815E8153A90C91442B63FA0'
  'KAT multi_roots=2'
  'KAT multi_root_0=7EB1E4312DA1F8FEE787782CBFA8C1921C2A108E1591669471CC7EF808172941'
  'KAT multi_root_1=9F5FC74988F1CA4E51F64EAF94DB85CA092260705815E8153A90C91442B63FA0'
  'KAT junk_rejected=1'
  'KAT empty_input_rejected=1'
)
for want in "${EXPECTED[@]}"; do
  if printf '%s\n' "$KAT_OUT" | grep -Fxq "$want"; then
    ok "${want%%=*} matches the known answer"
  else
    bad "${want%%=*}: expected '$want', got '$(printf '%s\n' "$KAT_OUT" | grep -F "${want%%=*}=" | head -1)'"
  fi
done

# ---------------------------------------------------------------------------------
# Layer 2 — upstream's own cell/BOC suite against its committed golden answers.
# ---------------------------------------------------------------------------------
echo "== upstream crypto/test/test-cells (vs test/regression-tests.ans) =="
CELLS_BIN="$TEST_BUILD/test-cells"
if [ ! -x "$CELLS_BIN" ]; then
  bad "test-cells missing at $CELLS_BIN (mayhem/build.sh should have produced it)"
elif [ ! -f "$REGRESSION" ]; then
  bad "upstream golden answers missing at $REGRESSION"
else
  CELLS_OUT="$(cd "$TEST_BUILD" && ./test-cells --regression "$REGRESSION" --filter -Bench 2>&1)"
  CELLS_RC=$?
  # The suite prints a computed summary line; a neutered binary prints nothing at all.
  N="$(printf '%s\n' "$CELLS_OUT" | sed -n 's/^\([0-9][0-9]*\) test(s) passed$/\1/p' | tail -1)"
  if [ "$CELLS_RC" -ne 0 ]; then
    bad "test-cells exited $CELLS_RC"
    printf '%s\n' "$CELLS_OUT" | tail -5 | sed 's/^/       /'
  elif [ -z "$N" ]; then
    bad "test-cells produced no '<N> test(s) passed' summary line (output was $(printf '%s' "$CELLS_OUT" | wc -c) bytes)"
  elif [ "$N" -lt 9 ]; then
    bad "test-cells reported only $N passing test(s); upstream ships at least 9"
  else
    # Each upstream sub-test that verified against the golden answers counts.
    for _ in $(seq 1 "$N"); do PASSED=$((PASSED + 1)); done
    printf '  ok   test-cells: %s sub-test(s) verified against %s\n' "$N" "$REGRESSION"
  fi
fi

# ---------------------------------------------------------------------------------
# Layer 3 — upstream's bignum suite (the arbitrary-precision arithmetic the cell
# layer is built on). Its per-iteration "check on" lines are computed output.
# ---------------------------------------------------------------------------------
echo "== upstream crypto/test/test-bigint =="
BIGINT_BIN="$TEST_BUILD/test-bigint"
if [ ! -x "$BIGINT_BIN" ]; then
  bad "test-bigint missing at $BIGINT_BIN (mayhem/build.sh should have produced it)"
else
  BIG_OUT="$("$BIGINT_BIN" 2>&1)"
  BIG_RC=$?
  BIG_N="$(printf '%s\n' "$BIG_OUT" | grep -c '^#[0-9][0-9]*: check on ')"
  if [ "$BIG_RC" -ne 0 ]; then
    bad "test-bigint exited $BIG_RC"
    printf '%s\n' "$BIG_OUT" | tail -5 | sed 's/^/       /'
  elif [ "$BIG_N" -lt 5 ]; then
    bad "test-bigint produced only $BIG_N computed check line(s) (expected >= 5)"
  else
    ok "test-bigint: $BIG_N computed check line(s)"
  fi
fi

echo
emit_ctrf "ton-boc-kat+test-cells+test-bigint" "$PASSED" "$FAILED"
