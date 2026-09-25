// Mayhem libFuzzer harness for TON Bag-of-Cells (BOC) deserialization.
//
// vm::std_boc_deserialize parses untrusted, attacker-controlled serialized cell
// data — the on-the-wire / on-disk representation used throughout the TON
// blockchain (blocks, messages, contract state, the cell database) — so every
// node processes bytes of this shape from strangers. That makes it the highest
// value parser in the tree.
//
// The harness takes its bytes ONLY from the fuzzer: no file I/O, no timers, no
// watchdogs, no input filtering (Mayhem owns the per-execution timeout, and a
// hang is itself a finding).

#include <cstddef>
#include <cstdint>

#include "td/utils/Slice.h"
#include "vm/boc.h"
#include "vm/cells/CellSlice.h"

namespace {

void deserialize_once(const uint8_t *data, size_t size) {
  auto res = vm::std_boc_deserialize(td::Slice(data, size),
                                     /* can_be_empty = */ true,
                                     /* allow_nonzero_level = */ true);
  if (res.is_error()) {
    return;
  }
  auto root = res.move_as_ok();
  if (root.is_null()) {
    return;
  }

  // Walk the root cell to exercise the cell-loading paths.
  vm::CellSlice cs{vm::NoVm{}, root};
  cs.size();
  cs.size_refs();
  cs.fetch_bits(cs.size());

  // Load EVERY cell of the tree. CellStorageStat does a de-duplicating DAG walk
  // (kill_dup = true), so a diamond-shaped BOC is visited once per distinct
  // cell rather than once per path, and the walk is TON's own traversal code
  // rather than something invented in the harness.
  vm::CellStorageStat stat;
  stat.compute_used_storage(root);
}

}  // namespace

// TON performs a small amount of one-time global initialisation on first use.
// Doing it here, outside the fuzzing loop, keeps it out of every per-input
// profile. (Leak detection is disabled at build time via mayhem/lsan_off.c.)
extern "C" int LLVMFuzzerInitialize(int * /*argc*/, char *** /*argv*/) {
  static const uint8_t warmup[1] = {0};
  deserialize_once(warmup, sizeof(warmup));
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  deserialize_once(data, size);
  return 0;
}
