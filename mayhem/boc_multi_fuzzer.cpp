// Mayhem libFuzzer harness for TON multi-root Bag-of-Cells handling.
//
// Companion to boc_fuzzer: where that one drives the single-root entry point,
// this one drives vm::std_boc_deserialize_multi — the multi-root form used for
// block proofs, collated data and cell-database dumps — and then feeds the
// result straight back into vm::std_boc_serialize_multi. That covers a second
// body of code the single-root harness never reaches: the root list / index
// parsing on the way in, and the BOC *writer* (cell ordering, index emission,
// CRC) on the way out.
//
// Bytes come only from the fuzzer: no file I/O, no timers, no watchdogs, and no
// filtering of inputs (Mayhem owns the per-execution timeout; a hang is a
// finding, not something to hide).

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "td/utils/Slice.h"
#include "vm/boc.h"
#include "vm/cells/CellSlice.h"

namespace {

void round_trip(const uint8_t *data, size_t size) {
  auto res = vm::std_boc_deserialize_multi(td::Slice(data, size));
  if (res.is_error()) {
    return;
  }
  auto roots = res.move_as_ok();
  if (roots.empty()) {
    return;
  }

  for (const auto &root : roots) {
    if (root.is_null()) {
      continue;
    }
    vm::CellSlice cs{vm::NoVm{}, root};
    cs.size();
    cs.size_refs();
    // De-duplicating DAG walk (TON's own), so shared subtrees are loaded once.
    vm::CellStorageStat stat;
    stat.compute_used_storage(root);
  }

  // Re-serialize what we just parsed, then parse that again: exercises the
  // writer and the deserializer's handling of its own canonical output.
  auto ser = vm::std_boc_serialize_multi(roots);
  if (ser.is_error()) {
    return;
  }
  auto bytes = ser.move_as_ok();
  auto again = vm::std_boc_deserialize_multi(bytes.as_slice());
  if (again.is_ok()) {
    auto again_roots = again.move_as_ok();
    for (const auto &root : again_roots) {
      if (root.not_null()) {
        vm::CellSlice cs{vm::NoVm{}, root};
        cs.size();
      }
    }
  }
}

}  // namespace

// One-time TON global initialisation, kept out of the per-input path.
// (Leak detection is disabled at build time via mayhem/lsan_off.c.)
extern "C" int LLVMFuzzerInitialize(int * /*argc*/, char *** /*argv*/) {
  static const uint8_t warmup[1] = {0};
  round_trip(warmup, sizeof(warmup));
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  round_trip(data, size);
  return 0;
}
