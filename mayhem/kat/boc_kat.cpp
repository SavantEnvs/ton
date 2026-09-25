// mayhem/kat/boc_kat.cpp — known-answer probe for the code the fuzz targets drive.
//
// Built by mayhem/build.sh with the project's NORMAL flags (no sanitizers, no
// -gdwarf-3) against a clean ton_crypto_core, and RUN by mayhem/test.sh, which
// compares every line below against values hard-coded in the test script.
//
// Why a probe and not only upstream's own suite: `test-cells` is a pass/fail
// runner, and a runner can be made to "pass" by a program that exits before it
// does anything. Every number here is a value the probe must COMPUTE, so a
// neutered binary prints nothing and test.sh fails loudly.
//
// The two cell hashes are independently checkable without TON at all — a TON
// cell's hash is sha256 over its two descriptor bytes followed by its data:
//   empty cell (0 bits, 0 refs)          -> sha256(00 00)
//   "Hello, world!" (104 bits, 0 refs)   -> sha256(00 1a "Hello, world!")
// so the expectations in test.sh are not merely "whatever TON printed today".
//
// Second job (`--emit-seeds <dir>`): write the starter BOC corpus. The seeds
// committed under mayhem/<target>/testsuite/ were produced by exactly this
// code path, so they are real, format-valid TON Bags-of-Cells.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "td/utils/buffer.h"
#include "td/utils/misc.h"
#include "td/utils/Slice.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

namespace {

// The canonical serialized empty cell: one root, no refs, no data.
const char kEmptyBocHex[] = "b5ee9c724101010100020000004cacb9cd";

int die(const char *what) {
  std::fprintf(stderr, "boc_kat: %s\n", what);
  return 1;
}

td::Ref<vm::Cell> hello_cell() {
  vm::CellBuilder cb;
  cb.store_bytes(td::Slice("Hello, world!"));
  return cb.finalize();
}

// A two-cell BOC: a root holding 16 bits and one reference to the hello cell.
td::Ref<vm::Cell> two_cell_root() {
  vm::CellBuilder cb;
  cb.store_long(0xbeef, 16);
  cb.store_ref(hello_cell());
  return cb.finalize();
}

bool write_file(const std::string &path, td::Slice bytes) {
  FILE *f = std::fopen(path.c_str(), "wb");
  if (f == nullptr) {
    return false;
  }
  bool ok = std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
  ok = (std::fclose(f) == 0) && ok;
  return ok;
}

int emit_seeds(const std::string &dir) {
  struct Seed {
    const char *name;
    td::Ref<vm::Cell> root;
    int mode;
  };
  std::vector<Seed> seeds = {
      {"empty_cell", vm::CellBuilder().finalize(), 0},
      {"hello_world", hello_cell(), 0},
      {"two_cells", two_cell_root(), 0},
      {"two_cells_indexed_crc", two_cell_root(), 31},
  };
  for (auto &s : seeds) {
    auto r = vm::std_boc_serialize(s.root, s.mode);
    if (r.is_error()) {
      return die("seed serialization failed");
    }
    auto buf = r.move_as_ok();
    if (!write_file(dir + "/" + s.name + ".boc", buf.as_slice())) {
      return die("seed write failed");
    }
    std::printf("SEED %s %zu %s\n", s.name, (size_t)buf.size(),
                td::buffer_to_hex(buf.as_slice()).c_str());
  }
  // A deliberately deeper seed: a 24-cell chain, so the fuzzer starts with an
  // input that already walks a non-trivial tree.
  auto cur = vm::CellBuilder().finalize();
  for (int i = 0; i < 24; i++) {
    vm::CellBuilder cb;
    cb.store_long(i, 8);
    cb.store_ref(cur);
    cur = cb.finalize();
  }
  auto chain = vm::std_boc_serialize(cur, 31);
  if (chain.is_error()) {
    return die("chain seed serialization failed");
  }
  auto chain_buf = chain.move_as_ok();
  if (!write_file(dir + "/chain24.boc", chain_buf.as_slice())) {
    return die("chain seed write failed");
  }
  std::printf("SEED chain24 %zu\n", (size_t)chain_buf.size());

  // Multi-root seed for the multi-root target.
  std::vector<td::Ref<vm::Cell>> roots = {hello_cell(), two_cell_root()};
  auto multi = vm::std_boc_serialize_multi(roots, 31);
  if (multi.is_error()) {
    return die("multi-root seed serialization failed");
  }
  auto multi_buf = multi.move_as_ok();
  if (!write_file(dir + "/multi_two_roots.boc", multi_buf.as_slice())) {
    return die("multi seed write failed");
  }
  std::printf("SEED multi_two_roots %zu %s\n", (size_t)multi_buf.size(),
              td::buffer_to_hex(multi_buf.as_slice()).c_str());
  return 0;
}

int run_kat() {
  // 1) Deserialize the canonical empty-cell BOC — the exact API the fuzz
  //    targets drive — and report the root hash + the storage statistics.
  auto raw = td::hex_decode(td::Slice(kEmptyBocHex));
  if (raw.is_error()) {
    return die("hex_decode failed");
  }
  auto raw_bytes = raw.move_as_ok();
  auto de = vm::std_boc_deserialize(td::Slice(raw_bytes), true, true);
  if (de.is_error()) {
    return die("std_boc_deserialize rejected the canonical empty BOC");
  }
  auto empty_root = de.move_as_ok();
  if (empty_root.is_null()) {
    return die("empty BOC produced a null root");
  }
  vm::CellStorageStat empty_stat;
  if (empty_stat.compute_used_storage(empty_root).is_error()) {
    return die("compute_used_storage failed on the empty cell");
  }
  std::printf("KAT empty_root_hash=%s\n", empty_root->get_hash().to_hex().c_str());
  std::printf("KAT empty_stat=cells=%llu,bits=%llu\n", empty_stat.cells, empty_stat.bits);

  // 2) Build the 13-byte "Hello, world!" cell and report its hash.
  auto hello = hello_cell();
  std::printf("KAT hello_hash=%s\n", hello->get_hash().to_hex().c_str());
  {
    vm::CellSlice cs{vm::NoVm{}, hello};
    std::printf("KAT hello_shape=bits=%u,refs=%u\n", cs.size(), cs.size_refs());
  }

  // 3) Serialize it and assert the exact wire bytes, then parse them back and
  //    assert the hash survives the round trip.
  auto ser = vm::std_boc_serialize(hello, 0);
  if (ser.is_error()) {
    return die("std_boc_serialize failed on the hello cell");
  }
  auto ser_buf = ser.move_as_ok();
  std::printf("KAT hello_boc=%s\n", td::buffer_to_hex(ser_buf.as_slice()).c_str());
  auto back = vm::std_boc_deserialize(ser_buf.as_slice(), true, true);
  if (back.is_error()) {
    return die("std_boc_deserialize rejected our own serialization");
  }
  std::printf("KAT hello_roundtrip_hash=%s\n", back.move_as_ok()->get_hash().to_hex().c_str());

  // 4) A two-cell BOC exercises the reference/index path of the same parser.
  auto two = two_cell_root();
  auto two_ser = vm::std_boc_serialize(two, 31);
  if (two_ser.is_error()) {
    return die("std_boc_serialize failed on the two-cell BOC");
  }
  auto two_buf = two_ser.move_as_ok();
  auto two_back = vm::std_boc_deserialize(two_buf.as_slice(), true, true);
  if (two_back.is_error()) {
    return die("std_boc_deserialize rejected the two-cell BOC");
  }
  auto two_root = two_back.move_as_ok();
  vm::CellStorageStat two_stat;
  if (two_stat.compute_used_storage(two_root).is_error()) {
    return die("compute_used_storage failed on the two-cell BOC");
  }
  std::printf("KAT two_stat=cells=%llu,bits=%llu\n", two_stat.cells, two_stat.bits);
  std::printf("KAT two_root_hash=%s\n", two_root->get_hash().to_hex().c_str());

  // 5) Multi-root: two roots in, two roots out, in order.
  std::vector<td::Ref<vm::Cell>> roots = {hello, two};
  auto multi = vm::std_boc_serialize_multi(roots, 31);
  if (multi.is_error()) {
    return die("std_boc_serialize_multi failed");
  }
  auto multi_buf = multi.move_as_ok();
  auto multi_back = vm::std_boc_deserialize_multi(multi_buf.as_slice());
  if (multi_back.is_error()) {
    return die("std_boc_deserialize_multi rejected our own serialization");
  }
  auto multi_roots = multi_back.move_as_ok();
  std::printf("KAT multi_roots=%zu\n", multi_roots.size());
  for (size_t i = 0; i < multi_roots.size(); i++) {
    std::printf("KAT multi_root_%zu=%s\n", i, multi_roots[i]->get_hash().to_hex().c_str());
  }

  // 6) Garbage must be REJECTED, not accepted — the parser's negative path.
  const unsigned char junk[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03};
  auto junk_res = vm::std_boc_deserialize(td::Slice(junk, sizeof(junk)), true, true);
  std::printf("KAT junk_rejected=%d\n", junk_res.is_error() ? 1 : 0);
  auto empty_res = vm::std_boc_deserialize(td::Slice(), false, false);
  std::printf("KAT empty_input_rejected=%d\n", empty_res.is_error() ? 1 : 0);
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc >= 3 && std::strcmp(argv[1], "--emit-seeds") == 0) {
    return emit_seeds(argv[2]);
  }
  return run_kat();
}
