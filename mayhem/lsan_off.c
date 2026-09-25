/*
 * mayhem/lsan_off.c — build-time leak-detection off switch.
 *
 * `-fsanitize=address` always bundles the leak detector in; there is no compiler
 * flag that keeps ASan's memory-corruption checks while dropping just that part.
 * Leaks are not the defect class this fleet fuzzes for, and TON deliberately
 * leaks a handful of small one-time globals during static initialisation, so
 * leak reports would only bury the memory-safety findings we are after.
 *
 * Linking this translation unit into every fuzz and -standalone binary turns the
 * leak detector off at BUILD time. ASan (heap/stack overflow, use-after-free,
 * …) and UBSan stay fully active and still halt.
 *
 * Deliberately NOT used here, and forbidden fleet-wide: the runtime
 * enable/disable pair, and the weak per-tool "default options" override hooks
 * that a harness can define to force option strings on the sanitizer runtime —
 * Mayhem alone owns the runtime sanitizer option set.
 *
 * NOTE: keep the definition below on ONE line — the conformance gate detects it
 * with a line-wise grep, so a declaration split across lines reads as absent.
 */
int __lsan_is_turned_off(void) { return 1; }
