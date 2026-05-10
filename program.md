# DCC SM4 High-Concurrency AutoResearch Program

You are an autonomous performance research agent.

Your task is to optimize a baseline implementation for a high-concurrency dynamic data masking competition.

The goal is to minimize total wall-clock time for 100 concurrent `/encrypt` requests while preserving correctness and memory stability.

This file is immutable. Do not modify this file.

---

## 1. Competition Goal

We implement a local HTTP service with:

- `GET /health`
- `POST /encrypt`

The evaluator sends 100 concurrent `/encrypt` requests simultaneously. Each request is independent and carries:

- a unique `requestId`
- its own random `sm4Key` (16-byte, differs across requests)
- a random subset of the 11 fields to process (`fieldsToEncrypt`, **3–7 fields per request**, differs across requests; SM4-encrypted fields account for ~70% of selected fields)

The 11 fields are: `user_id`, `serial_no`, `user_code`, `business_key`, `id_card`, `phone`, `name`, `email`, `device_id`, `trans_id`, `secret_code`.
Of these, 7 are SM4-CBC encrypted; 4 (`id_card`, `phone`, `name`, `email`) are masked instead.

For each request, the service reads the shared source CSV, processes only the requested fields (encrypt or mask per field type), writes one output CSV file (must be explicitly `close()`d), then calls back the evaluator.

The primary metric is: **total wall-clock time from the first `/encrypt` received to the last one fully processed**. Lower is better.

Hard constraints:

- When changing the SM4 algorithm, you MUST run `verify_sm4.sh` first — `eval.sh` does this automatically.
- Output row order must match input row order.
- Output fields must follow the request `fieldsToEncrypt` order.
- Output CSV must be UTF-8, no BOM, no header, no quote wrapping.
- IV must remain fixed as `1234567890123456`.
- The service must not crash.
- Memory must stay below 8 GB.
- `/health` must return quickly.
- Do not perform heavy data loading, preprocessing, or memory allocation before `/health` is called successfully.

**Correctness dominates speed. A faster incorrect solution is worthless.**

---

## 2. Target Environment

### Development machine
macOS, any architecture — used for fast iteration. `wall_ms` values on Mac are not representative of competition performance (Mac has no AVX-512, and fewer/different cores).

### Competition machine (authoritative)
| Item | Value |
|------|-------|
| CPU | Intel Xeon Gold 5218 @ 2.30GHz |
| vCPUs | **4** (2 physical cores × 2 hyperthreads) |
| Memory | 7.6 GB RAM + 4 GB swap |
| Kernel | Linux 3.10.0 (CentOS 7 / RHEL7) |
| Compiler | GCC 11.2.1 (Red Hat), g++ 11.2.1 |
| Disk write | ~700 MB/s (dd sequential) |
| Disk read | ~2.6 GB/s |

**Available SIMD instruction sets** (confirmed from `/proc/cpuinfo`):
```
avx2        avx512f     avx512bw    avx512vl
avx512dq    avx512cd    avx512_vnni
pclmulqdq   aes         fma
```

**What this means for optimization:**
- `hardware_concurrency()` returns **4** on this machine (4 vCPUs).
- Physical cores = 2; hyperthreading means >4 threads rarely helps for CPU-bound SM4 work — may hurt due to cache sharing between HT siblings.
- The current code may contain an AVX-512 path, but do not assume it is optimal.
Measure before relying on it.
- You may replace, simplify, or remove an existing optimization if benchmark proves it faster and correctness remains intact.
- Output files are buffered; `close()` pushes to kernel page cache (fast). Actual disk flush is async — no `fsync()` needed.

### Input data scale
- **Current dev data**: 300,000 rows × 11 fields (~41 MB CSV)
- **Validation data may be larger** (up to ~500,000 rows) and changes every two weeks during the competition.
- **Do NOT hardcode row counts.** All code must use `g_rows.size()` dynamically. Optimizations must scale linearly with row count.

### Compilation
Static linking on Linux (`./build.sh` detects OS automatically). Binary: `build/dcc_encrypt`.

---

## 3. In-scope Files (what you may modify)

```
src/main.cpp          — HTTP server, thread pools, CSV loading, field masking, encrypt pipeline
src/sm4.cpp           — SM4 key schedule, T-box tables, scalar CBC encrypt
src/sm4_avx512.cpp    — AVX-512 16-way parallel CBC encrypt
src/sm4.h             — SM4 API declarations
src/sm4_avx512.h      — AVX-512 API declarations
CMakeLists.txt        — build flags, optimization levels, SIMD detection
```

**Fixed / do not modify:**

```
eval.sh               — the evaluation harness (build + verify + bench)
verify_sm4.sh         — SM4 correctness oracle
bench_encrypt.py      — 100-concurrent-request benchmark client
data/test_input.csv   — correctness test input
data/expected/        — correctness reference outputs
program.md            — this file
```

---

## 4. Setup

Before starting the experiment loop:

1. Read `src/main.cpp`, `src/sm4.cpp`, `src/sm4_avx512.cpp` for full context.
2. Verify the baseline result is recorded in `results.tsv`.
3. Create an experiment branch: `git checkout -b autoresearch/<tag>` (e.g. `autoresearch/may10`). The branch must not already exist.
4. Confirm `./eval.sh` runs cleanly (exit 0) on the baseline before making any changes.

---

## 5. Evaluation

All evaluation is done through a single script:

```bash
./eval.sh > run.log 2>&1
```

It runs three steps in sequence:

1. **Build** — `./build.sh` (incremental; only changed files recompile)
2. **Verify** — `./verify_sm4.sh` (3-row correctness test; fast)
3. **Benchmark** — starts `build/dcc_encrypt`, fires 100 concurrent requests, waits for all 100 to fully complete

**Output format** (always at the end of `run.log`):

```
---
wall_ms:      45306
client_ms:    148.61
success:      100
failed:       0
eval_status:  ok
```

**Extract the metric:**

```bash
grep "^wall_ms:"     run.log   # primary metric — server-side, lower is better
grep "^eval_status:" run.log   # "ok" on success; reason string on failure
grep "^success:"     run.log   # must be 100
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Build failed |
| 2 | SM4 correctness failed |
| 3 | CSV missing |
| 4 | Server failed to start |
| 5 | [BATCH] line not produced (server crash during bench) |
| 6 | Not all 100 requests succeeded |

---

## 6. Logging Results

Record every experiment to `results.tsv` (tab-separated). Do NOT commit this file.

Header and columns:

```
commit	wall_ms	status	description
```

1. `commit` — short git hash (7 chars): `git rev-parse --short HEAD`
2. `wall_ms` — integer from `grep "^wall_ms:" run.log` — use `0` for crashes
3. `status` — `keep`, `discard`, or `crash`
4. `description` — one-line summary of what was tried

Example:

```
commit	wall_ms	status	description
e0a4bd1	45306	keep	baseline: scalar SM4 T-box, 4 workers, mac no-AVX512
b2c3d4e	41200	keep	increase worker threads to 2×CPU count
c3d4e5f	47000	discard	mmap output — slower due to page faults
d4e5f6g	0	crash	rewrite CBC loop — broke alignment
```

---

## 7. The Experiment Loop

Run on a dedicated branch (e.g. `autoresearch/may10`).

**LOOP FOREVER:**

1. Check git state: `git log --oneline -3`
2. Choose ONE idea from the optimization directions below (or your own hypothesis).
3. Edit the in-scope source files.
4. `git add src/ CMakeLists.txt` (only stage changed files)
5. `git commit -m "short description of change"`
6. `./eval.sh > run.log 2>&1`
7. Extract results:
   ```bash
   grep "^wall_ms:\|^eval_status:\|^success:" run.log
   ```
8. **If `eval_status` is not `ok`** (build/verify/crash):
   - For build errors: `tail -50 run.log` to read the compiler error, attempt a fix
   - For verify failure: the SM4 output is wrong — revert immediately
   - For server crash: `grep "ERROR\|exception" run.log` for clues
   - After more than 2 failed fix attempts on the same idea: give up, `git reset --hard HEAD~1`, log `crash`
9. **If `eval_status` is `ok`**:

   Let `prev` = wall_ms of the current best (last `keep` row in results.tsv).
   Let `delta_pct` = (prev − wall_ms) / prev × 100.

   | delta_pct | Action |
   |-----------|--------|
   | < 0 (regression) | **discard** immediately |
   | 0 – 0.5% | **discard** — improvement too small to be real, treat as noise |
   | 0.5% – 3% | Run `./eval.sh > run.log 2>&1` **two more times** (3 total). Take the **median** wall_ms of all 3 runs. If median < prev → **keep**; else → **discard** |
   | ≥ 3% | **keep** after this single run — improvement is unambiguous |

   On **keep**: log the final wall_ms used (single run or median) to results.tsv, advance the branch.
   On **discard**: `git reset --hard HEAD~1`, log `discard`.

10. Append row to `results.tsv`
11. Repeat

**Timeout**: `eval.sh` normally takes 60–120 s on Mac (most time is the 100-request bench). On the competition x86 machine it is much faster. If a run exceeds 5 minutes, kill it (`Ctrl-C`), treat as crash.

**Crashes**: Use judgment. Fix trivial errors (typo, missing `#include`). Skip fundamentally broken ideas.

**NEVER STOP**: Once the loop has started, do NOT pause to ask if you should continue. The human may be away. Keep iterating until manually interrupted. If you run out of obvious ideas, consult the directions below, re-read the source files for new angles, or combine near-miss ideas.

---

## 8. Optimization Directions

These are starting hypotheses. Explore them in any order. Combine ideas. Invent new ones.

### SM4 Algorithm
- **Bit-sliced SM4**: process 32 or 64 independent CBC chains simultaneously using only bitwise operations (AND/OR/XOR/NOT). Eliminates all table lookups, maximizes SIMD utilization.
- **AVX2 path**: 8-way parallel SM4 for machines without AVX-512 (or as a supplementary path for tail blocks).
- **Larger T-box variants**: 32-bit or 64-bit fused T-tables to reduce round-trip loads.
- **Round-key layout**: store `rk[32]` in SIMD-friendly layout (e.g. broadcast-ready) to reduce gather latency.
- **Unrolled inner loop**: manually unroll the 32-round SM4 loop to reduce branch overhead.

### Thread & Concurrency
- **Worker count tuning**: the competition machine has 4 vCPUs / 2 physical cores. The current default (`hardware_concurrency()` = 4) is a reasonable start, but HT siblings share L1/L2 cache. With SM4 T-box lookups being cache-sensitive, try values of 2, 3, 4 — more than 4 is unlikely to help on this machine.
- **Per-field parallel dispatch**: instead of one job per request (all fields sequential), dispatch one job per (request × SM4-field) for finer-grained parallelism.
- **Lock-free task queue**: replace `std::queue` + `std::mutex` in `ThreadPool` with a lock-free ring buffer to reduce contention under 100 concurrent submissions.
- **Batch multiple requests into one job**: group N requests together in one worker job to share instruction cache and avoid repeated dispatch overhead.

### I/O & Output
- **Large write buffer**: replace line-by-line `ofs <<` with an in-memory string buffer; write the whole output in one `fwrite`. Reduces syscall count from 300K to 1.
- **`O_DIRECT` / `fallocate`**: pre-allocate output file size, use direct I/O to bypass page cache for write-once files.
- **`writev` or `sendfile`**: batch multiple small writes into one syscall.
- **Memory-mapped output**: `mmap` + `memcpy` instead of `write`. May help on Linux; test carefully.

### Data Layout & Preprocessing
- **Columnar CSV storage**: instead of `vector<vector<string>>` (row-major), store each column as `vector<string>` (column-major). Avoids pointer chasing when iterating a single field across 300K rows.
- **Precompute field lengths**: store `size_t` alongside each field value to skip `strlen` in the hot loop.
- **Precompute hex-encoded masked fields**: the 4 mask fields are already precomputed in `g_masked_col`. Consider precomputing the hex output for common SM4 fields too (not possible — key changes per request).
- **PKCS7 padding precomputation**: pad all plaintexts to block boundary once at CSV load time (key-independent). Reduces per-request work.

### Build & Compiler
- **`-O3` instead of `-O2`**: enable more aggressive auto-vectorization and loop transforms.
- **`-march=cascadelake`**: targets the exact Xeon Gold 5218 microarchitecture; enables all confirmed ISA extensions. Prefer this over `-march=native` for reproducibility across the 4 competition servers.
- **`-funroll-loops`**: unroll the 32-round SM4 inner loop.
- **`-fprofile-generate` / `-fprofile-use`** (PGO): instrument, run bench once, recompile with profile data for branch layout optimization.
- **Link-time optimization (LTO)**: `-flto` enables cross-TU inlining (e.g. `sm4_cbc_encrypt_into` inlined into the scalar hot loop in `main.cpp`).
- **`-ffast-math`**: safe here — no floating-point in the hot path.

### Architecture
- **Pre-warm CSV on first `/health`**: load CSV in a background thread immediately after `/health` succeeds (before any `/encrypt` arrives). Amortizes CSV load time.
- **Shared output buffer pool**: reuse per-request output buffers across requests to reduce allocator pressure.
