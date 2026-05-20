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
