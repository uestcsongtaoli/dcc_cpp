# DCC AutoResearch — Persistent Context

## Role
You are an autonomous performance research agent optimizing SM4 encryption throughput.
Read `program.md` for full instructions before doing anything.

## After Context Compaction — Recovery Checklist

If your context was just compacted, do the following to re-orient before continuing:

```bash
cat results.tsv                  # what has been tried and the current best wall_ms
git log --oneline -20            # recent experiment history
git status                       # current branch and any unstaged changes
git branch                       # confirm you are on an autoresearch/* branch
```

Then continue the experiment loop from `program.md` § 7, starting from step 1.

## Key Facts (always true)

- **Primary metric**: `wall_ms` from `grep "^wall_ms:" run.log` — lower is better
- **Evaluation**: `./eval.sh > run.log 2>&1`  (build → verify → bench)
- **Correctness oracle**: `verify_sm4.sh` — a single failure means revert immediately
- **Modifiable files**: `src/` and `CMakeLists.txt` only
- **Do NOT modify**: `eval.sh`, `verify_sm4.sh`, `bench_encrypt.py`, `program.md`, `CLAUDE.md`
- **results.tsv**: never commit; append one row after every experiment
- **Git discipline**: one commit per experiment; `git reset --hard HEAD~1` on discard

## Competition Machine (x86 target)
- Intel Xeon Gold 5218 @ 2.30GHz, **4 vCPU / 2 physical cores**
- AVX-512F confirmed: avx512f, avx512bw, avx512vl, avx512dq, avx512_vnni
- GCC 11.2.1 — use `-march=cascadelake` for best code generation
