#!/usr/bin/env python3
"""
/encrypt 接口并发压测脚本
- 100 个并发请求
- 每个请求随机选取 11 个字段中的若干个
- 每个请求使用不同的 sm4Key
- 记录每个请求的耗时及整体统计
"""

import asyncio
import aiohttp
import time
import random
import string
import json
import statistics
from dataclasses import dataclass, field

# ── 配置 ──────────────────────────────────────────────────────────────────────
BASE_URL        = "http://localhost:8080/encrypt"
CONCURRENCY     = 100       # 并发数
REQUEST_TIMEOUT = 30        # 单个请求超时（秒）

ALL_FIELDS = [
    "user_id",
    "serial_no",
    "user_code",
    "business_key",
    "id_card",
    "phone",
    "name",
    "email",
    "device_id",
    "trans_id",
    "secret_code",
]

# ── 工具函数 ───────────────────────────────────────────────────────────────────

def random_sm4_key() -> str:
    """生成 16 字节（32 个十六进制字符）的随机 sm4Key"""
    return ''.join(random.choices(string.hexdigits.lower(), k=32))


def random_fields() -> list[str]:
    """从 11 个字段中随机选取 1～11 个"""
    k = random.randint(1, len(ALL_FIELDS))
    return random.sample(ALL_FIELDS, k)


def random_request_id(idx: int) -> str:
    return f"REQ_{idx:04d}_{random.randint(1000, 9999)}"


# ── 结果容器 ───────────────────────────────────────────────────────────────────

@dataclass
class Result:
    idx:        int
    request_id: str
    sm4_key:    str
    fields:     list[str]
    status:     int   = 0
    latency_ms: float = 0.0
    success:    bool  = False
    error:      str   = ""
    body:       str   = ""


# ── 单个请求 ───────────────────────────────────────────────────────────────────

async def do_request(
    session: aiohttp.ClientSession,
    idx: int,
    semaphore: asyncio.Semaphore,
) -> Result:
    sm4_key    = random_sm4_key()
    fields     = random_fields()
    request_id = random_request_id(idx)

    payload = {
        "requestId":       request_id,
        "sm4Key":          sm4_key,
        "ip":              "127.0.0.1",
        "fieldsToEncrypt": fields,
    }

    result = Result(
        idx        = idx,
        request_id = request_id,
        sm4_key    = sm4_key,
        fields     = fields,
    )

    async with semaphore:
        t0 = time.perf_counter()
        try:
            async with session.post(
                BASE_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ) as resp:
                result.status  = resp.status
                result.body    = await resp.text()
                result.latency_ms = (time.perf_counter() - t0) * 1000
                result.success = (resp.status == 200)
        except asyncio.TimeoutError:
            result.latency_ms = (time.perf_counter() - t0) * 1000
            result.error      = "TIMEOUT"
        except aiohttp.ClientConnectorError as e:
            result.latency_ms = (time.perf_counter() - t0) * 1000
            result.error      = f"CONNECTION_ERROR: {e}"
        except Exception as e:
            result.latency_ms = (time.perf_counter() - t0) * 1000
            result.error      = f"ERROR: {e}"

    return result


# ── 主流程 ─────────────────────────────────────────────────────────────────────

async def main():
    semaphore = asyncio.Semaphore(CONCURRENCY)

    connector = aiohttp.TCPConnector(
        limit=CONCURRENCY,
        limit_per_host=CONCURRENCY,
    )

    print(f"开始压测: {CONCURRENCY} 个并发请求 → {BASE_URL}")
    print(f"字段池: {ALL_FIELDS}\n")

    wall_start = time.perf_counter()

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            do_request(session, i + 1, semaphore)
            for i in range(CONCURRENCY)
        ]
        results: list[Result] = await asyncio.gather(*tasks)

    wall_elapsed_ms = (time.perf_counter() - wall_start) * 1000

    # ── 打印每条明细 ───────────────────────────────────────────────────────────
    print(f"{'#':>4}  {'RequestID':<20}  {'sm4Key':>12}  "
          f"{'字段数':>5}  {'HTTP':>4}  {'耗时(ms)':>9}  {'结果'}")
    print("-" * 90)

    for r in sorted(results, key=lambda x: x.idx):
        key_abbr = r.sm4_key[:8] + "…"
        status_str = str(r.status) if r.status else "---"
        outcome    = "OK" if r.success else (r.error or f"HTTP {r.status}")
        print(
            f"{r.idx:>4}  {r.request_id:<20}  {key_abbr:>12}  "
            f"{len(r.fields):>5}  {status_str:>4}  {r.latency_ms:>9.2f}  {outcome}"
        )

    # ── 汇总统计 ───────────────────────────────────────────────────────────────
    latencies   = [r.latency_ms for r in results]
    successes   = [r for r in results if r.success]
    failures    = [r for r in results if not r.success]

    print("\n" + "=" * 90)
    print("汇总统计")
    print("=" * 90)
    print(f"  总请求数     : {len(results)}")
    print(f"  成功         : {len(successes)}")
    print(f"  失败         : {len(failures)}")
    print(f"  整体耗时(ms) : {wall_elapsed_ms:.2f}")
    print(f"  吞吐量(req/s): {len(results) / (wall_elapsed_ms / 1000):.2f}")

    if latencies:
        sorted_lat = sorted(latencies)
        print(f"\n  延迟分布 (ms):")
        print(f"    最小  : {min(latencies):.2f}")
        print(f"    最大  : {max(latencies):.2f}")
        print(f"    平均  : {statistics.mean(latencies):.2f}")
        print(f"    中位数: {statistics.median(latencies):.2f}")
        if len(latencies) > 1:
            print(f"    标准差: {statistics.stdev(latencies):.2f}")
        p50  = sorted_lat[int(len(sorted_lat) * 0.50)]
        p90  = sorted_lat[int(len(sorted_lat) * 0.90)]
        p95  = sorted_lat[int(len(sorted_lat) * 0.95)]
        p99  = sorted_lat[int(len(sorted_lat) * 0.99)]
        print(f"    P50   : {p50:.2f}")
        print(f"    P90   : {p90:.2f}")
        print(f"    P95   : {p95:.2f}")
        print(f"    P99   : {p99:.2f}")

    if failures:
        print(f"\n  失败明细:")
        for r in failures:
            print(f"    [{r.idx:>3}] {r.request_id} — {r.error or f'HTTP {r.status}'}")

    # ── 字段选取频率 ───────────────────────────────────────────────────────────
    freq: dict[str, int] = {f: 0 for f in ALL_FIELDS}
    for r in results:
        for f in r.fields:
            freq[f] += 1

    print(f"\n  字段被选中次数 (共 {len(results)} 个请求):")
    for fname, cnt in sorted(freq.items(), key=lambda x: -x[1]):
        bar = "█" * int(cnt / len(results) * 20)
        print(f"    {fname:<14}: {cnt:>3}  {bar}")


if __name__ == "__main__":
    asyncio.run(main())
