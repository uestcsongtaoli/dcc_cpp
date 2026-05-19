#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <atomic>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <cstdio>
#include <chrono>
#include <filesystem>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <immintrin.h>
#include "sm4.h"
#include "sm4_avx512.h"

// ─── Config ───────────────────────────────────────────────────────────────────

static std::string g_csv_path;
static std::string g_output_dir;
static std::string g_team_code;
static std::string g_callback_url;
static bool        g_debug      = false;
static int         g_port       = 8080;
static int         g_workers    = 0;
static int         g_expect_reqs= 100;
static int         g_mini_batch = 16;    // DCC_MINI_BATCH: requests per mini-batch
static int         g_chunk_size = 8192;  // DCC_CHUNK_SIZE: rows per compute task

// ─── Timing ───────────────────────────────────────────────────────────────────

using TClock = std::chrono::steady_clock;
using TPoint = TClock::time_point;
static inline TPoint tnow() { return TClock::now(); }
static inline double tms(TPoint a, TPoint b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}
#define TLOG(fmt, ...) \
    do { if (g_debug) { fprintf(stderr, "[T] " fmt "\n", ##__VA_ARGS__); } } while(0)

static const uint8_t SM4_IV[16] = {
    '1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'
};

// ─── Field mapping ────────────────────────────────────────────────────────────

struct FieldInfo { int col; bool is_sm4; };

static const std::unordered_map<std::string, FieldInfo> FIELDS = {
    {"user_id",      {0,  true}},
    {"serial_no",    {1,  true}},
    {"user_code",    {2,  true}},
    {"business_key", {3,  true}},
    {"id_card",      {4,  false}},
    {"phone",        {5,  false}},
    {"name",         {6,  false}},
    {"email",        {7,  false}},
    {"device_id",    {8,  true}},
    {"trans_id",     {9,  true}},
    {"secret_code",  {10, true}},
};

// col → SM4 field index (0-6); -1 for mask fields
static const int COL_TO_SM4IDX[11] = {0, 1, 2, 3, -1, -1, -1, -1, 4, 5, 6};
// SM4 field index (0-6) → column index
static const int SM4IDX_TO_COL[7]  = {0, 1, 2, 3, 8, 9, 10};

// ─── CSV data ─────────────────────────────────────────────────────────────────

static std::vector<std::string> g_cols[11];
static size_t                   g_nrows = 0;
static std::atomic<bool> g_csv_ready{false};
static std::mutex g_csv_mu;

// Precomputed mask output (col4-7 → idx0-3)
static std::vector<std::string> g_masked_col[4];
static std::vector<uint16_t>    g_mask_outlen[4];  // byte length of each masked value

// Pre-computed PKCS7-padded plaintext blobs for the 7 SM4 fields.
// Sequential memory instead of scattered std::string heap pointers →
// hardware prefetcher friendly, avoids per-request memcpy+memset.
struct SM4PaddedField {
    std::vector<uint32_t> offset;  // byte offset in blob for row r
    std::vector<uint16_t> padlen;  // PKCS7 padded length for row r (multiple of 16)
    std::vector<uint8_t>  blob;    // concatenated PKCS7-padded plaintexts
};
static SM4PaddedField g_sm4_pad[7];

static std::string mask(const std::string& s);  // forward decl

static void load_csv() {
    auto t0 = tnow();
    std::ifstream ifs(g_csv_path);
    if (!ifs) throw std::runtime_error("Cannot open: " + g_csv_path);

    std::string line;
    std::getline(ifs, line); // skip header

    for (int c = 0; c < 11; ++c) g_cols[c].reserve(320000);

    auto t1 = tnow();
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        const char* p   = line.c_str();
        const char* end = p + line.size();
        if (end > p && *(end - 1) == '\r') --end;
        int col = 0;
        while (col < 11) {
            const char* fs = p;
            while (p < end && *p != ',') ++p;
            g_cols[col].emplace_back(fs, (size_t)(p - fs));
            ++col;
            if (p < end) ++p;
        }
        while (col < 11) { g_cols[col].emplace_back(); ++col; }
    }
    g_nrows = g_cols[0].size();
    auto t2 = tnow();

    // Precompute mask for 4 mask columns (col4-7 → idx0-3)
    for (int m = 0; m < 4; m++) {
        int col = m + 4;
        g_masked_col[m].reserve(g_nrows);
        g_mask_outlen[m].resize(g_nrows);
        for (size_t r = 0; r < g_nrows; ++r) {
            g_masked_col[m].push_back(mask(g_cols[col][r]));
            g_mask_outlen[m][r] = (uint16_t)g_masked_col[m][r].size();
        }
    }
    auto t3 = tnow();

    // Pre-compute PKCS7-padded plaintext blobs for 7 SM4 fields.
    for (int f = 0; f < 7; f++) {
        int col = SM4IDX_TO_COL[f];
        g_sm4_pad[f].offset.resize(g_nrows);
        g_sm4_pad[f].padlen.resize(g_nrows);
        uint32_t total = 0;
        for (size_t r = 0; r < g_nrows; r++) {
            g_sm4_pad[f].offset[r] = total;
            size_t plen = g_cols[col][r].size();
            auto   pad  = (uint16_t)(16 - (plen & 15u));
            auto   padded = (uint16_t)(plen + pad);
            g_sm4_pad[f].padlen[r] = padded;
            total += padded;
        }
        g_sm4_pad[f].blob.resize(total);
        for (size_t r = 0; r < g_nrows; r++) {
            size_t  plen = g_cols[col][r].size();
            uint8_t pad  = (uint8_t)(g_sm4_pad[f].padlen[r] - (uint16_t)plen);
            uint8_t* dst = g_sm4_pad[f].blob.data() + g_sm4_pad[f].offset[r];
            memcpy(dst, g_cols[col][r].data(), plen);
            memset(dst + plen, pad, pad);
        }
    }
    auto t4 = tnow();

    fprintf(stderr,
        "[INFO] CSV loaded: %zu rows"
        " | open=%.1fms  parse=%.1fms  mask_pre=%.1fms  pad_pre=%.1fms  total=%.1fms\n",
        g_nrows, tms(t0, t1), tms(t1, t2), tms(t2, t3), tms(t3, t4), tms(t0, t4));
}

static void ensure_csv() {
    if (g_csv_ready.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(g_csv_mu);
    if (g_csv_ready.load(std::memory_order_relaxed)) return;
    load_csv();
    g_csv_ready.store(true, std::memory_order_release);
}

// ─── Mask ─────────────────────────────────────────────────────────────────────

static std::string mask(const std::string& s) {
    if (s.empty()) return s;
    std::vector<size_t> cp_starts;
    cp_starts.reserve(s.size());
    for (size_t i = 0; i < s.size(); ) {
        cp_starts.push_back(i);
        unsigned char c = (unsigned char)s[i];
        if      ((c & 0x80) == 0x00) i += 1;
        else if ((c & 0xE0) == 0xC0) i += 2;
        else if ((c & 0xF0) == 0xE0) i += 3;
        else                          i += 4;
    }
    size_t n = cp_starts.size();
    size_t first_end = (n > 1) ? cp_starts[1] : s.size();
    std::string first(s, 0, first_end);
    if (n <= 6)
        return first + "#####";
    std::string last(s, cp_starts[n - 1]);
    return first + "####" + last;
}

// ─── Thread pool ──────────────────────────────────────────────────────────────

class ThreadPool {
    std::vector<std::thread>        workers_;
    std::queue<std::function<void()>> q_;
    std::mutex                      mu_;
    std::condition_variable         cv_;
    bool                            stop_ = false;
public:
    explicit ThreadPool(size_t n) {
        for (size_t i = 0; i < n; i++) {
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lk(mu_);
                        cv_.wait(lk, [&]{ return stop_ || !q_.empty(); });
                        if (stop_ && q_.empty()) return;
                        task = std::move(q_.front()); q_.pop();
                    }
                    task();
                }
            });
        }
    }
    void submit(std::function<void()> f) {
        { std::lock_guard<std::mutex> lk(mu_); q_.push(std::move(f)); }
        cv_.notify_one();
    }
    ~ThreadPool() {
        { std::lock_guard<std::mutex> lk(mu_); stop_ = true; }
        cv_.notify_all();
        for (auto& w : workers_) w.join();
    }
};

static ThreadPool* g_work_pool = nullptr;
static ThreadPool* g_conn_pool = nullptr;

// ─── Batch timing ─────────────────────────────────────────────────────────────

static std::mutex         g_batch_mu;
static TPoint             g_t_batch_start;
static std::atomic<bool>  g_t_batch_set{false};
static std::atomic<int>   g_req_submitted{0};
static std::atomic<int>   g_req_done{0};

struct ReqStat { double total_ms, encrypt_ms, cb_ms; };
static std::vector<ReqStat> g_req_stats;

static void batch_mark_start() {
    if (g_t_batch_set.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(g_batch_mu);
    if (!g_t_batch_set.load(std::memory_order_relaxed)) {
        g_t_batch_start = tnow();
        g_t_batch_set.store(true, std::memory_order_release);
    }
}
static double batch_wall_ms() {
    if (!g_t_batch_set.load(std::memory_order_acquire)) return 0.0;
    return tms(g_t_batch_start, tnow());
}
static void batch_req_done(double total_ms, double encrypt_ms, double cb_ms) {
    {
        std::lock_guard<std::mutex> lk(g_batch_mu);
        g_req_stats.push_back({total_ms, encrypt_ms, cb_ms});
    }
    int done = ++g_req_done;
    if (g_expect_reqs <= 0 || done != g_expect_reqs) return;

    double wall = batch_wall_ms();
    std::lock_guard<std::mutex> lk(g_batch_mu);
    double s_tot=0, s_enc=0, s_cb=0, mn_tot=1e9, mx_tot=0, mn_enc=1e9, mx_enc=0;
    for (auto& s : g_req_stats) {
        s_tot += s.total_ms;
        if (s.total_ms < mn_tot) mn_tot = s.total_ms;
        if (s.total_ms > mx_tot) mx_tot = s.total_ms;
        s_enc += s.encrypt_ms;
        if (s.encrypt_ms < mn_enc) mn_enc = s.encrypt_ms;
        if (s.encrypt_ms > mx_enc) mx_enc = s.encrypt_ms;
        s_cb  += s.cb_ms;
    }
    int n = (int)g_req_stats.size();
    fprintf(stderr,
        "\n[BATCH] %d/%d done  wall=%.0fms"
        "  | req  avg=%.0f min=%.0f max=%.0f"
        "  | enc  avg=%.0f min=%.0f max=%.0f"
        "  | cb   avg=%.0fms\n\n",
        done, g_expect_reqs, wall,
        s_tot/n, mn_tot, mx_tot,
        s_enc/n, mn_enc, mx_enc,
        s_cb/n);
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

static void write_all(int fd, const char* p, size_t n) {
    while (n > 0) {
        ssize_t w = ::write(fd, p, n);
        if (w <= 0) return;
        p += w; n -= w;
    }
}
static void send_json(int fd, int status, const std::string& body) {
    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d OK\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        status, body.size());
    write_all(fd, hdr, hlen);
    write_all(fd, body.data(), body.size());
}

struct HttpReq { std::string method, path, body; };

static bool read_http(int fd, HttpReq& req) {
    std::string raw;
    raw.reserve(4096);
    char buf[4096];
    size_t hend = std::string::npos;
    while (hend == std::string::npos) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        raw.append(buf, n);
        hend = raw.find("\r\n\r\n");
        if (raw.size() > 131072) return false;
    }
    hend += 4;

    size_t crlf1 = raw.find("\r\n");
    if (crlf1 == std::string::npos) return false;
    std::string rline = raw.substr(0, crlf1);
    size_t sp1 = rline.find(' ');
    size_t sp2 = rline.find(' ', sp1 + 1);
    if (sp1 == std::string::npos) return false;
    req.method = rline.substr(0, sp1);
    req.path   = (sp2 != std::string::npos)
               ? rline.substr(sp1+1, sp2-sp1-1)
               : rline.substr(sp1+1);

    std::string hdrs_lo = raw.substr(0, hend);
    std::transform(hdrs_lo.begin(), hdrs_lo.end(), hdrs_lo.begin(), ::tolower);
    size_t cl = 0;
    size_t clpos = hdrs_lo.find("content-length:");
    if (clpos != std::string::npos) {
        size_t vs = hdrs_lo.find_first_not_of(" \t", clpos + 15);
        if (vs != std::string::npos) cl = std::stoul(hdrs_lo.substr(vs));
    }
    if (cl > 0) {
        size_t already = (raw.size() > hend) ? (raw.size() - hend) : 0;
        req.body.resize(cl);
        if (already > 0)
            memcpy(&req.body[0], raw.data() + hend, std::min(already, cl));
        size_t got = already;
        while (got < cl) {
            ssize_t n = recv(fd, &req.body[got], cl - got, 0);
            if (n <= 0) break;
            got += n;
        }
    }
    return true;
}

// ─── JSON helpers ─────────────────────────────────────────────────────────────

static std::string json_str(const std::string& j, const std::string& key) {
    std::string k = "\"" + key + "\"";
    size_t p = j.find(k);
    if (p == std::string::npos) return {};
    size_t colon = j.find(':', p + k.size());
    if (colon == std::string::npos) return {};
    size_t q1 = j.find('"', colon + 1);
    if (q1 == std::string::npos) return {};
    size_t q2 = j.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    return j.substr(q1 + 1, q2 - q1 - 1);
}
static std::vector<std::string> json_arr(const std::string& j, const std::string& key) {
    std::string k = "\"" + key + "\"";
    size_t p = j.find(k);
    if (p == std::string::npos) return {};
    size_t a1 = j.find('[', p + k.size());
    if (a1 == std::string::npos) return {};
    size_t a2 = j.find(']', a1);
    if (a2 == std::string::npos) return {};
    std::string arr = j.substr(a1 + 1, a2 - a1 - 1);
    std::vector<std::string> res;
    size_t pos = 0;
    while (pos < arr.size()) {
        size_t q1 = arr.find('"', pos);
        if (q1 == std::string::npos) break;
        size_t q2 = arr.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        res.push_back(arr.substr(q1 + 1, q2 - q1 - 1));
        pos = q2 + 1;
    }
    return res;
}

// ─── HTTP POST callback ───────────────────────────────────────────────────────

static bool http_post(const std::string& url, const std::string& body) {
    std::string u = url;
    if (u.rfind("http://", 0) == 0) u = u.substr(7);
    size_t sl = u.find('/');
    std::string hostport = (sl == std::string::npos) ? u : u.substr(0, sl);
    std::string path     = (sl == std::string::npos) ? "/" : u.substr(sl);
    std::string host = hostport;
    int port = 80;
    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        port = std::stoi(hostport.substr(colon + 1));
    }
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string ports = std::to_string(port);
    if (getaddrinfo(host.c_str(), ports.c_str(), &hints, &res) != 0) return false;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv{5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    bool ok = false;
    if (connect(sock, res->ai_addr, res->ai_addrlen) == 0) {
        std::string req =
            "POST " + path + " HTTP/1.0\r\n"
            "Host: " + host + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "\r\n" + body;
        write_all(sock, req.data(), req.size());
        ok = true;
    }
    close(sock);
    freeaddrinfo(res);
    return ok;
}

// ─── AVX2 hex encoder ────────────────────────────────────────────────────────

static inline void hex16_avx2(const uint8_t* __restrict__ src,
                               char*          __restrict__ dst) {
    const __m256i lut  = _mm256_broadcastsi128_si256(
        _mm_set_epi8('F','E','D','C','B','A','9','8',
                     '7','6','5','4','3','2','1','0'));
    const __m256i mask = _mm256_set1_epi8(0x0f);
    __m256i data = _mm256_broadcastsi128_si256(
                       _mm_loadu_si128((const __m128i*)src));
    __m256i hi   = _mm256_and_si256(_mm256_srli_epi16(data, 4), mask);
    __m256i lo   = _mm256_and_si256(data, mask);
    __m256i hi_c = _mm256_shuffle_epi8(lut, hi);
    __m256i lo_c = _mm256_shuffle_epi8(lut, lo);
    __m256i u_lo = _mm256_unpacklo_epi8(hi_c, lo_c);
    __m256i u_hi = _mm256_unpackhi_epi8(hi_c, lo_c);
    _mm256_storeu_si256((__m256i*)dst,
        _mm256_permute2x128_si256(u_lo, u_hi, 0x20));
}
static inline void hex_encode(const uint8_t* __restrict__ src,
                               char*          __restrict__ dst, size_t n) {
    for (size_t i = 0; i < n; i += 16)
        hex16_avx2(src + i, dst + i * 2);
}

// ─── Per-request batch state ──────────────────────────────────────────────────

struct BatchReq {
    std::string request_id;
    std::string ip;
    SM4Ctx      ctx;           // pre-expanded round keys

    int  nfields    = 0;
    int  col[11]    = {};
    bool is_sm4[11] = {};
    int  sm4idx[11] = {};      // SM4 field idx (0-6) or -1
    int  maskidx[11]= {};      // mask idx (0-3) or -1

    // Pre-allocated output buffer.
    // row_offset[r]          = byte offset of row r in out_buf.
    // row_offset[nrows]      = total size.
    // field_out_offset[fi][r] = byte offset of field fi *within* row r
    //                           (relative to row_offset[r], not counting comma/newline).
    std::string              out_buf;
    std::vector<uint32_t>    row_offset;
    std::vector<uint32_t>    field_out_offset[11];

    std::string out_path;
    TPoint      t_req_start;
};

// ─── submit_and_wait helper ───────────────────────────────────────────────────
// Submit `count` tasks fn(0)..fn(count-1) to g_work_pool and block until all
// complete.  Must NOT be called from a g_work_pool thread (would deadlock).

static void submit_and_wait(size_t count, std::function<void(size_t)> fn) {
    if (count == 0) return;
    std::atomic<int>        remaining((int)count);
    std::mutex              m;
    std::condition_variable cv;
    bool                    all_done = false;

    for (size_t i = 0; i < count; i++) {
        g_work_pool->submit([&, i]() {
            fn(i);
            if (--remaining == 0) {
                std::lock_guard<std::mutex> lk(m);
                all_done = true;
                cv.notify_all();
            }
        });
    }
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&]{ return all_done; });
}

// ─── Field-level compute ──────────────────────────────────────────────────────
//
// Instead of compute_rows(req, chunk) [all fields, one request], we now have:
//   compute_field_sm4 (one SM4 field, all mini-batch requests needing it)
//   compute_field_mask (one mask field, all mini-batch requests needing it)
//
// Loop order: row-block OUTER, request INNER.
// → The 32-row plaintext blob chunk (512 B, fits in L1) stays hot for all N
//   request encryptions before advancing to the next 32-row block.

struct FieldReqs {
    BatchReq** reqs;
    const int* fi;     // fi[i] = field position of this field in reqs[i]
    size_t     n;
};

static void compute_field_sm4(
    int sm4idx,
    size_t row_start, size_t row_end,
    const FieldReqs& fr)
{
    if (fr.n == 0 || row_start >= row_end) return;
    const SM4PaddedField& spf = g_sm4_pad[sm4idx];
    constexpr size_t B = 32;
    const size_t full = row_start + ((row_end - row_start) / B) * B;

    alignas(64) uint8_t ct_s[B][64];
    const uint8_t* pt_p[B];
    size_t         ct_l[B];
    uint8_t*       ct_p[B];
    for (size_t b = 0; b < B; b++) ct_p[b] = ct_s[b];

    // ── x32 path: row-block outer, request inner ──────────────────────────────
    for (size_t base_row = row_start; base_row < full; base_row += B) {
        // Load this block's plaintext once — reused for all N requests below
        for (size_t b = 0; b < B; b++) {
            pt_p[b] = spf.blob.data() + spf.offset[base_row + b];
            ct_l[b] = spf.padlen[base_row + b];
        }
        // Encrypt with each request's key (blob chunk stays in L1)
        for (size_t ri = 0; ri < fr.n; ri++) {
            BatchReq* req = fr.reqs[ri];
            int f = fr.fi[ri];
            sm4_cbc_encrypt_x32_nopad(req->ctx, SM4_IV, pt_p, ct_l, ct_p);
            char* base = req->out_buf.data();
            for (size_t b = 0; b < B; b++) {
                if (ct_l[b] == 0) continue;
                size_t r = base_row + b;
                hex_encode(ct_s[b],
                           base + req->row_offset[r] + req->field_out_offset[f][r],
                           ct_l[b]);
            }
        }
    }

    // ── scalar remainder ──────────────────────────────────────────────────────
    for (size_t r = full; r < row_end; r++) {
        const std::string& val = g_cols[SM4IDX_TO_COL[sm4idx]][r];
        for (size_t ri = 0; ri < fr.n; ri++) {
            BatchReq* req = fr.reqs[ri];
            int f = fr.fi[ri];
            uint8_t ct[64];
            size_t cl = sm4_cbc_encrypt_into(req->ctx, SM4_IV,
                (const uint8_t*)val.data(), val.size(), ct);
            hex_encode(ct,
                       req->out_buf.data() + req->row_offset[r] + req->field_out_offset[f][r],
                       cl);
        }
    }
}

static void compute_field_mask(
    int maskidx,
    size_t row_start, size_t row_end,
    const FieldReqs& fr)
{
    if (fr.n == 0 || row_start >= row_end) return;
    // Row outer, request inner: g_masked_col[maskidx][r] stays cache-warm
    for (size_t r = row_start; r < row_end; r++) {
        const std::string& m = g_masked_col[maskidx][r];
        for (size_t ri = 0; ri < fr.n; ri++) {
            BatchReq* req = fr.reqs[ri];
            int f = fr.fi[ri];
            memcpy(req->out_buf.data() + req->row_offset[r] + req->field_out_offset[f][r],
                   m.data(), m.size());
        }
    }
}

// ─── Batch processor ──────────────────────────────────────────────────────────
//
// Processes the collected batch in mini-batches of MINI requests at a time.
//
// Memory budget analysis (300K rows, 7 fields max, 112 MB out_buf/request):
//   Old (all 100 at once): 100 × 112 MB = 11.2 GB  → exceeds 8 GB constraint
//   New (MINI=16 at once): 16  × 112 MB =  1.8 GB  → safe on 7.6 GB machine
//
// Each mini-batch runs the full pipeline (alloc → encrypt → write+callback)
// and frees out_buf immediately after the file is written, before moving on.
// Chunk-first task ordering within each mini-batch preserves L3 cache reuse.

static void process_batch(std::vector<BatchReq*> batch) {
    if (batch.empty()) return;
    auto t_batch = tnow();
    ensure_csv();
    const size_t nrows = g_nrows;

    std::filesystem::create_directories(g_output_dir);

    constexpr size_t MAX_MINI   = 100;   // upper bound for stack arrays
    const size_t MINI       = (size_t)std::max(1, g_mini_batch);
    const size_t CHUNK_SIZE = (size_t)std::max(1, g_chunk_size);
    const size_t n_chunks = (nrows + CHUNK_SIZE - 1) / CHUNK_SIZE;

    for (size_t mb_start = 0; mb_start < batch.size(); mb_start += MINI) {
        size_t     mb_end = std::min(mb_start + MINI, batch.size());
        size_t     mb_sz  = mb_end - mb_start;
        BatchReq** mb     = batch.data() + mb_start;
        auto t_mb = tnow();

        // ── Phase 1: row offsets + field offsets + out_buf alloc ─────────────
        submit_and_wait(mb_sz, [&](size_t i) {
            BatchReq* req = mb[i];
            req->row_offset.resize(nrows + 1);
            for (int fi = 0; fi < req->nfields; fi++)
                req->field_out_offset[fi].resize(nrows);

            // Pass A: compute sizes + field byte offsets within each row
            uint32_t off = 0;
            for (size_t r = 0; r < nrows; r++) {
                req->row_offset[r] = off;
                uint32_t fpos = 0;
                for (int fi = 0; fi < req->nfields; fi++) {
                    if (fi > 0) fpos++;  // comma
                    req->field_out_offset[fi][r] = fpos;
                    fpos += req->is_sm4[fi]
                            ? (uint32_t)g_sm4_pad[req->sm4idx[fi]].padlen[r] * 2u
                            : g_mask_outlen[req->maskidx[fi]][r];
                }
                off += fpos + 1;  // +1 for newline
            }
            req->row_offset[nrows] = off;
            req->out_buf.resize(off);

            // Pass B: fill structural characters (commas + newlines)
            char* buf = req->out_buf.data();
            for (size_t r = 0; r < nrows; r++) {
                char* row = buf + req->row_offset[r];
                for (int fi = 1; fi < req->nfields; fi++)
                    row[req->field_out_offset[fi][r] - 1] = ',';
                row[req->row_offset[r + 1] - req->row_offset[r] - 1] = '\n';
            }
        });

        // ── Phase 2: field-level batch compute ───────────────────────────────
        // Build per-field request lists (field-first = blob stays L1-hot)
        // Arrays sized for max 7 SM4 + 4 mask fields; reqs/fi storage reused.
        BatchReq* sm4_req_buf[7][MAX_MINI];
        int       sm4_fi_buf [7][MAX_MINI];
        size_t    sm4_cnt    [7] = {};
        BatchReq* mask_req_buf[4][MAX_MINI];
        int       mask_fi_buf [4][MAX_MINI];
        size_t    mask_cnt   [4] = {};

        for (size_t i = 0; i < mb_sz; i++) {
            BatchReq* req = mb[i];
            for (int fi = 0; fi < req->nfields; fi++) {
                if (req->is_sm4[fi]) {
                    int s = req->sm4idx[fi];
                    sm4_req_buf[s][sm4_cnt[s]] = req;
                    sm4_fi_buf [s][sm4_cnt[s]] = fi;
                    sm4_cnt[s]++;
                } else {
                    int m = req->maskidx[fi];
                    mask_req_buf[m][mask_cnt[m]] = req;
                    mask_fi_buf [m][mask_cnt[m]] = fi;
                    mask_cnt[m]++;
                }
            }
        }

        // Build task list: field-first, then chunk
        struct FTask { bool is_sm4; int field_idx; size_t rs, re; };
        std::vector<FTask> ftasks;
        ftasks.reserve((7 + 4) * n_chunks);
        for (int f = 0; f < 7; f++) {
            if (!sm4_cnt[f]) continue;
            for (size_t chunk = 0; chunk < n_chunks; chunk++) {
                size_t rs = chunk * CHUNK_SIZE;
                ftasks.push_back({true,  f, rs, std::min(rs + CHUNK_SIZE, nrows)});
            }
        }
        for (int f = 0; f < 4; f++) {
            if (!mask_cnt[f]) continue;
            for (size_t chunk = 0; chunk < n_chunks; chunk++) {
                size_t rs = chunk * CHUNK_SIZE;
                ftasks.push_back({false, f, rs, std::min(rs + CHUNK_SIZE, nrows)});
            }
        }
        submit_and_wait(ftasks.size(), [&](size_t i) {
            const FTask& t = ftasks[i];
            FieldReqs fr;
            if (t.is_sm4) {
                fr = { sm4_req_buf[t.field_idx], sm4_fi_buf[t.field_idx],
                       sm4_cnt[t.field_idx] };
                compute_field_sm4(t.field_idx, t.rs, t.re, fr);
            } else {
                fr = { mask_req_buf[t.field_idx], mask_fi_buf[t.field_idx],
                       mask_cnt[t.field_idx] };
                compute_field_mask(t.field_idx, t.rs, t.re, fr);
            }
        });
        auto t_mb_compute = tnow();

        // ── Phase 3: write files + callbacks, free out_buf immediately ────────
        submit_and_wait(mb_sz, [&](size_t i) {
            BatchReq* req = mb[i];

            FILE* fp = fopen(req->out_path.c_str(), "wb");
            if (fp) {
                fwrite(req->out_buf.data(), 1, req->out_buf.size(), fp);
                fclose(fp);
            }
            // Release output buffer and metadata now — don't wait until batch end
            std::string().swap(req->out_buf);
            std::vector<uint32_t>().swap(req->row_offset);
            for (int fi = 0; fi < req->nfields; fi++)
                std::vector<uint32_t>().swap(req->field_out_offset[fi]);

            double cb_ms = 0.0;
            if (!g_callback_url.empty() && g_callback_url != "skip") {
                auto t_cb0 = tnow();
                std::string cb =
                    "{\"teamCode\":\"" + g_team_code + "\","
                    "\"requestId\":\"" + req->request_id + "\","
                    "\"ip\":\"" + req->ip + "\"}";
                for (int retry = 0; retry < 5; retry++) {
                    if (http_post(g_callback_url, cb)) break;
                    usleep(50000);
                }
                cb_ms = tms(t_cb0, tnow());
            }

            double d_total = tms(req->t_req_start, tnow());
            double d_enc   = tms(t_mb, t_mb_compute);
            double d_wall  = batch_wall_ms();
            int    done    = g_req_done.load() + 1;
            int    subm    = g_req_submitted.load();

            fprintf(stderr,
                "[DONE] %-28s [%3d/%-3d]  req=%7.1fms  wall=%7.1fms"
                "  enc=%6.1f  cb=%5.1f\n",
                req->request_id.c_str(), done, subm,
                d_total, d_wall, d_enc, cb_ms);

            batch_req_done(d_total, d_enc, cb_ms);
        });
    }

    auto t_end = tnow();
    fprintf(stderr,
        "[BATCH_PHASES] n=%zu  total=%.1fms\n",
        batch.size(), tms(t_batch, t_end));

    for (auto* req : batch) delete req;
}

// ─── Batch collector ─────────────────────────────────────────────────────────
//
// Accumulates incoming /encrypt requests until we have g_coord_batch_size of
// them, then fires process_batch(). Also has a 1000 ms flush timeout so that
// small test runs (e.g. verify_sm4.sh, which sends only 1 request) don't wait
// forever for a full batch that never comes.

static std::mutex              g_coord_mu;
static std::vector<BatchReq*>  g_coord_pending;
static int                     g_coord_batch_size = 100;
static TPoint                  g_coord_first_time; // when first req of current batch arrived
static bool                    g_coord_has_timer = false;

// Timeout in ms: if the batch isn't full after this many ms, flush it anyway.
static constexpr double COORD_TIMEOUT_MS = 1000.0;

static void coord_add(BatchReq* req) {
    std::vector<BatchReq*> to_fire;
    {
        std::lock_guard<std::mutex> lk(g_coord_mu);
        if (!g_coord_has_timer) {
            g_coord_first_time = tnow();
            g_coord_has_timer  = true;
        }
        g_coord_pending.push_back(req);
        if ((int)g_coord_pending.size() >= g_coord_batch_size) {
            to_fire = std::move(g_coord_pending);
            g_coord_pending.clear();
            g_coord_has_timer = false;
        }
    }
    if (!to_fire.empty())
        process_batch(std::move(to_fire));
}

// Timer thread: flush pending requests that have been waiting too long.
static void coord_timer_loop() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        std::vector<BatchReq*> to_fire;
        {
            std::lock_guard<std::mutex> lk(g_coord_mu);
            if (g_coord_has_timer && !g_coord_pending.empty()) {
                double elapsed = tms(g_coord_first_time, tnow());
                if (elapsed >= COORD_TIMEOUT_MS) {
                    to_fire = std::move(g_coord_pending);
                    g_coord_pending.clear();
                    g_coord_has_timer = false;
                }
            }
        }
        if (!to_fire.empty())
            process_batch(std::move(to_fire));
    }
}

// ─── Connection handler ───────────────────────────────────────────────────────

static void handle_conn(int fd) {
    HttpReq req;
    if (!read_http(fd, req)) { close(fd); return; }

    if (req.method == "GET" && req.path == "/health") {
        send_json(fd, 200, R"({"returnCode":"SUC0000","body": true,"errorMsg":""})");

    } else if (req.method == "POST" && req.path == "/encrypt") {
        std::string rid    = json_str(req.body, "requestId");
        std::string key    = json_str(req.body, "sm4Key");
        std::string ip     = json_str(req.body, "ip");
        auto        fields = json_arr(req.body, "fieldsToEncrypt");

        batch_mark_start();
        g_req_submitted.fetch_add(1, std::memory_order_relaxed);

        // Send HTTP 200 immediately (before any computation)
        send_json(fd, 200, R"({"returnCode":"SUC0000","body": true,"errorMsg":""})");
        close(fd);
        fd = -1;

        // Build request state (lightweight: parse + key expand only)
        auto* breq = new BatchReq;
        breq->t_req_start = tnow();
        breq->request_id  = rid;
        breq->ip          = ip;
        breq->out_path    = g_output_dir + rid + ".csv";

        bool ok = true;
        for (const auto& f : fields) {
            auto it = FIELDS.find(f);
            if (it == FIELDS.end()) { ok = false; break; }
            int fi = breq->nfields++;
            breq->col[fi]      = it->second.col;
            breq->is_sm4[fi]   = it->second.is_sm4;
            if (it->second.is_sm4) {
                breq->sm4idx[fi]  = COL_TO_SM4IDX[it->second.col];
                breq->maskidx[fi] = -1;
            } else {
                breq->sm4idx[fi]  = -1;
                breq->maskidx[fi] = it->second.col - 4;
            }
        }
        if (!ok) { delete breq; return; }

        uint8_t key16[16] = {};
        memcpy(key16, key.data(), std::min(key.size(), (size_t)16));
        sm4_init(breq->ctx, key16);

        coord_add(breq);

    } else {
        send_json(fd, 404, R"({"returnCode":"ERR0001","body": false,"errorMsg":"not found"})");
    }

    if (fd >= 0) close(fd);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main() {
    auto env = [](const char* k, const char* def) -> std::string {
        const char* v = getenv(k);
        return v ? v : def;
    };

    g_csv_path     = env("DCC_CSV_PATH",    "/dcc/root/table_data.csv");
    g_output_dir   = env("DCC_OUTPUT_DIR",  "/opt/app/dcc/baseline/output/");
    g_team_code    = env("DCC_TEAM_CODE",   "baseline");
    g_callback_url = env("DCC_CALLBACK_URL","http://dcc08-data-encrypt.paas.cmbchina.cn/callback");
    g_debug        = (env("DCC_DEBUG",     "0") == "1");
    g_expect_reqs  = std::stoi(env("DCC_EXPECT_REQS", "100"));
    g_port         = std::stoi(env("DCC_PORT",         "8080"));
    g_workers      = std::stoi(env("DCC_WORKERS",      "0"));
    g_mini_batch   = std::stoi(env("DCC_MINI_BATCH",   "16"));
    g_chunk_size   = std::stoi(env("DCC_CHUNK_SIZE",   "8192"));

    if (!g_output_dir.empty() && g_output_dir.back() != '/')
        g_output_dir += '/';

    signal(SIGPIPE, SIG_IGN);

    unsigned nw = (g_workers > 0)
                  ? (unsigned)g_workers
                  : std::thread::hardware_concurrency();
    if (nw < 1) nw = 1;
    unsigned nc = 64;

    g_coord_batch_size = (g_expect_reqs > 0) ? g_expect_reqs : 100;

    std::cerr << "[INFO] Workers: " << nw << "  Conn pool: " << nc
              << "  BatchSize: " << g_coord_batch_size
              << "  MiniBatch: " << g_mini_batch
              << "  ChunkSize: " << g_chunk_size
              << "  AVX-512: ON"
              << "  CSV: " << g_csv_path
              << "  Out: " << g_output_dir << "\n";

    g_work_pool = new ThreadPool(nw);
    g_conn_pool = new ThreadPool(nc);

    // Batch flush timer (daemon thread — no join needed)
    std::thread(coord_timer_loop).detach();

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt  = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)g_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, 512);
    std::cerr << "[INFO] Listening on :" << g_port << "\n";

    struct timeval conn_tv{10, 0};
    while (true) {
        int fd = accept(srv, nullptr, nullptr);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &conn_tv, sizeof(conn_tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &conn_tv, sizeof(conn_tv));
        g_conn_pool->submit([fd]{ handle_conn(fd); });
    }
    return 0;
}
