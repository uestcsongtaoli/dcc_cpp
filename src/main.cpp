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
static bool        g_profile    = false;   // DCC_PROFILE=1 → per-phase RDTSC breakdown
static int         g_port       = 8080;
static int         g_workers         = 0;   // compute (DCC_WORKERS / DCC_COMPUTE_WORKERS)
static int         g_write_workers   = 16;  // DCC_WRITE_WORKERS
static int         g_cb_workers      = 8;   // DCC_CALLBACK_WORKERS
static int         g_expect_reqs= 100;
static int         g_sm4_mode   = 16;      // DCC_SM4_MODE: 0=scalar, 16=x16 (default), 32=x32

// ─── Compute profiling (DCC_PROFILE=1) ────────────────────────────────────────
//
// Per-section RDTSC cycle counts, accumulated from all compute threads.
// Reported as percentages at end of [BATCH_PHASES].  Zero overhead when
// g_profile == false (all RDTSC calls are inside "if (g_profile)" branches
// that are perfectly branch-predicted as not-taken).

static inline uint64_t rdtsc() { return __builtin_ia32_rdtsc(); }

static std::atomic<uint64_t> g_cyc_sm4{0};    // inside sm4_cbc_encrypt_x*_nopad
static std::atomic<uint64_t> g_cyc_hex{0};    // inside hex_encode loop
static std::atomic<uint64_t> g_cyc_mask{0};   // inside mask memcpy loop
static std::atomic<uint64_t> g_cyc_other{0};  // everything else in compute_rows

static void profile_reset() {
    g_cyc_sm4.store(0); g_cyc_hex.store(0);
    g_cyc_mask.store(0); g_cyc_other.store(0);
}
static void profile_log(double wall_ms) {
    uint64_t sm4  = g_cyc_sm4.load();
    uint64_t hex  = g_cyc_hex.load();
    uint64_t mask = g_cyc_mask.load();
    uint64_t oth  = g_cyc_other.load();
    uint64_t tot  = sm4 + hex + mask + oth;
    if (tot == 0) return;
    auto pct = [&](uint64_t v) { return v * 100.0 / tot; };
    fprintf(stderr,
        "[PROFILE] wall=%.0fms  SM4=%.1f%%  hex=%.1f%%  mask=%.1f%%  other=%.1f%%"
        "  (cyc: sm4=%zu hex=%zu mask=%zu oth=%zu)\n",
        wall_ms, pct(sm4), pct(hex), pct(mask), pct(oth),
        (size_t)sm4, (size_t)hex, (size_t)mask, (size_t)oth);
}

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

// Fixed hex/mask output lengths per field (0 = variable; set in load_csv).
// g_sm4_hex_fixed[f] = hex chars per row for SM4 field f; 0 if row-varies.
// g_mask_len_fixed[m] = mask bytes per row for mask field m; 0 if row-varies.
static uint16_t g_sm4_hex_fixed[7] = {};
static uint16_t g_mask_len_fixed[4] = {};

// Prefix sums for variable-output fields (size nrows+1; entry[0]=0).
// g_bkey_prefix[r] = Σ_{s<r}  padlen[s]*2   (business_key hex chars, sm4idx=3)
// g_name_prefix[r] = Σ_{s<r}  mask_outlen[s] (name mask bytes, maskidx=2)
static std::vector<uint32_t> g_bkey_prefix;
static std::vector<uint32_t> g_name_prefix;

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

    // ── Step 4: fixed vs variable output lengths + prefix sums ───────────────
    //
    // Determine which SM4/mask fields have a fixed output length for all rows.
    // Build prefix-sum arrays for the variable ones (business_key, name).
    // These arrays are used in process_batch Phase 1 to compute total output
    // sizes in O(1) per request, replacing the old 300K-row per-request scan.
    for (int f = 0; f < 7; f++) {
        uint16_t pl0 = g_sm4_pad[f].padlen[0];
        bool is_fixed = true;
        for (size_t r = 1; r < g_nrows && is_fixed; r++)
            if (g_sm4_pad[f].padlen[r] != pl0) is_fixed = false;
        g_sm4_hex_fixed[f] = is_fixed ? (uint16_t)(pl0 * 2u) : 0u;
    }
    for (int m = 0; m < 4; m++) {
        uint16_t l0 = g_mask_outlen[m][0];
        bool is_fixed = true;
        for (size_t r = 1; r < g_nrows && is_fixed; r++)
            if (g_mask_outlen[m][r] != l0) is_fixed = false;
        g_mask_len_fixed[m] = is_fixed ? l0 : 0u;
    }
    // business_key (sm4idx=3): variable padlen → build hex-char prefix sum
    if (g_sm4_hex_fixed[3] == 0) {
        g_bkey_prefix.resize(g_nrows + 1, 0u);
        for (size_t r = 0; r < g_nrows; r++)
            g_bkey_prefix[r + 1] = g_bkey_prefix[r] + (uint32_t)g_sm4_pad[3].padlen[r] * 2u;
    }
    // name (maskidx=2): variable mask length → build mask-byte prefix sum
    if (g_mask_len_fixed[2] == 0) {
        g_name_prefix.resize(g_nrows + 1, 0u);
        for (size_t r = 0; r < g_nrows; r++)
            g_name_prefix[r + 1] = g_name_prefix[r] + g_mask_outlen[2][r];
    }
    auto t5 = tnow();

    fprintf(stderr,
        "[INFO] CSV loaded: %zu rows"
        " | open=%.1fms  parse=%.1fms  mask_pre=%.1fms  pad_pre=%.1fms"
        "  prefix=%.1fms  total=%.1fms\n"
        "[INFO] Field fixedness:"
        "  sm4=[%d,%d,%d,%d,%d,%d,%d]hex"
        "  mask=[%d,%d,%d,%d]B\n",
        g_nrows, tms(t0,t1), tms(t1,t2), tms(t2,t3), tms(t3,t4),
        tms(t4,t5), tms(t0,t5),
        g_sm4_hex_fixed[0], g_sm4_hex_fixed[1], g_sm4_hex_fixed[2], g_sm4_hex_fixed[3],
        g_sm4_hex_fixed[4], g_sm4_hex_fixed[5], g_sm4_hex_fixed[6],
        g_mask_len_fixed[0], g_mask_len_fixed[1], g_mask_len_fixed[2], g_mask_len_fixed[3]);
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

static ThreadPool* g_compute_pool = nullptr;  // CPU-bound SM4/mask
static ThreadPool* g_write_pool   = nullptr;  // file I/O
static ThreadPool* g_cb_pool      = nullptr;  // HTTP callbacks
static ThreadPool* g_conn_pool    = nullptr;  // incoming connections

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

    // Output layout metadata (replaces per-request 300K-row scan).
    // fixed_row_bytes = bytes contributed per row by fixed-size fields + commas + newline.
    // has_bkey / has_name = whether the variable-output fields are selected.
    // Write position for row r: r*fixed_row_bytes + g_bkey_prefix[r] + g_name_prefix[r]
    //   (prefix terms added only when the corresponding flag is set).
    uint32_t fixed_row_bytes = 0;
    bool     has_bkey = false;   // business_key selected (variable padlen)
    bool     has_name = false;   // name selected (variable mask len)

    std::string out_buf;         // output buffer; allocated in Phase 1

    std::string out_path;
    TPoint      t_req_start;
};

// ─── submit_and_wait helper ───────────────────────────────────────────────────
// Submit `count` tasks fn(0)..fn(count-1) to g_compute_pool and block until all
// complete.  Must NOT be called from a g_compute_pool thread (would deadlock).

static void submit_and_wait(size_t count, std::function<void(size_t)> fn) {
    if (count == 0) return;
    std::atomic<int>        remaining((int)count);
    std::mutex              m;
    std::condition_variable cv;
    bool                    all_done = false;

    for (size_t i = 0; i < count; i++) {
        g_compute_pool->submit([&, i]() {
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

// ─── Per-request row-range compute ───────────────────────────────────────────
//
// g_sm4_mode selects the SIMD width for the hot AVX-512 path:
//   0  = pure scalar (baseline / regression check)
//  16  = x16 (default): 16 rows per SM4 batch (one ZMM group)
//  32  = x32: 32 rows per SM4 batch (two interleaved ZMM groups to hide gather latency)
//
// g_profile=true: accumulates RDTSC cycle counts per section into global atomics.
// g_profile=false: the RDTSC calls are inside never-taken "if (g_profile)" branches
// → zero throughput overhead (branch predictor saturates immediately).

static void compute_rows(BatchReq* req, size_t row_start, size_t row_end) {
    if (row_start >= row_end) return;

    char* base = req->out_buf.data();

    // O(1) row-start position using pre-built prefix sums (no row_offset array).
    const uint32_t  fixed_rbs = req->fixed_row_bytes;
    const uint32_t* bkey_pfx  = req->has_bkey ? g_bkey_prefix.data() : nullptr;
    const uint32_t* name_pfx  = req->has_name ? g_name_prefix.data() : nullptr;
    auto row_pos = [&](size_t r) -> uint32_t {
        uint32_t pos = (uint32_t)r * fixed_rbs;
        if (bkey_pfx) pos += bkey_pfx[r];
        if (name_pfx) pos += name_pfx[r];
        return pos;
    };

    // Thread-local profiling accumulators.  Flushed to globals at end.
    uint64_t p_sm4 = 0, p_hex = 0, p_mask = 0, p_other = 0;

    // ── x32 path (B=32, two interleaved ZMM groups) ───────────────────────────
    if (g_sm4_mode == 32) {
        constexpr size_t B = 32;
        alignas(64) uint8_t ct_s[B][64];
        const uint8_t* pt_p[B];
        size_t         ct_l[B];
        uint8_t*       ct_p[B];
        for (size_t b = 0; b < B; b++) ct_p[b] = ct_s[b];

        const size_t full32 = row_start + ((row_end - row_start) / B) * B;

        for (size_t base_row = row_start; base_row < full32; base_row += B) {
            char* wp[B];
            uint64_t t0, t1;
            if (g_profile) t0 = rdtsc();
            for (size_t b = 0; b < B; b++)
                wp[b] = base + row_pos(base_row + b);
            if (g_profile) { t1 = rdtsc(); p_other += t1 - t0; }

            for (int fi = 0; fi < req->nfields; fi++) {
                if (fi > 0)
                    for (size_t b = 0; b < B; b++) *wp[b]++ = ',';

                if (req->is_sm4[fi]) {
                    int sidx = req->sm4idx[fi];
                    const SM4PaddedField& spf = g_sm4_pad[sidx];
                    for (size_t b = 0; b < B; b++) {
                        size_t r = base_row + b;
                        pt_p[b] = spf.blob.data() + spf.offset[r];
                        ct_l[b] = spf.padlen[r];
                    }
                    if (g_profile) t0 = rdtsc();
                    sm4_cbc_encrypt_x32_nopad(req->ctx, SM4_IV, pt_p, ct_l, ct_p);
                    if (g_profile) { t1 = rdtsc(); p_sm4 += t1 - t0; t0 = t1; }
                    for (size_t b = 0; b < B; b++) {
                        if (ct_l[b] == 0) continue;
                        hex_encode(ct_s[b], wp[b], ct_l[b]);
                        wp[b] += ct_l[b] * 2;
                    }
                    if (g_profile) { t1 = rdtsc(); p_hex += t1 - t0; }
                } else {
                    int midx = req->maskidx[fi];
                    if (g_profile) t0 = rdtsc();
                    for (size_t b = 0; b < B; b++) {
                        size_t r = base_row + b;
                        const std::string& m = g_masked_col[midx][r];
                        memcpy(wp[b], m.data(), m.size());
                        wp[b] += m.size();
                    }
                    if (g_profile) { t1 = rdtsc(); p_mask += t1 - t0; }
                }
            }
            for (size_t b = 0; b < B; b++) *wp[b] = '\n';
        }
        // Remainder handled by the x16 loop below (fall through).
        row_start = full32;
    }

    // ── x16 AVX-512 path (default) ───────────────────────────────────────────
    if (g_sm4_mode >= 16) {
        constexpr size_t B = 16;
        alignas(64) uint8_t ct_s[B][64];
        const uint8_t* pt_p[B];
        size_t         ct_l[B];
        uint8_t*       ct_p[B];
        for (size_t b = 0; b < B; b++) ct_p[b] = ct_s[b];

        const size_t full = row_start + ((row_end - row_start) / B) * B;

        for (size_t base_row = row_start; base_row < full; base_row += B) {
            char* wp[B];
            uint64_t t0, t1;
            if (g_profile) t0 = rdtsc();
            for (size_t b = 0; b < B; b++)
                wp[b] = base + row_pos(base_row + b);
            if (g_profile) { t1 = rdtsc(); p_other += t1 - t0; }

            for (int fi = 0; fi < req->nfields; fi++) {
                if (fi > 0)
                    for (size_t b = 0; b < B; b++) *wp[b]++ = ',';

                if (req->is_sm4[fi]) {
                    int sidx = req->sm4idx[fi];
                    const SM4PaddedField& spf = g_sm4_pad[sidx];
                    for (size_t b = 0; b < B; b++) {
                        size_t r = base_row + b;
                        pt_p[b] = spf.blob.data() + spf.offset[r];
                        ct_l[b] = spf.padlen[r];
                    }
                    if (g_profile) t0 = rdtsc();
                    sm4_cbc_encrypt_x16_nopad(req->ctx, SM4_IV, pt_p, ct_l, ct_p);
                    if (g_profile) { t1 = rdtsc(); p_sm4 += t1 - t0; t0 = t1; }
                    for (size_t b = 0; b < B; b++) {
                        if (ct_l[b] == 0) continue;
                        hex_encode(ct_s[b], wp[b], ct_l[b]);
                        wp[b] += ct_l[b] * 2;
                    }
                    if (g_profile) { t1 = rdtsc(); p_hex += t1 - t0; }
                } else {
                    int midx = req->maskidx[fi];
                    if (g_profile) t0 = rdtsc();
                    for (size_t b = 0; b < B; b++) {
                        size_t r = base_row + b;
                        const std::string& m = g_masked_col[midx][r];
                        memcpy(wp[b], m.data(), m.size());
                        wp[b] += m.size();
                    }
                    if (g_profile) { t1 = rdtsc(); p_mask += t1 - t0; }
                }
            }
            for (size_t b = 0; b < B; b++) *wp[b] = '\n';
        }
        row_start = full;
    }

    // ── scalar remainder (last <16 rows, also handles g_sm4_mode==0 entirely) ─
    for (size_t r = row_start; r < row_end; r++) {
        char* p = base + row_pos(r);
        uint64_t t0, t1;
        for (int fi = 0; fi < req->nfields; fi++) {
            if (fi > 0) *p++ = ',';
            if (req->is_sm4[fi]) {
                int sidx = req->sm4idx[fi];
                const std::string& val = g_cols[SM4IDX_TO_COL[sidx]][r];
                if (!val.empty()) {
                    uint8_t ct[64];
                    if (g_profile) t0 = rdtsc();
                    size_t cl = sm4_cbc_encrypt_into(req->ctx, SM4_IV,
                        (const uint8_t*)val.data(), val.size(), ct);
                    if (g_profile) { t1 = rdtsc(); p_sm4 += t1 - t0; t0 = t1; }
                    hex_encode(ct, p, cl);
                    if (g_profile) { t1 = rdtsc(); p_hex += t1 - t0; }
                    p += cl * 2;
                }
            } else {
                int midx = req->maskidx[fi];
                const std::string& m = g_masked_col[midx][r];
                if (g_profile) t0 = rdtsc();
                memcpy(p, m.data(), m.size());
                if (g_profile) { t1 = rdtsc(); p_mask += t1 - t0; }
                p += m.size();
            }
        }
        *p = '\n';
    }

    // Flush thread-local accumulators to globals (relaxed: ordering doesn't matter).
    if (g_profile) {
        g_cyc_sm4.fetch_add(p_sm4,   std::memory_order_relaxed);
        g_cyc_hex.fetch_add(p_hex,   std::memory_order_relaxed);
        g_cyc_mask.fetch_add(p_mask, std::memory_order_relaxed);
        g_cyc_other.fetch_add(p_other, std::memory_order_relaxed);
    }
}

// ─── Batch processor ──────────────────────────────────────────────────────────
//
// Called ONCE per batch from a conn-pool thread (never g_compute_pool).
//
// Phase 1: parallel O(1) size computation + out_buf allocation.
// Phase 2: encrypt+mask all rows, chunk-first task ordering for L3 cache reuse.
// Phase 3: write output files + callbacks.

static void process_batch(std::vector<BatchReq*> batch) {
    if (batch.empty()) return;
    auto t_batch = tnow();
    const size_t nrows = g_nrows;
    ensure_csv();

    // ── Phase 1: O(1) size computation + output buffer allocation ─────────────
    //
    // Most SM4 fields have a fixed padlen for all rows (user_id, serial_no,
    // user_code, device_id, trans_id, secret_code).  business_key is the only
    // SM4 field with variable padlen.  Mask fields id_card, phone, email produce
    // a fixed-length output; only name varies.
    //
    // g_sm4_hex_fixed[f] and g_mask_len_fixed[m] are set in load_csv.
    // g_bkey_prefix / g_name_prefix are their cumulative sums (size nrows+1).
    //
    // Per-request total size = nrows*fixed_row_bytes
    //                        + g_bkey_prefix[nrows]  (if business_key selected)
    //                        + g_name_prefix[nrows]  (if name selected)
    // No 300K-row loop needed.  Page faults from resize() happen here in Phase 1
    // (parallelized across compute workers) rather than lazily in Phase 2.
    submit_and_wait(batch.size(), [&](size_t i) {
        BatchReq* req = batch[i];

        // Count fixed output bytes per row: commas + newline + fixed-field output.
        uint32_t fixed = 1;  // newline
        for (int fi = 0; fi < req->nfields; fi++) {
            if (fi > 0) fixed++;          // comma separator
            if (req->is_sm4[fi]) {
                uint16_t h = g_sm4_hex_fixed[req->sm4idx[fi]];
                if (h)   fixed += h;
                else     req->has_bkey = true;  // sm4idx==3: business_key
            } else {
                uint16_t m = g_mask_len_fixed[req->maskidx[fi]];
                if (m)   fixed += m;
                else     req->has_name = true;  // maskidx==2: name
            }
        }
        req->fixed_row_bytes = fixed;

        // O(1) total output size via global prefix sums.
        uint32_t total = (uint32_t)nrows * fixed;
        if (req->has_bkey) total += g_bkey_prefix[nrows];
        if (req->has_name) total += g_name_prefix[nrows];

        // Allocate.  std::string::resize zero-inits → page faults triggered here,
        // parallelized across all compute workers, not serialized in Phase 2.
        req->out_buf.resize(total);
    });
    auto t_alloc = tnow();

    // ── Phase 2: encrypt + mask, chunk-first task order ───────────────────────
    //
    // Chunk-first order: all 100 tasks for chunk 0 are submitted before chunk 1.
    // Workers processing the same row range across different requests share the
    // same column slice in L3 cache → avoids redundant cache-line loads.
    //
    // CHUNK_SIZE = 8192: one request's working set per task ≈
    //   8192 rows × avg 3.5 SM4 fields × 16 bytes/padlen ≈ 458 KB → L2/L3 warm.

    constexpr size_t CHUNK_SIZE = 8192;
    const size_t n_chunks = (nrows + CHUNK_SIZE - 1) / CHUNK_SIZE;

    struct CTask { BatchReq* req; size_t rs, re; };
    std::vector<CTask> ctasks;
    ctasks.reserve(n_chunks * batch.size());
    for (size_t chunk = 0; chunk < n_chunks; chunk++) {
        size_t rs = chunk * CHUNK_SIZE;
        size_t re = std::min(rs + CHUNK_SIZE, nrows);
        for (auto* req : batch)
            ctasks.push_back({req, rs, re});
    }
    if (g_profile) profile_reset();
    submit_and_wait(ctasks.size(), [&](size_t i) {
        compute_rows(ctasks[i].req, ctasks[i].rs, ctasks[i].re);
    });
    auto t_compute = tnow();
    if (g_profile) profile_log(tms(t_alloc, t_compute));

    // ── Phase 3: write → callback pipeline (write_pool → cb_pool) ───────────
    //
    // compute_pool is NOT used here: write_pool handles fwrite, cb_pool handles
    // HTTP POSTs.  Both are independent of compute so the next batch (if any)
    // can start compute immediately while I/O and network calls drain.
    //
    // process_batch blocks on ph3_remaining so batch lifetime and [BATCH_PHASES]
    // logging remain correct; the blocking happens on a conn-pool thread (not a
    // compute thread), so there is no deadlock risk.
    std::filesystem::create_directories(g_output_dir);

    std::atomic<int>        ph3_remaining((int)batch.size());
    std::mutex              ph3_mu;
    std::condition_variable ph3_cv;

    for (size_t i = 0; i < batch.size(); i++) {
        g_write_pool->submit([&, i]() {
            BatchReq* req = batch[i];

            FILE* fp = fopen(req->out_path.c_str(), "wb");
            if (fp) {
                fwrite(req->out_buf.data(), 1, req->out_buf.size(), fp);
                fclose(fp);
            }
            double d_wr = tms(t_compute, tnow());

            // After write completes, hand off to cb_pool.
            // Capture req and d_wr by value (local to this lambda frame).
            // t_batch / t_compute / ph3_* captured by ref from process_batch
            // scope — safe because process_batch blocks until ph3_remaining==0.
            g_cb_pool->submit([&, req, d_wr]() {
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
                double d_enc   = tms(t_batch, t_compute);
                double d_wall  = batch_wall_ms();
                int    subm    = g_req_submitted.load();

                batch_req_done(d_total, d_enc, cb_ms);
                int done = g_req_done.load();

                fprintf(stderr,
                    "[DONE] %-28s [%3d/%-3d]  req=%7.1fms  wall=%7.1fms"
                    "  enc=%6.1f  wr=%5.2f  cb=%5.1f\n",
                    req->request_id.c_str(), done, subm,
                    d_total, d_wall, d_enc, d_wr, cb_ms);

                if (--ph3_remaining == 0) {
                    std::lock_guard<std::mutex> lk(ph3_mu);
                    ph3_cv.notify_all();
                }
            });
        });
    }

    // Block until every write+callback in this batch has completed.
    {
        std::unique_lock<std::mutex> lk(ph3_mu);
        ph3_cv.wait(lk, [&]{ return ph3_remaining.load() == 0; });
    }

    auto t_end = tnow();
    fprintf(stderr,
        "[BATCH_PHASES] n=%zu  alloc=%.1fms  compute=%.1fms  output=%.1fms  total=%.1fms\n",
        batch.size(),
        tms(t_batch, t_alloc), tms(t_alloc, t_compute),
        tms(t_compute, t_end), tms(t_batch, t_end));

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
    g_debug        = (env("DCC_DEBUG",   "0") == "1");
    g_profile      = (env("DCC_PROFILE", "0") == "1");
    g_sm4_mode     = std::stoi(env("DCC_SM4_MODE", "16"));  // 0=scalar 16=x16 32=x32
    g_expect_reqs  = std::stoi(env("DCC_EXPECT_REQS", "100"));
    g_port         = std::stoi(env("DCC_PORT",         "8080"));
    // DCC_COMPUTE_WORKERS takes priority; DCC_WORKERS kept for backward compat.
    {
        const char* cw = getenv("DCC_COMPUTE_WORKERS");
        g_workers = std::stoi(cw ? cw : env("DCC_WORKERS", "0"));
    }
    g_write_workers = std::stoi(env("DCC_WRITE_WORKERS",    "16"));
    g_cb_workers    = std::stoi(env("DCC_CALLBACK_WORKERS", "8"));

    if (!g_output_dir.empty() && g_output_dir.back() != '/')
        g_output_dir += '/';

    signal(SIGPIPE, SIG_IGN);

    unsigned ncompute = (g_workers > 0)
                        ? (unsigned)g_workers
                        : std::thread::hardware_concurrency();
    if (ncompute < 1) ncompute = 1;
    if (g_write_workers  < 1) g_write_workers  = 1;
    if (g_cb_workers     < 1) g_cb_workers     = 1;
    unsigned nc = 64;

    g_coord_batch_size = (g_expect_reqs > 0) ? g_expect_reqs : 100;

    std::cerr << "[INFO] Compute: " << ncompute
              << "  Write: "   << g_write_workers
              << "  CB: "      << g_cb_workers
              << "  Conn: "    << nc
              << "  BatchSize: " << g_coord_batch_size
              << "  SM4mode: x" << g_sm4_mode
              << (g_profile ? "  PROFILE:ON" : "")
              << "  CSV: " << g_csv_path
              << "  Out: " << g_output_dir << "\n";

    g_compute_pool = new ThreadPool(ncompute);
    g_write_pool   = new ThreadPool((unsigned)g_write_workers);
    g_cb_pool      = new ThreadPool((unsigned)g_cb_workers);
    g_conn_pool    = new ThreadPool(nc);

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
