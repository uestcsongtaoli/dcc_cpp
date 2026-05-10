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
#include "sm4.h"
#include "sm4_avx512.h"

// ─── Config (set via env vars) ────────────────────────────────────────────────

static std::string g_csv_path;
static std::string g_output_dir;
static std::string g_team_code;
static std::string g_callback_url;
static bool        g_debug      = false;  // DCC_DEBUG=1 to enable
static bool        g_avx512_ok  = false;  // set at startup by cpu_has_avx512f()

// ─── Timing helpers ───────────────────────────────────────────────────────────

using TClock = std::chrono::steady_clock;
using TPoint = TClock::time_point;

static inline TPoint tnow() { return TClock::now(); }

static inline double tms(TPoint a, TPoint b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

// TLOG: only emits when DCC_DEBUG=1; zero overhead in release mode
#define TLOG(fmt, ...) \
    do { if (g_debug) { fprintf(stderr, "[T] " fmt "\n", ##__VA_ARGS__); } } while(0)

// Fixed IV from baseline: "1234567890123456" as ASCII bytes
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

// ─── CSV data cache ───────────────────────────────────────────────────────────

static std::vector<std::vector<std::string>> g_rows;
static std::atomic<bool> g_csv_ready{false};
static std::mutex g_csv_mu;

// Permanent empty string — avoids dangling reference to temporaries.
static const std::string g_empty_str;

// Precomputed mask results for the 4 mask columns (computed once at CSV load).
// Index mapping: id_card(col4)→0, phone(col5)→1, name(col6)→2, email(col7)→3
// All 100 concurrent requests read this read-only data without any locking.
static std::vector<std::string> g_masked_col[4];

static std::string mask(const std::string& s);  // forward decl; defined below

static std::vector<std::string> parse_line(const std::string& line) {
    std::vector<std::string> cols;
    std::string f;
    f.reserve(32);
    for (unsigned char c : line) {
        if (c == ',') { cols.push_back(f); f.clear(); }
        else if (c != '\r') f += (char)c;
    }
    cols.push_back(f);
    return cols;
}

static void load_csv() {
    auto t0 = tnow();
    std::ifstream ifs(g_csv_path);
    if (!ifs) throw std::runtime_error("Cannot open: " + g_csv_path);

    std::string line;
    std::getline(ifs, line); // skip header

    auto t1 = tnow();
    while (std::getline(ifs, line)) {
        if (!line.empty())
            g_rows.push_back(parse_line(line));
    }
    auto t2 = tnow();

    // Precompute mask() for all 4 mask columns.
    // id_card=col4→idx0, phone=col5→idx1, name=col6→idx2, email=col7→idx3
    for (int m = 0; m < 4; m++) {
        int col = m + 4;
        g_masked_col[m].reserve(g_rows.size());
        for (const auto& row : g_rows)
            g_masked_col[m].push_back(col < (int)row.size() ? mask(row[col]) : std::string{});
    }
    auto t3 = tnow();

    fprintf(stderr,
        "[INFO] CSV loaded: %zu rows"
        " | open=%.1fms  parse=%.1fms  mask_pre=%.1fms  total=%.1fms\n",
        g_rows.size(), tms(t0, t1), tms(t1, t2), tms(t2, t3), tms(t0, t3));
}

static void ensure_csv() {
    if (g_csv_ready.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(g_csv_mu);
    if (g_csv_ready.load(std::memory_order_relaxed)) return;
    load_csv();
    g_csv_ready.store(true, std::memory_order_release);
}

// ─── Mask ─────────────────────────────────────────────────────────────────────
// Java uses UTF-16 length() which equals Unicode code points for BMP chars
// (covers all common CJK). We count UTF-8 code points same way.

static std::string mask(const std::string& s) {
    if (s.empty()) return s;

    // Collect byte offset of each Unicode code point
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

    // first char: bytes [cp_starts[0], cp_starts[1])
    size_t first_end = (n > 1) ? cp_starts[1] : s.size();
    std::string first(s, 0, first_end);

    if (n <= 6) {
        return first + "#####";
    } else {
        std::string last(s, cp_starts[n - 1]);
        return first + "####" + last;
    }
}

// ─── Thread pool ──────────────────────────────────────────────────────────────

class ThreadPool {
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> q_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_ = false;
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

// ─── Batch timing & aggregate stats ──────────────────────────────────────────

static int                g_expect_reqs = 100;   // DCC_EXPECT_REQS (0 = disable summary)
static std::atomic<int>   g_req_submitted{0};
static std::atomic<int>   g_req_done{0};

static std::mutex         g_batch_mu;
static TPoint             g_t_batch_start;        // time first /encrypt was received
static std::atomic<bool>  g_t_batch_set{false};

struct ReqStat { double total_ms, encrypt_ms, cb_ms; };
static std::vector<ReqStat> g_req_stats;          // guarded by g_batch_mu

// Record the start of the batch (first /encrypt call).
// Double-checked locking — same pattern as ensure_csv().
static void batch_mark_start() {
    if (g_t_batch_set.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(g_batch_mu);
    if (!g_t_batch_set.load(std::memory_order_relaxed)) {
        g_t_batch_start = tnow();
        g_t_batch_set.store(true, std::memory_order_release);
    }
}

// Elapsed ms since the first /encrypt request (the metric the competition scores).
static double batch_wall_ms() {
    if (!g_t_batch_set.load(std::memory_order_acquire)) return 0.0;
    return tms(g_t_batch_start, tnow());
}

// Called at the end of every do_encrypt().
// Collects stats, increments done counter, prints [BATCH] when all finish.
static void batch_req_done(double total_ms, double encrypt_ms, double cb_ms) {
    {
        std::lock_guard<std::mutex> lk(g_batch_mu);
        g_req_stats.push_back({total_ms, encrypt_ms, cb_ms});
    }
    int done = ++g_req_done;
    if (g_expect_reqs <= 0 || done != g_expect_reqs) return;

    // All expected requests finished — print aggregate summary.
    double wall = batch_wall_ms();
    std::lock_guard<std::mutex> lk(g_batch_mu);
    double s_tot=0, s_enc=0, s_cb=0;
    double mn_tot=1e9, mx_tot=0, mn_enc=1e9, mx_enc=0;
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
        "\n[BATCH] %d/%d done"
        "  wall=%.0fms"
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

// ─── HTTP request reader ──────────────────────────────────────────────────────

struct HttpReq { std::string method, path, body; };

static bool read_http(int fd, HttpReq& req) {
    // Read until \r\n\r\n (end of headers)
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
    hend += 4; // skip \r\n\r\n

    // Parse request line
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

    // Find Content-Length (case-insensitive)
    std::string hdrs = raw.substr(0, hend);
    std::string hdrs_lo = hdrs;
    std::transform(hdrs_lo.begin(), hdrs_lo.end(), hdrs_lo.begin(), ::tolower);

    size_t cl = 0;
    size_t clpos = hdrs_lo.find("content-length:");
    if (clpos != std::string::npos) {
        size_t vs = hdrs_lo.find_first_not_of(" \t", clpos + 15);
        if (vs != std::string::npos)
            cl = std::stoul(hdrs_lo.substr(vs));
    }

    if (cl > 0) {
        // Some body bytes may already be in raw
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

// ─── JSON helpers (minimal, no external dep) ──────────────────────────────────

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
    // Parse http://host[:port]/path
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

// ─── Encrypt job ─────────────────────────────────────────────────────────────

static void do_encrypt(std::string requestId, std::string ip,
                        std::string sm4Key, std::vector<std::string> fields) {
    auto t_start = tnow();
    try {
        // ── 1. CSV ready ───────────────────────────────────────────────────
        ensure_csv();
        auto t_csv = tnow();
        TLOG("%-32s  csv_wait=%6.1fms", requestId.c_str(), tms(t_start, t_csv));

        // ── 2. SM4 key schedule ────────────────────────────────────────────
        SM4Ctx ctx;
        uint8_t key16[16] = {};
        size_t klen = std::min(sm4Key.size(), (size_t)16);
        memcpy(key16, sm4Key.data(), klen);
        sm4_init(ctx, key16);
        auto t_init = tnow();
        TLOG("%-32s  sm4_init=%6.3fms", requestId.c_str(), tms(t_csv, t_init));

        // ── 3. Resolve fields ──────────────────────────────────────────────
        std::vector<FieldInfo> finfos;
        finfos.reserve(fields.size());
        for (const auto& f : fields) {
            auto it = FIELDS.find(f);
            if (it == FIELDS.end())
                throw std::runtime_error("Unknown field: " + f);
            finfos.push_back(it->second);
        }

        // ── 4. Open output file ────────────────────────────────────────────
        std::filesystem::create_directories(g_output_dir);
        std::string outpath = g_output_dir + requestId + ".csv";
        std::ofstream ofs(outpath, std::ios::binary);
        if (!ofs) throw std::runtime_error("Cannot write: " + outpath);
        auto t_open = tnow();
        TLOG("%-32s  file_open=%6.2fms", requestId.c_str(), tms(t_init, t_open));

        // ── 5. Encrypt rows ────────────────────────────────────────────────
        static const char HEX[] = "0123456789ABCDEF";
        const size_t nrows = g_rows.size();

        // Shared scalar helper: build one complete output line for row_idx.
        auto scalar_row = [&](std::string& ln, size_t row_idx) {
            uint8_t ct_buf[64];
            const auto& row = g_rows[row_idx];
            ln.clear();
            for (size_t fi_i = 0; fi_i < finfos.size(); ++fi_i) {
                if (fi_i > 0) ln += ',';
                const auto& fi = finfos[fi_i];
                if (fi.is_sm4) {
                    const std::string& val =
                        (fi.col < (int)row.size()) ? row[fi.col] : g_empty_str;
                    if (!val.empty()) {
                        size_t cl = sm4_cbc_encrypt_into(ctx, SM4_IV,
                                        (const uint8_t*)val.data(), val.size(), ct_buf);
                        size_t s = ln.size();
                        ln.resize(s + cl * 2);
                        for (size_t k = 0; k < cl; ++k) {
                            ln[s + k*2]   = HEX[ct_buf[k] >> 4];
                            ln[s + k*2+1] = HEX[ct_buf[k] & 0xf];
                        }
                    }
                } else {
                    ln += g_masked_col[fi.col - 4][row_idx];
                }
            }
            ln += '\n';
        };

        if (g_avx512_ok) {
            // ── AVX-512 path: process 16 rows at a time ────────────────────
            // For each SM4 field, gather 16 field values and encrypt them in
            // parallel with sm4_cbc_encrypt_x16 (16 independent CBC chains,
            // same key+IV, different plaintexts).  Mask fields use the
            // precomputed g_masked_col lookup as before.
            constexpr size_t B = 16;
            std::string lbufs[B];
            for (auto& lb : lbufs) lb.reserve(512);

            const uint8_t* pt_p[B];
            size_t         pt_l[B];
            alignas(64) uint8_t ct_s[B][64];   // ciphertext staging (max 4 blocks)
            uint8_t*       ct_p[B];
            size_t         ct_l[B];
            for (size_t b = 0; b < B; ++b) ct_p[b] = ct_s[b];

            const size_t full = (nrows / B) * B;

            for (size_t base = 0; base < full; base += B) {
                for (size_t b = 0; b < B; ++b) lbufs[b].clear();

                for (size_t fi_i = 0; fi_i < finfos.size(); ++fi_i) {
                    const auto& fi = finfos[fi_i];
                    if (fi.is_sm4) {
                        // Gather 16 plaintexts, encrypt in parallel.
                        for (size_t b = 0; b < B; ++b) {
                            const auto& row = g_rows[base + b];
                            const std::string& val =
                                (fi.col < (int)row.size()) ? row[fi.col] : g_empty_str;
                            pt_p[b] = (const uint8_t*)val.data();
                            pt_l[b] = val.size();
                        }
                        sm4_cbc_encrypt_x16(ctx, SM4_IV, pt_p, pt_l, ct_p, ct_l);
                        // Hex-encode into per-row line buffers.
                        for (size_t b = 0; b < B; ++b) {
                            if (fi_i > 0) lbufs[b] += ',';
                            if (ct_l[b] == 0) continue;
                            size_t s = lbufs[b].size();
                            lbufs[b].resize(s + ct_l[b] * 2);
                            for (size_t k = 0; k < ct_l[b]; ++k) {
                                lbufs[b][s + k*2]   = HEX[ct_s[b][k] >> 4];
                                lbufs[b][s + k*2+1] = HEX[ct_s[b][k] & 0xf];
                            }
                        }
                    } else {
                        // Precomputed mask lookup — zero compute, zero alloc.
                        for (size_t b = 0; b < B; ++b) {
                            if (fi_i > 0) lbufs[b] += ',';
                            lbufs[b] += g_masked_col[fi.col - 4][base + b];
                        }
                    }
                }

                for (size_t b = 0; b < B; ++b) {
                    lbufs[b] += '\n';
                    ofs.write(lbufs[b].data(), lbufs[b].size());
                }
            }

            // Scalar remainder for the last (nrows % 16) rows.
            std::string line;
            line.reserve(512);
            for (size_t row_idx = full; row_idx < nrows; ++row_idx) {
                scalar_row(line, row_idx);
                ofs.write(line.data(), line.size());
            }
        } else {
            // ── Scalar path (no AVX-512) ───────────────────────────────────
            std::string line;
            line.reserve(512);
            for (size_t row_idx = 0; row_idx < nrows; ++row_idx) {
                scalar_row(line, row_idx);
                ofs.write(line.data(), line.size());
            }
        }
        auto t_encrypt = tnow();
        TLOG("%-32s  encrypt=%7.1fms  rows=%zu  fields=%zu",
             requestId.c_str(), tms(t_open, t_encrypt),
             g_rows.size(), finfos.size());

        // ── 6. Flush & close ───────────────────────────────────────────────
        ofs.close();
        auto t_close = tnow();
        TLOG("%-32s  flush=%6.2fms", requestId.c_str(), tms(t_encrypt, t_close));

        // ── 7. Callback ────────────────────────────────────────────────────
        if (!g_callback_url.empty() && g_callback_url != "skip") {
            std::string cb =
                "{\"teamCode\":\"" + g_team_code + "\","
                "\"requestId\":\"" + requestId + "\","
                "\"ip\":\"" + ip + "\"}";
            for (int i = 0; i < 5; i++) {
                if (http_post(g_callback_url, cb)) break;
                usleep(50000);
            }
        }
        auto t_cb = tnow();
        TLOG("%-32s  callback=%6.1fms", requestId.c_str(), tms(t_close, t_cb));

        // ── Summary (always printed) ───────────────────────────────────────
        double d_total   = tms(t_start, t_cb);
        double d_encrypt = tms(t_open, t_encrypt);
        double d_cb      = tms(t_close, t_cb);
        double d_wall    = batch_wall_ms();   // elapsed since first request arrived
        int    done      = g_req_done.load() + 1;  // +1: will be incremented below
        int    submitted = g_req_submitted.load();

        fprintf(stderr,
            "[DONE] %-28s [%3d/%-3d]  req=%7.0fms  wall=%7.0fms"
            "  (csv=%5.1f  init=%.2f  enc=%6.0f  wr=%4.1f  cb=%5.0f)\n",
            requestId.c_str(), done, submitted,
            d_total, d_wall,
            tms(t_start, t_csv), tms(t_csv, t_init),
            d_encrypt, tms(t_encrypt, t_close), d_cb);

        batch_req_done(d_total, d_encrypt, d_cb);  // increments g_req_done, triggers [BATCH]

    } catch (const std::exception& e) {
        fprintf(stderr, "[ERROR] %s: %s  elapsed=%.1fms\n",
                requestId.c_str(), e.what(), tms(t_start, tnow()));
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

        batch_mark_start();          // record time of first /encrypt (idempotent)
        g_req_submitted.fetch_add(1, std::memory_order_relaxed);

        // Respond immediately; process in background
        send_json(fd, 200, R"({"returnCode":"SUC0000","body": true,"errorMsg":""})");
        close(fd);
        fd = -1;

        g_work_pool->submit([=]() mutable {
            do_encrypt(std::move(rid), std::move(ip),
                       std::move(key), std::move(fields));
        });

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
    g_debug        = (env("DCC_DEBUG", "0") == "1");
    g_expect_reqs  = std::stoi(env("DCC_EXPECT_REQS", "100"));  // 0 = disable [BATCH] summary
    g_avx512_ok    = cpu_has_avx512f();

    if (!g_output_dir.empty() && g_output_dir.back() != '/')
        g_output_dir += '/';

    signal(SIGPIPE, SIG_IGN); // don't crash on broken socket writes

    // Worker thread pool: one thread per logical CPU (for encrypt jobs)
    unsigned nw = std::thread::hardware_concurrency();
    if (nw < 1) nw = 4;
    // Connection thread pool: fixed 64 threads replaces unbounded detach().
    // Conn threads are I/O-bound and short-lived (recv + queue + send), so 64
    // handles 100 concurrent connections without growing thread count unboundedly.
    unsigned nc = 64;
    std::cerr << "[INFO] Workers: " << nw << "  Conn pool: " << nc
              << "  AVX-512: " << (g_avx512_ok ? "ON" : "OFF")
              << "  CSV: " << g_csv_path
              << "  Out: " << g_output_dir << "\n";
    g_work_pool = new ThreadPool(nw);
    g_conn_pool = new ThreadPool(nc);

    // Server socket
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, 512);
    std::cerr << "[INFO] Listening on :8080\n";

    // Accept loop — submit to bounded pool instead of unbounded detach.
    // Also set per-connection recv/send timeouts so hung clients don't
    // permanently consume a conn-pool thread.
    struct timeval conn_tv{10, 0};  // 10 s timeout per connection
    while (true) {
        int fd = accept(srv, nullptr, nullptr);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &conn_tv, sizeof(conn_tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &conn_tv, sizeof(conn_tv));
        g_conn_pool->submit([fd]{ handle_conn(fd); });
    }
    return 0;
}
