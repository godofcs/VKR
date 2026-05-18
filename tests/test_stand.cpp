#include "../Interfaces/merkle_client.h"
#include "../utils/SHA256/sha256.h"

#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>


using namespace std;
using Clock = chrono::high_resolution_clock;


using CreateFullFn   = IFullClient*  (*)();
using CreateLightFn  = ILightClient* (*)();
using DestroyFullFn  = void          (*)(IFullClient*);
using DestroyLightFn = void          (*)(ILightClient*);

struct Library {
    void*           handle        = nullptr;
    CreateFullFn    create_full   = nullptr;
    CreateLightFn   create_light  = nullptr;
    DestroyFullFn   destroy_full  = nullptr;
    DestroyLightFn  destroy_light = nullptr;
    string          path;
};

template <typename Fn>
static Fn resolve_(void* h, const char* sym) {
    dlerror();   // очистка
    Fn p = reinterpret_cast<Fn>(dlsym(h, sym));
    const char* err = dlerror();
    if (err) {
        cerr << "dlsym('" << sym << "') failed: " << err << "\n";
        exit(2);
    }
    return p;
}

static Library load_library(const string& path) {
    Library lib;
    lib.path = path;
    lib.handle = dlopen(path.c_str(), RTLD_NOW);
    if (!lib.handle) {
        cerr << "dlopen('" << path << "') failed: " << dlerror() << "\n";
        exit(1);
    }
    lib.create_full   = resolve_<CreateFullFn>  (lib.handle, "CreateMerkleFullClient");
    lib.create_light  = resolve_<CreateLightFn> (lib.handle, "CreateMerkleLightClient");
    lib.destroy_full  = resolve_<DestroyFullFn> (lib.handle, "DestroyMerkleFullClient");
    lib.destroy_light = resolve_<DestroyLightFn>(lib.handle, "DestroyMerkleLightClient");
    return lib;
}


template <typename F>
static double time_ms(F&& f) {
    auto t0 = Clock::now();
    f();
    auto t1 = Clock::now();
    return chrono::duration<double, milli>(t1 - t0).count();
}

static size_t get_rss_kb() {
    ifstream f("/proc/self/statm");
    long total_pages = 0, resident_pages = 0;
    f >> total_pages >> resident_pages;
    if (!f) return 0;
    long page_kb = sysconf(_SC_PAGESIZE) / 1024;
    return static_cast<size_t>(resident_pages * page_kb);
}

static size_t file_size_bytes(const string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 ? static_cast<size_t>(st.st_size) : 0;
}


static vector<KeyValue> generate_data(size_t n) {
    vector<KeyValue> data;
    data.reserve(n);
    string key;
    for (size_t i = 0; i < n; ++i) {
        key = "key_" + to_string(i);
        data.push_back({picosha2::hash256_hex_string(key), "v" + to_string(i)});
    }
    return data;
}


// Проверки корректности

// Счётчик функциональных провалов. Стенд не выходит сразу при провале --
// печатает WARNING и продолжает, чтобы получить количественные замеры даже
// для частично корректных реализаций. Итоговый exit code != 0 будет, если
// были провалы.
static int g_fail_count = 0;
static void fail_(const string& msg) {
    cerr << "  CORRECTNESS FAIL: " << msg << "\n";
    ++g_fail_count;
}

static void run_correctness(Library& lib) {
    cout << "Functional checks:\n";
    IFullClient*  full  = lib.create_full();
    ILightClient* light = lib.create_light();

    // 1) Build на наборе из 100 пар, root_hash непустой, verify проходит для каждой пары
    auto data = generate_data(100);
    full->Build(data);
    light->SetRootHash(full->GetRootHash());

    if (full->GetRootHash().empty()) fail_("root hash is empty after Build");

    for (const auto& kv : data) {
        auto p = full->RequestProof(kv.key);
        if (!light->VerifyProof(kv, p)) fail_("verify after Build, key=" + kv.key);
    }
    cout << "  - Build + verify all leaves: OK\n";

    string key = "key_" + to_string(5);
    const string key5    = picosha2::hash256_hex_string(key);
    key = "key_" + to_string(0);
    const string key0    = picosha2::hash256_hex_string(key);
    key = "key_" + to_string(10);
    const string key10   = picosha2::hash256_hex_string(key);
    key = "key_" + to_string(9999999);
    const string key_new = picosha2::hash256_hex_string(key);

    // 2) Update существующего ключа: новое значение верифицируется, старое значение -- не верифицируется
    full->Update({key5, "NEW_v5"});
    light->SetRootHash(full->GetRootHash());

    if (!light->VerifyProof({key5, "NEW_v5"}, full->RequestProof(key5))) {
        fail_("verify after Update(existing) with new value");
    }
    if (light->VerifyProof({key5, "v5"}, full->RequestProof(key5))) {
        fail_("old value accepted after Update(existing)");
    }
    cout << "  - Update(existing key): OK\n";

    // 3) Update нового ключа = Insert. Размер увеличивается на 1, verify нового элемента проходит
    full->Update({key_new, "v_new"});
    light->SetRootHash(full->GetRootHash());

    if (!light->VerifyProof({key_new, "v_new"}, full->RequestProof(key_new))) {
        fail_("verify after Update(new) (insert)");
    }
    cout << "  - Update(new key) = Insert: OK\n";

    // 4) Delete: удалённую пару нельзя подтвердить, verify остальных листьев проходит.
    light->VerifyProof({key0, "v0"}, full->RequestProof(key0));
    full->Delete(key0);
    light->SetRootHash(full->GetRootHash());

    if (light->VerifyProof({key0, "v0"}, full->RequestProof(key0))) {
        fail_("deleted key still verifies");
    }
    if (!light->VerifyProof({key10, "v10"}, full->RequestProof(key10))) {
        fail_("verify of remaining leaf after Delete");
    }

    cout << "  - Delete: OK\n";

    // 5) Delete несуществующего ключа -- допустимо бросить исключение, либо игнорировать, вызов не разрушает дерево.
    const string root_before = full->GetRootHash();
    key = "key_" + to_string(8888888);
    try { full->Delete(picosha2::hash256_hex_string(key)); }
    catch (...) { /* допустимо */ }
    if (full->GetRootHash() != root_before) {
        fail_("Delete(missing key) changed the tree state");
    }
    cout << "  - Delete(missing key) is a safe no-op: OK\n";

    // 6) Negative: подменённый байт в доказательстве -- VerifyProof отвергает.
    {
        auto p = full->RequestProof(key_new);
        if (!p.empty()) {
            p[0] ^= 0x01;
            if (light->VerifyProof({key_new, "v_new"}, p)) {
                fail_("tampered proof accepted");
            }
        }
    }
    // 7) Negative: подменённое значение -- VerifyProof отвергает.
    {
        auto p = full->RequestProof(key10);
        if (light->VerifyProof({key10, "WRONG_VALUE"}, p)) {
            fail_("wrong value accepted");
        }
    }
    cout << "  - Negative cases (tampered proof, wrong value): OK\n";

    lib.destroy_light(light);
    lib.destroy_full(full);
}


// Замеры производительности

struct Metrics {
    size_t N                  = 0;
    double build_ms           = 0;
    double update_existing_ms = 0;
    double insert_ms          = 0;
    double delete_ms          = 0;
    double verify_ms          = 0;
    size_t proof_size_bytes   = 0;
    size_t memory_kb          = 0;
};

template <typename F>
static double measure_avg_ms(int repeats, F&& op) {
    auto t0 = Clock::now();
    for (int i = 0; i < repeats; ++i) op(i);
    auto t1 = Clock::now();
    double total = chrono::duration<double, milli>(t1 - t0).count();
    return total / repeats;
}

static Metrics measure_for_n(Library& lib, size_t N, int repeats) {
    Metrics m;
    m.N = N;
    auto data = generate_data(N);

    // Build
    int build_repeats = max(1, repeats / 10);
    {
        IFullClient* full = lib.create_full();
        size_t rss_before = get_rss_kb();
        m.build_ms = measure_avg_ms(build_repeats, [&](int) {
            full->Build(data);
        });
        size_t rss_after = get_rss_kb();
        m.memory_kb = (rss_after > rss_before) ? (rss_after - rss_before) : 0;

        // размер доказательства
        auto p = full->RequestProof(data[N / 2].key);
        m.proof_size_bytes = p.size();

        lib.destroy_full(full);
    }

    // Update existing
    {
        IFullClient* full = lib.create_full();
        full->Build(data);
        mt19937 gen(42);
        uniform_int_distribution<size_t> dist(0, N - 1);
        vector<KeyValue> updates;
        updates.reserve(repeats);
        for (int i = 0; i < repeats; ++i) {
            updates.push_back({data[dist(gen)].key, "u_" + to_string(i)});
        }
        m.update_existing_ms = measure_avg_ms(repeats, [&](int i) {
            full->Update(updates[i]);
        });
        lib.destroy_full(full);
    }

    // Insert
    {
        IFullClient* full = lib.create_full();
        full->Build(data);
        vector<KeyValue> inserts;
        inserts.reserve(repeats);
        string key;
        for (int i = 0; i < repeats; ++i) {
            key = "key_" + to_string(N + 1 + i);
            inserts.push_back({picosha2::hash256_hex_string(key), "new_v" + to_string(i)});
        }
        m.insert_ms = measure_avg_ms(repeats, [&](int i) {
            full->Update(inserts[i]);
        });
        lib.destroy_full(full);
    }

    // Delete
    {
        IFullClient* full = lib.create_full();
        full->Build(data);
        int max_repeats = min<int>(repeats, static_cast<int>(N));
        vector<string> keys;
        keys.reserve(max_repeats);
        for (int i = 0; i < max_repeats; ++i) keys.push_back(data[i].key);
        m.delete_ms = measure_avg_ms(max_repeats, [&](int i) {
            full->Delete(keys[i]);
        });
        lib.destroy_full(full);
    }

    // Verify (RequestProof + VerifyProof)
    {
        IFullClient*  full  = lib.create_full();
        ILightClient* light = lib.create_light();
        full->Build(data);
        light->SetRootHash(full->GetRootHash());

        mt19937 gen(123);
        uniform_int_distribution<size_t> dist(0, N - 1);
        vector<pair<KeyValue, vector<uint8_t>>> probes;
        probes.reserve(repeats);
        for (int i = 0; i < repeats; ++i) {
            size_t idx = dist(gen);
            probes.push_back({data[idx], full->RequestProof(data[idx].key)});
        }
        m.verify_ms = measure_avg_ms(repeats, [&](int i) {
            volatile bool ok = light->VerifyProof(probes[i].first, probes[i].second);
            (void) ok;
        });
        lib.destroy_light(light);
        lib.destroy_full(full);
    }

    return m;
}


static string fmt_num(double v, int prec = 3) {
    ostringstream s;
    s << fixed << setprecision(prec) << v;
    return s.str();
}

static void print_metrics(const Metrics& m) {
    cout << "  n = " << setw(8) << m.N
         << " | build = "       << setw(10) << fmt_num(m.build_ms)           << " ms"
         << " | update = "      << setw(8)  << fmt_num(m.update_existing_ms) << " ms"
         << " | insert = "      << setw(8)  << fmt_num(m.insert_ms)          << " ms"
         << " | delete = "      << setw(8)  << fmt_num(m.delete_ms)          << " ms"
         << " | verify = "      << setw(8)  << fmt_num(m.verify_ms)          << " ms"
         << " | proof = "       << setw(5)  << m.proof_size_bytes            << " B"
         << " | mem = "         << setw(6)  << m.memory_kb                   << " KB"
         << "\n";
}


static vector<size_t> parse_sizes(const string& s) {
    vector<size_t> r;
    string buf;
    for (char c : s) {
        if (c == ',' || c == ' ') {
            if (!buf.empty()) { r.push_back(stoull(buf)); buf.clear(); }
        } else {
            buf += c;
        }
    }
    if (!buf.empty()) r.push_back(stoull(buf));
    return r;
}


int main(int argc, char** argv) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <path-to-lib.so> [sizes_csv] [repeats]\n";
        cerr << "  sizes_csv default: 1000,10000\n";
        cerr << "  repeats   default: 10\n";
        return 1;
    }
    string lib_path = argv[1];
    vector<size_t> sizes = (argc >= 3) ? parse_sizes(argv[2])
                                       : vector<size_t>{1000, 10000};
    int repeats = (argc >= 4) ? atoi(argv[3]) : 100;

    cout << "============================================================\n";
    cout << "Library : " << lib_path << "\n";
    cout << "Size    : " << file_size_bytes(lib_path) << " bytes\n";
    cout << "Sizes   : ";
    for (size_t i = 0; i < sizes.size(); ++i) {
        cout << sizes[i] << (i + 1 < sizes.size() ? ", " : "");
    }
    cout << "\nRepeats : " << repeats << " (Build: " << max(1, repeats / 10) << ")\n";
    cout << "============================================================\n";

    Library lib = load_library(lib_path);

    run_correctness(lib);
    if (g_fail_count == 0) {
        cout << "  -> all functional checks passed\n";
    } else {
        cout << "  -> " << g_fail_count
             << " functional check(s) failed; continuing to measurements\n";
    }

    cout << "\nPerformance:\n";
    for (size_t N : sizes) {
        cout << "  measuring n=" << N << " ..." << flush;
        Metrics m = measure_for_n(lib, N, repeats);
        cout << " done\n";
        print_metrics(m);
    }

    dlclose(lib.handle);
    return g_fail_count == 0 ? 0 : 10;

}
