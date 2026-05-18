#include "../Interfaces/merkle_client.h"
#include "../utils/SHA256/sha256.h"
#include "analyzer.h"

#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace std;
using Clock = chrono::steady_clock;


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
    string          name;
};

template <typename Fn>
static Fn resolve_sym(void* h, const char* sym) {
    dlerror();
    Fn p = reinterpret_cast<Fn>(dlsym(h, sym));
    const char* err = dlerror();
    if (err) throw runtime_error(string("dlsym('") + sym + "') failed: " + err);
    return p;
}

static string basename_no_ext(const string& path) {
    auto slash = path.find_last_of('/');
    string n = (slash == string::npos) ? path : path.substr(slash + 1);
    if (n.rfind("lib", 0) == 0) n.erase(0, 3);
    if (n.size() >= 3 && n.compare(n.size() - 3, 3, ".so") == 0)
        n.erase(n.size() - 3);
    return n;
}

static Library load_library(const string& path) {
    Library lib;
    lib.path = path;
    lib.name = basename_no_ext(path);
    lib.handle = dlopen(path.c_str(), RTLD_NOW);
    if (!lib.handle)
        throw runtime_error("dlopen('" + path + "') failed: " + (dlerror() ? dlerror() : ""));
    lib.create_full   = resolve_sym<CreateFullFn>  (lib.handle, "CreateMerkleFullClient");
    lib.create_light  = resolve_sym<CreateLightFn> (lib.handle, "CreateMerkleLightClient");
    lib.destroy_full  = resolve_sym<DestroyFullFn> (lib.handle, "DestroyMerkleFullClient");
    lib.destroy_light = resolve_sym<DestroyLightFn>(lib.handle, "DestroyMerkleLightClient");
    return lib;
}

static size_t get_rss_kb() {
    ifstream f("/proc/self/statm");
    long total = 0, resident = 0;
    f >> total >> resident;
    if (!f) return 0;
    long page_kb = sysconf(_SC_PAGESIZE) / 1024;
    return static_cast<size_t>(resident * page_kb);
}

static size_t file_size_bytes(const string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 ? static_cast<size_t>(st.st_size) : 0;
}

static vector<KeyValue> generate_data(size_t n) {
    vector<KeyValue> data;
    data.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        string key = "key_" + to_string(i);
        data.push_back({picosha2::hash256_hex_string(key), "v" + to_string(i)});
    }
    return data;
}


// Проверки корректности

static bool run_correctness(Library& lib) {
    IFullClient*  full  = lib.create_full();
    ILightClient* light = lib.create_light();
    int fails = 0;
    auto fail = [&](const string& s) { cerr << "  FAIL: " << s << "\n"; ++fails; };

    auto data = generate_data(100);
    full->Build(data);
    light->SetRootHash(full->GetRootHash());

    if (full->GetRootHash().empty()) fail("empty root after Build");
    for (const auto& kv : data) {
        auto p = full->RequestProof(kv.key);
        if (!light->VerifyProof(kv, p)) { fail("verify after Build"); break; }
    }

    const string key5    = picosha2::hash256_hex_string(string("key_5"));
    const string key0    = picosha2::hash256_hex_string(string("key_0"));
    const string key10   = picosha2::hash256_hex_string(string("key_10"));
    const string key_new = picosha2::hash256_hex_string(string("key_9999999"));

    full->Update({key5, "NEW_v5"});
    light->SetRootHash(full->GetRootHash());
    if (!light->VerifyProof({key5, "NEW_v5"}, full->RequestProof(key5)))
        fail("verify after Update(existing)");
    if (light->VerifyProof({key5, "v5"}, full->RequestProof(key5)))
        fail("old value accepted after Update");

    full->Update({key_new, "v_new"});
    light->SetRootHash(full->GetRootHash());
    if (!light->VerifyProof({key_new, "v_new"}, full->RequestProof(key_new)))
        fail("verify after Insert");
    
    full->Delete(key0);
    light->SetRootHash(full->GetRootHash());
    if (light->VerifyProof({key0, "v0"}, full->RequestProof(key0)))
        fail("deleted key still verifies");
    if (!light->VerifyProof({key10, "v10"}, full->RequestProof(key10)))
        fail("verify of remaining leaf after Delete");

    {
        auto p = full->RequestProof(key_new);
        if (!p.empty()) { p[0] ^= 0x01;
            if (light->VerifyProof({key_new, "v_new"}, p)) fail("tampered proof accepted"); }
    }
    {
        auto p = full->RequestProof(key10);
        if (light->VerifyProof({key10, "WRONG"}, p)) fail("wrong value accepted");
    }

    lib.destroy_light(light);
    lib.destroy_full(full);
    return fails == 0;
}


// Замеры производительности

template <typename F>
static double measure_avg_ms(int repeats, F&& op) {
    auto t0 = Clock::now();
    for (int i = 0; i < repeats; ++i) op(i);
    auto t1 = Clock::now();
    return chrono::duration<double, milli>(t1 - t0).count() / repeats;
}

static analyzer::PerformanceMetrics measure_for_n(Library& lib, size_t N, int repeats) {
    analyzer::PerformanceMetrics m;
    m.N                  = N;
    m.library_size_bytes = file_size_bytes(lib.path);
    auto data = generate_data(N);

    int build_repeats = max(1, repeats / 10);
    {
        IFullClient* full = lib.create_full();
        size_t rss_before = get_rss_kb();
        m.build_ms = measure_avg_ms(build_repeats, [&](int) { full->Build(data); });
        size_t rss_after = get_rss_kb();
        m.memory_kb = rss_after > rss_before ? rss_after - rss_before : 0;
        m.proof_size_bytes = full->RequestProof(data[N / 2].key).size();
        lib.destroy_full(full);
    }
    {
        IFullClient* full = lib.create_full();
        full->Build(data);
        mt19937 gen(42);
        uniform_int_distribution<size_t> dist(0, N - 1);
        vector<KeyValue> upd;
        upd.reserve(repeats);
        for (int i = 0; i < repeats; ++i)
            upd.push_back({data[dist(gen)].key, "u_" + to_string(i)});
        m.update_existing_ms = measure_avg_ms(repeats, [&](int i) { full->Update(upd[i]); });
        lib.destroy_full(full);
    }
    {
        IFullClient* full = lib.create_full();
        full->Build(data);
        vector<KeyValue> ins;
        ins.reserve(repeats);
        for (int i = 0; i < repeats; ++i) {
            string k = "key_" + to_string(N + 1 + i);
            ins.push_back({picosha2::hash256_hex_string(k), "new_v" + to_string(i)});
        }
        m.insert_ms = measure_avg_ms(repeats, [&](int i) { full->Update(ins[i]); });
        lib.destroy_full(full);
    }
    {
        IFullClient* full = lib.create_full();
        full->Build(data);
        int max_r = min<int>(repeats, static_cast<int>(N));
        vector<string> keys;
        keys.reserve(max_r);
        for (int i = 0; i < max_r; ++i) keys.push_back(data[i].key);
        m.delete_ms = measure_avg_ms(max_r, [&](int i) { full->Delete(keys[i]); });
        lib.destroy_full(full);
    }
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
            (void)ok;
        });
        lib.destroy_light(light);
        lib.destroy_full(full);
    }
    return m;
}


// Парсинг аргументов

static vector<size_t> parse_sizes(const string& s) {
    vector<size_t> r;
    string buf;
    for (char c : s) {
        if (c == ',' || c == ' ') {
            if (!buf.empty()) { r.push_back(stoull(buf)); buf.clear(); }
        } else buf += c;
    }
    if (!buf.empty()) r.push_back(stoull(buf));
    return r;
}

static analyzer::Weights parse_weights(const string& s) {
    vector<double> v;
    string buf;
    for (char c : s) {
        if (c == ',' || c == ' ') {
            if (!buf.empty()) { v.push_back(stod(buf)); buf.clear(); }
        } else buf += c;
    }
    if (!buf.empty()) v.push_back(stod(buf));
    if (v.size() != 8)
        throw invalid_argument("--weights expects 8 comma-separated values: "
                               "b,u,i,d,v,p,m,l");
    analyzer::Weights w;
    w.build       = v[0]; w.update      = v[1]; w.insert = v[2]; w.del      = v[3];
    w.verify      = v[4]; w.proof_bytes = v[5]; w.memory = v[6]; w.lib_size = v[7];
    return w;
}


int main(int argc, char** argv) {
    vector<size_t>      sizes   = {1000, 10000};
    int                 repeats = 10;
    analyzer::Weights   weights;
    vector<string>      lib_paths;

    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if (a == "--sizes"   && i + 1 < argc) { sizes   = parse_sizes(argv[++i]); }
        else if (a == "--repeats" && i + 1 < argc) { repeats = atoi(argv[++i]); }
        else if (a == "--weights" && i + 1 < argc) { weights = parse_weights(argv[++i]); }
        else if (!a.empty() && a[0] != '-') { lib_paths.push_back(a); }
        else {
            cerr << "Usage: " << argv[0]
                 << " [--sizes 100,1000] [--repeats 10] [--weights b,u,i,d,v,p,m,l]"
                    " <lib1.so> [lib2.so ...]\n";
            return 1;
        }
    }
    if (lib_paths.empty()) {
        cerr << "compare_stand: no libraries given\n";
        return 1;
    }

    struct LoadedLib {
        Library                  lib;
        analyzer::ThresholdFlags flags;
    };
    vector<LoadedLib> libs;
    libs.reserve(lib_paths.size());

    for (const string& p : lib_paths) {
        cout << "[ load ] " << p << "\n";
        LoadedLib L;
        try { L.lib = load_library(p); }
        catch (const exception& e) { cerr << "  " << e.what() << "\n"; continue; }
        L.flags.packaged_as_dll = true;
        L.flags.conforms_to_interface = true;
        L.flags.portable = true;               
        L.flags.reproducible_build = true;     
        L.flags.has_documentation = true;      

        cout << "[ chk  ] " << L.lib.name << "\n";
        L.flags.correctness_passed = run_correctness(L.lib);
        libs.push_back(move(L));
    }

    if (libs.empty()) {
        cerr << "compare_stand: no libraries successfully loaded\n";
        return 2;
    }

    for (size_t N : sizes) {
        cout << "\n[ run  ] n=" << N << " repeats=" << repeats << "\n";

        vector<analyzer::ImplementationResult> results;
        results.reserve(libs.size());

        for (auto& L : libs) {
            cout << "  measuring " << L.lib.name << " ..." << flush;
            analyzer::ImplementationResult r;
            r.name    = L.lib.name;
            r.flags   = L.flags;
            r.metrics = measure_for_n(L.lib, N, repeats);
            cout << " done (build=" << r.metrics.build_ms << " ms)\n";
            results.push_back(move(r));
        }

        auto ranked = analyzer::RankImplementations(results, weights);
        analyzer::PrintReport(cout, ranked, N);
    }

    for (auto& L : libs) dlclose(L.lib.handle);
    return 0;
}
