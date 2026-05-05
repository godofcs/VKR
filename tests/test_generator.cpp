#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <iomanip>
#include <cassert>
#include <sys/resource.h>
#include <unistd.h>
#ifdef __linux__
  #include <cstdio>
#endif

#define main __included_main_unused

#ifdef USE_POINTER_IMPL
    #include "../Merkle tree /merkle_tree.cpp"
    using TestedMerkleTree = MerkleTree;
    static constexpr const char* IMPL_NAME = "Merkle Tree on shared_ptr";
#elif defined(USE_VECTOR_IMPL)
    #include "../Merkle tree /optimized_merkle_tree.cpp"
    using TestedMerkleTree = VectorMerkleTree;
    static constexpr const char* IMPL_NAME = "Merkle Tree on vector<string>";
#else
    #error "Define USE_POINTER_IMPL or USE_VECTOR_IMPL"
#endif

#undef main
#undef MerkleTree

using namespace std;
using namespace std::chrono;


vector<KeyValue> GenerateData(size_t n, uint32_t seed = 42) {
    vector<KeyValue> data;
    data.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const string raw = "key_" + to_string(seed) + "_" + to_string(i);
        KeyValue kv;
        kv.key = picosha2::hash256_hex_string(raw);
        kv.value = "value_" + to_string(i);
        data.push_back(std::move(kv));
    }
    return data;
}

template <typename F>
double MeasureMs(F&& fn) {
    const auto t0 = high_resolution_clock::now();
    fn();
    const auto t1 = high_resolution_clock::now();
    return duration<double, milli>(t1 - t0).count();
}

size_t GetPeakRSSBytes() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
#ifdef __APPLE__
    return static_cast<size_t>(usage.ru_maxrss);
#else
    return static_cast<size_t>(usage.ru_maxrss) * 1024;
#endif
}

size_t GetCurrRSSBytes() {
#ifdef __linux__
    FILE* f = std::fopen("/proc/self/statm", "r");
    if (!f) return 0;
    long total_pages = 0, resident_pages = 0;
    if (std::fscanf(f, "%ld %ld", &total_pages, &resident_pages) != 2) {
        std::fclose(f);
        return 0;
    }
    std::fclose(f);
    long page_sz = sysconf(_SC_PAGESIZE);
    return static_cast<size_t>(resident_pages) * static_cast<size_t>(page_sz);
#else
    return GetPeakRSSBytes();
#endif
}

double BytesToMB(size_t b) { return static_cast<double>(b) / (1024.0 * 1024.0); }

struct RunResult {
    size_t n = 0;
    double build_ms = 0.0;
    double verify_total_ms = 0.0;
    size_t verify_iter = 0;
    double update_total_ms = 0.0;
    size_t update_iter = 0;
    double delete_total_ms = 0.0;
    size_t delete_iter = 0;
    string root_hash;

    double mem_build_delta_mb = 0.0;
    double mem_curr_after_build_mb = 0.0;
    double mem_peak_total_mb = 0.0;
};

RunResult RunOne(size_t n, size_t verify_iter, size_t update_iter, size_t delete_iter) {
    RunResult r;
    r.n = n;
    r.verify_iter = verify_iter;
    r.update_iter = update_iter;
    r.delete_iter = delete_iter;

    auto data = GenerateData(n);

    const size_t mem_before_peak = GetPeakRSSBytes();

    TestedMerkleTree* tree = nullptr;
    r.build_ms = MeasureMs([&] {
        tree = new TestedMerkleTree(data);
    });
    r.root_hash = tree->GetRootHash();

    const size_t mem_after_peak = GetPeakRSSBytes();
    const size_t mem_after_curr = GetCurrRSSBytes();
    r.mem_build_delta_mb     = BytesToMB(mem_after_peak - mem_before_peak);
    r.mem_curr_after_build_mb = BytesToMB(mem_after_curr);

    mt19937 rng(0xC0FFEE);
    uniform_int_distribution<size_t> idx_dist(0, n - 1);

    r.verify_total_ms = MeasureMs([&] {
        for (size_t i = 0; i < verify_iter; ++i) {
            const size_t idx = idx_dist(rng);
            string key = data[idx].key;
            const bool ok = tree->VerifyValue(static_cast<int>(idx), key);
            assert(ok && "Verification of an existing leaf must succeed");
            (void)ok;
        }
    });

    r.update_total_ms = MeasureMs([&] {
        for (size_t i = 0; i < update_iter; ++i) {
            const size_t idx = idx_dist(rng);
            KeyValue kv;
            kv.key = picosha2::hash256_hex_string(
                "upd_" + to_string(i) + "_" + to_string(idx));
            kv.value = "newval_" + to_string(i);
            tree->UpdateValue(kv, static_cast<int>(idx));
        }
    });

    mt19937 rng_del(0xDEADBEEF);
    size_t cur_size = n;
    r.delete_total_ms = MeasureMs([&] {
        for (size_t i = 0; i < delete_iter && cur_size > 0; ++i) {
            uniform_int_distribution<size_t> d(0, cur_size - 1);
            const size_t idx = d(rng_del);
            tree->DeleteValue(static_cast<int>(idx));
            --cur_size;
        }
    });

    delete tree;

    r.mem_peak_total_mb = BytesToMB(GetPeakRSSBytes());
    return r;
}

void PrintRow(const RunResult& r) {
    cout << fixed << setprecision(3);
    cout << "n = " << setw(8) << r.n
         << " | build = " << setw(10) << r.build_ms << " ms"
         << " | verify avg = " << setw(8) << (r.verify_total_ms / r.verify_iter) << " ms"
         << " | update avg = " << setw(10) << (r.update_total_ms / r.update_iter) << " ms"
         << " | delete avg = " << setw(10) << (r.delete_iter > 0 ? r.delete_total_ms / r.delete_iter : 0.0) << " ms"
         << setprecision(1)
         << " | mem build = " << setw(7) << r.mem_build_delta_mb << " MB"
         << " | RSS after = " << setw(7) << r.mem_curr_after_build_mb << " MB"
         << " | peak = " << setw(7) << r.mem_peak_total_mb << " MB"
         << "\n";
}

vector<size_t> ParseSizes(int argc, char** argv) {
    vector<size_t> result;
    if (argc < 2) {
        // Размеры входных данных: малые размеры + от 1e6 до 5e6 с шагом 1e6
        result = {1000, 10000, 100000};
        for (size_t k = 1; k <= 5; ++k) {
            result.push_back(k * 1000000);
        }
        return result;
    }
    string s = argv[1];
    size_t pos = 0;
    while (pos < s.size()) {
        size_t comma = s.find(',', pos);
        if (comma == string::npos) comma = s.size();
        if (comma > pos) {
            result.push_back(stoull(s.substr(pos, comma - pos)));
        }
        pos = comma + 1;
    }
    return result;
}

int main(int argc, char** argv) {
    cout << "==============================================================\n";
    cout << "Implementation: " << IMPL_NAME << "\n";
    cout << "Hash function:  SHA-256 (picosha2)\n";
    cout << "==============================================================\n";

    const vector<size_t> sizes = ParseSizes(argc, argv);

    vector<RunResult> all;
    for (size_t n : sizes) {
        size_t verify_iter, update_iter, delete_iter;
        if (n <= 1000)         { verify_iter = 10000; update_iter = 1000; delete_iter = 100; }
        else if (n <= 10000)   { verify_iter = 10000; update_iter = 100;  delete_iter = 10; }
        else if (n <= 100000)  { verify_iter = 10000; update_iter = 10;   delete_iter = 5; }
        else                   { verify_iter = 1000;  update_iter = 1;    delete_iter = 1; }

        cout << "Run for n = " << n << " ... " << flush;
        RunResult r = RunOne(n, verify_iter, update_iter, delete_iter);
        cout << "done in "
             << fixed << setprecision(1)
             << (r.build_ms + r.verify_total_ms + r.update_total_ms + r.delete_total_ms) / 1000.0
             << " s.\n";
        all.push_back(r);
    }

    cout << "\n--- Summary ----------------------------------------------------\n";
    for (const auto& r : all) PrintRow(r);
    cout << "----------------------------------------------------------------\n";
    cout << "Last root hash: " << all.back().root_hash << "\n";
    return 0;
}
