#pragma once

#include <algorithm>
#include <cstddef>
#include <iomanip>
#include <limits>
#include <numeric>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

namespace analyzer {

struct PerformanceMetrics {
    size_t N                  = 0;
    double      build_ms           = 0;
    double      update_existing_ms = 0;
    double      insert_ms          = 0;
    double      delete_ms          = 0;
    double      verify_ms          = 0;
    size_t proof_size_bytes   = 0;
    size_t memory_kb          = 0;
    size_t library_size_bytes = 0;
};

struct ThresholdFlags {
    bool conforms_to_interface = true;
    bool packaged_as_dll       = true;
    bool portable              = true;
    bool reproducible_build    = true;
    bool has_documentation     = true;
    bool correctness_passed    = true;
};

struct ImplementationResult {
    string         name;
    PerformanceMetrics  metrics;
    ThresholdFlags      flags;
};

struct Weights {
    double build       = 1.0;
    double update      = 1.0;
    double insert      = 1.0;
    double del         = 1.0;
    double verify      = 1.0;
    double proof_bytes = 1.0;
    double memory      = 1.0;
    double lib_size    = 1.0;
};

struct NormalizedMetrics {
    double build       = 0;
    double update      = 0;
    double insert      = 0;
    double del         = 0;
    double verify      = 0;
    double proof_bytes = 0;
    double memory      = 0;
    double lib_size    = 0;
};

struct RankedImplementation {
    string        name;
    NormalizedMetrics  normalized;
    double             criterion        = 0.0;
    bool               passed_threshold = true;
    string        rejection_reason;
};

namespace detail {

inline Weights normalize_weights(Weights w) {
    if (w.build < 0 || w.update < 0 || w.insert < 0 || w.del < 0 ||
        w.verify < 0 || w.proof_bytes < 0 || w.memory < 0 || w.lib_size < 0)
        throw invalid_argument("analyzer: negative weight");

    const double s = w.build + w.update + w.insert + w.del +
                     w.verify + w.proof_bytes + w.memory + w.lib_size;
    if (s <= 0) throw invalid_argument("analyzer: weight sum must be > 0");

    w.build /= s; w.update /= s; w.insert /= s; w.del /= s;
    w.verify /= s; w.proof_bytes /= s; w.memory /= s; w.lib_size /= s;
    return w;
}

inline double normalize_lib(double x, double xmin, double xmax) {
    if (xmax <= xmin) return 1.0;
    return (xmax - x) / (xmax - xmin);
}

inline string collect_rejections(const ThresholdFlags& f) {
    string r;
    if (!f.conforms_to_interface) r += "interface, ";
    if (!f.packaged_as_dll)       r += "dll, ";
    if (!f.portable)              r += "portable, ";
    if (!f.reproducible_build)    r += "reproducible, ";
    if (!f.has_documentation)     r += "docs, ";
    if (!f.correctness_passed)    r += "correctness, ";
    if (!r.empty()) r.resize(r.size() - 2);
    return r;
}

}

inline vector<RankedImplementation>
RankImplementations(const vector<ImplementationResult>& results,
                    const Weights& raw_weights)
{
    const Weights w = detail::normalize_weights(raw_weights);

    vector<RankedImplementation> out(results.size());
    vector<size_t> passed;
    passed.reserve(results.size());

    for (size_t i = 0; i < results.size(); ++i) {
        out[i].name = results[i].name;
        string r = detail::collect_rejections(results[i].flags);
        if (r.empty()) {
            passed.push_back(i);
        } else {
            out[i].passed_threshold = false;
            out[i].rejection_reason = move(r);
        }
    }

    if (passed.empty()) return out;

    auto range_over = [&](auto getter) {
        double lo =  numeric_limits<double>::infinity();
        double hi = -numeric_limits<double>::infinity();
        for (size_t i : passed) {
            const double v = static_cast<double>(getter(results[i].metrics));
            lo = min(lo, v);
            hi = max(hi, v);
        }
        return make_pair(lo, hi);
    };

    const auto [b_lo, b_hi] = range_over([](const PerformanceMetrics& m){ return m.build_ms; });
    const auto [u_lo, u_hi] = range_over([](const PerformanceMetrics& m){ return m.update_existing_ms; });
    const auto [i_lo, i_hi] = range_over([](const PerformanceMetrics& m){ return m.insert_ms; });
    const auto [d_lo, d_hi] = range_over([](const PerformanceMetrics& m){ return m.delete_ms; });
    const auto [v_lo, v_hi] = range_over([](const PerformanceMetrics& m){ return m.verify_ms; });
    const auto [p_lo, p_hi] = range_over([](const PerformanceMetrics& m){ return m.proof_size_bytes; });
    const auto [m_lo, m_hi] = range_over([](const PerformanceMetrics& m){ return m.memory_kb; });
    const auto [l_lo, l_hi] = range_over([](const PerformanceMetrics& m){ return m.library_size_bytes; });

    for (size_t i : passed) {
        const PerformanceMetrics& m = results[i].metrics;
        NormalizedMetrics& f = out[i].normalized;
        f.build       = detail::normalize_lib(m.build_ms,                      b_lo, b_hi);
        f.update      = detail::normalize_lib(m.update_existing_ms,            u_lo, u_hi);
        f.insert      = detail::normalize_lib(m.insert_ms,                     i_lo, i_hi);
        f.del         = detail::normalize_lib(m.delete_ms,                     d_lo, d_hi);
        f.verify      = detail::normalize_lib(m.verify_ms,                     v_lo, v_hi);
        f.proof_bytes = detail::normalize_lib(m.proof_size_bytes,              p_lo, p_hi);
        f.memory      = detail::normalize_lib(m.memory_kb,                     m_lo, m_hi);
        f.lib_size    = detail::normalize_lib(m.library_size_bytes,            l_lo, l_hi);

        out[i].criterion = w.build       * f.build
                         + w.update      * f.update
                         + w.insert      * f.insert
                         + w.del         * f.del
                         + w.verify      * f.verify
                         + w.proof_bytes * f.proof_bytes
                         + w.memory      * f.memory
                         + w.lib_size    * f.lib_size;
    }

    return out;
}


inline void PrintReport(ostream& os,
                        const vector<RankedImplementation>& ranked,
                        size_t N_marker = 0)
{
    auto sorted = ranked;
    stable_sort(sorted.begin(), sorted.end(),
        [](const RankedImplementation& a, const RankedImplementation& b) {
            if (a.passed_threshold != b.passed_threshold)
                return a.passed_threshold && !b.passed_threshold;
            return a.criterion > b.criterion;
        });

    os << "===========================================================\n";
    os << " Ranking by additive convolution K(r) (section 1.3)";
    if (N_marker) os << "   n = " << N_marker;
    os << "\n";
    os << "===========================================================\n";
    os << left << setw(28) << "implementation"
       << right << setw(10) << "K(r)"
       << setw(8)  << "build"
       << setw(8)  << "update"
       << setw(8)  << "insert"
       << setw(8)  << "delete"
       << setw(8)  << "verify"
       << setw(8)  << "proof"
       << setw(8)  << "memory"
       << setw(8)  << "size"
       << "\n";
    os << "-----------------------------------------------------------------------------------------------\n";

    auto fmt = [](double v) {
        ostringstream s;
        s << fixed << setprecision(3) << v;
        return s.str();
    };

    for (const auto& r : sorted) {
        os << left << setw(28) << r.name;
        if (!r.passed_threshold) {
            os << "  [REJECTED: " << r.rejection_reason << "]\n";
            continue;
        }
        os << right
           << setw(10) << fmt(r.criterion)
           << setw(8)  << fmt(r.normalized.build)
           << setw(8)  << fmt(r.normalized.update)
           << setw(8)  << fmt(r.normalized.insert)
           << setw(8)  << fmt(r.normalized.del)
           << setw(8)  << fmt(r.normalized.verify)
           << setw(8)  << fmt(r.normalized.proof_bytes)
           << setw(8)  << fmt(r.normalized.memory)
           << setw(8)  << fmt(r.normalized.lib_size)
           << "\n";
    }
    os << "\n";
}

}
