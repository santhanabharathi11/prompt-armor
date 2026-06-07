# Benchmarks

All measurements on Apple M-series (arm64). Python 3.14. 1000 iterations per payload.

## Detector Latency

| Detector | p50 | p95 | p99 | Mean |
|----------|-----|-----|-----|------|
| InjectionDetector | 18μs | 20μs | 39μs | 18μs |
| InjectionDetector (Hindi/Multilingual) | 11μs | 12μs | 16μs | 11μs |
| JailbreakDetector | 10μs | 11μs | 16μs | 10μs |
| PIIDetector | 13μs | 15μs | 21μs | 13μs |
| SecretsDetector | 22μs | 24μs | 31μs | 22μs |
| FinancialDetector | 19μs | 22μs | 28μs | 20μs |
| CloudDetector | 28μs | 31μs | 36μs | 28μs |
| ToxicDetector | 11μs | 13μs | 18μs | 11μs |
| **Full pipeline (benign)** | **64μs** | **71μs** | **85μs** | **64μs** |
| **Full pipeline (attack)** | **135μs** | **147μs** | **186μs** | **134μs** |

**Total overhead per LLM request: 0.06ms (benign) — 0.14ms (attack)**

Compared to typical LLM API latency of 500ms–5000ms, prompt-armor adds less than 0.03% overhead.

## Detection Accuracy

Measured against a sample corpus of attack payloads and benign inputs.

| Detector | True Positive Rate | False Positive Rate |
|----------|-------------------|---------------------|
| InjectionDetector | 8/8 (100%) | 0/10 (0%) |
| PIIDetector | 8/8 (100%) | 0/10 (0%) |
| SecretsDetector | 8/8 (100%) | 0/10 (0%) |

## Reproduce

```bash
python scripts/benchmark.py
python scripts/benchmark.py --detectors-only
python scripts/benchmark.py --accuracy-only
```

## Architecture Notes

All detectors use compiled regex — no ML inference, no network calls.
Scanning runs synchronously in < 1ms before the LLM API call is made.
Under high concurrency, each async worker scans independently — no lock contention.
