from cym500.benchmark.metrics import BenchmarkMetrics, percentile


def test_percentile_basic():
    assert percentile([1, 2, 3, 4, 5], 0.5) == 3
    assert abs(percentile([1, 2, 3, 4, 5], 0.95) - 4.8) < 1e-6


def test_metrics_tpr_fpr():
    m = BenchmarkMetrics(gateway="test")
    m.n_attack = 10
    m.n_attack_blocked = 8
    m.n_benign = 100
    m.n_benign_blocked = 3
    assert m.tpr == 0.8
    assert m.fpr == 0.03
