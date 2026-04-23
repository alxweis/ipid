import math
import random
from enum import Enum
from math import erfc, sqrt, log

import numpy as np
from scipy.stats import chisquare

from core.utils import config

MAX_IP_ID = 65535
MIN_STEPS_BEFORE_WRAPAROUND = 3
MAX_INC = math.ceil((MAX_IP_ID + 1) / MIN_STEPS_BEFORE_WRAPAROUND) - 1

GLOBAL_MAX_INC = MAX_INC

LOCAL_GE1_MAX_INC = 2000

MULTI_GLOBAL_CLUSTER_MAX_INC = 800
MULTI_GLOBAL_MAX_CLUSTERS = 16


class IPIDSubsequence:
    def __init__(self, sequence: np.ndarray):
        self.sequence: np.ndarray = sequence
        self.increments: np.ndarray = np.diff(self.sequence) % (MAX_IP_ID + 1)

    def is_increasing(self, min_inc: int, max_inc: int) -> bool:
        if len(self.increments) == 0:
            return False
        return np.all((min_inc <= self.increments) & (self.increments <= max_inc))


class IPIDSequence:
    def __init__(self, sequence: list[int] | tuple[int, ...] | np.ndarray):
        arr = np.array(sequence, dtype=np.int32)
        self.s = IPIDSubsequence(arr)
        idx = np.arange(len(arr)) % 6
        self.a = IPIDSubsequence(arr[np.isin(idx, [0, 1, 4])])
        self.b = IPIDSubsequence(arr[np.isin(idx, [2, 3, 5])])
        self.ap = IPIDSubsequence(arr[np.isin(idx, [1, 4])])
        self.bp = IPIDSubsequence(arr[np.isin(idx, [2, 5])])
        # idx = np.arange(len(arr)) % 8
        # self.a = IPIDSubsequence(arr[np.isin(idx, [0, 2, 4, 6])])
        # self.b = IPIDSubsequence(arr[np.isin(idx, [1, 3, 5, 7])])
        # self.ap = IPIDSubsequence(arr[np.isin(idx, [0, 4])])
        # self.ap_no_first = IPIDSubsequence(arr[np.isin(idx, [0, 4])][1:])
        # self.bp = IPIDSubsequence(arr[np.isin(idx, [1, 5])])
        # self.bp_no_first = IPIDSubsequence(arr[np.isin(idx, [1, 5])][1:])
        # self.cp = IPIDSubsequence(arr[np.isin(idx, [2, 6])])
        # self.cp_no_first = IPIDSubsequence(arr[np.isin(idx, [2, 6])][1:])
        # self.dp = IPIDSubsequence(arr[np.isin(idx, [3, 7])])
        # self.dp_no_first = IPIDSubsequence(arr[np.isin(idx, [3, 7])][1:])

    def __len__(self):
        return len(self.s.sequence)


class Pattern(Enum):
    REFLECTION = "Mirror"
    CONSTANT = "Constant"
    GLOBAL = "Single"
    PER_DST = "Per-Dst"  # per-destination/ per-connection counter
    PER_CON = "Per-Con"  # per-connection counter
    PER_BUCKET = "Per-Bucket"  # per-bucket counter
    PER_CPU = "Per-CPU"  # per-cpu counter when >1 cpu
    RANDOM = "Random"
    FALLBACK = "Fallback"
    NONE = "None"


# region Class Recognition
def nrm_entropy(values: np.ndarray) -> float:
    unique_values, counts = np.unique(values, return_counts=True)
    probabilities = counts / counts.sum()
    entropy = -np.sum(probabilities * np.log2(probabilities))
    max_entropy = np.log2(len(unique_values))  # Max Entropy based on unique values
    if max_entropy == 0:
        return 0
    return entropy / max_entropy


def get_clusters(values: np.ndarray, max_diff: int) -> list[dict[int, np.int32]]:
    if not values.size:
        return []

    # Erstelle Liste von (original_index, value) Paaren, sortiert nach Wert
    indexed_values = [(i, np.int32(val)) for i, val in enumerate(values)]
    indexed_values.sort(key=lambda x: x[1])

    # Finde Cluster-Grenzen
    breaks = []
    val_count = len(indexed_values)

    for i in range(val_count):
        current_val = indexed_values[i][1]
        next_val = indexed_values[(i + 1) % val_count][1]

        diff = (next_val - current_val + (MAX_IP_ID + 1)) % (MAX_IP_ID + 1)

        if diff > max_diff:
            breaks.append((i + 1) % val_count)

    # Keine Breaks = alle Werte in einem Cluster
    if not breaks:
        return [dict(sorted([(idx, val) for idx, val in indexed_values]))]

    # Erstelle Cluster
    final_clusters = []
    start_idx = breaks[-1] if breaks else 0

    for break_idx in breaks:
        cluster = {}
        current_idx = start_idx

        while current_idx != break_idx:
            idx, val = indexed_values[current_idx]
            cluster[idx] = val
            current_idx = (current_idx + 1) % val_count

        if cluster:
            final_clusters.append(dict(sorted(cluster.items())))

        start_idx = break_idx

    return final_clusters


# def p_value(values: np.ndarray, start_point: int, stop_point: int) -> float:
#     intervals = len(values) // 2
#     interval_edges = np.linspace(start_point, stop_point, intervals + 1)
#     observed_frequencies, _ = np.histogram(values, bins=interval_edges)
#     expected_frequencies = np.full(intervals, len(values) / intervals)
#
#     chi2_stat, p = chisquare(f_obs=observed_frequencies, f_exp=expected_frequencies)
#     return p
#
#
# def is_uniform(values: np.ndarray, start_point: int, stop_point: int, alpha: float) -> bool:
#     return p_value(values, start_point, stop_point) > alpha


def is_reflection(seq: IPIDSequence) -> bool:
    recv = seq.s.sequence.tolist()
    sent = config.reflection_send_ip_ids
    m = len(sent)

    if not recv:
        return False

    first_offset = (recv[0] - sent[0]) % (MAX_IP_ID + 1)

    for i, ip_id in enumerate(recv):
        expected = (sent[i % m] + first_offset) % (MAX_IP_ID + 1)
        if ip_id != expected:
            return False

    return True


def is_constant(seq: IPIDSequence) -> bool:
    return np.all(seq.s.increments == 0)


def is_per_dst(seq: IPIDSequence) -> bool:
    return (seq.a.is_increasing(min_inc=1, max_inc=1) and
            seq.b.is_increasing(min_inc=1, max_inc=1))


def is_per_con(seq: IPIDSequence) -> bool:
    return (seq.ap.is_increasing(min_inc=1, max_inc=1) and
            seq.bp.is_increasing(min_inc=1, max_inc=1))
    # return (seq.ap_no_first.is_increasing(min_inc=1, max_inc=1) and
    #         seq.bp_no_first.is_increasing(min_inc=1, max_inc=1) and
    #         seq.cp_no_first.is_increasing(min_inc=1, max_inc=1) and
    #         seq.dp_no_first.is_increasing(min_inc=1, max_inc=1))


def is_per_bucket(seq: IPIDSequence) -> bool:
    return (seq.ap.is_increasing(min_inc=1, max_inc=MAX_INC) and
            seq.bp.is_increasing(min_inc=1, max_inc=MAX_INC))
    # return (seq.ap.is_increasing(min_inc=1, max_inc=MAX_INC) and
    #         seq.bp.is_increasing(min_inc=1, max_inc=MAX_INC) and
    #         seq.cp.is_increasing(min_inc=1, max_inc=MAX_INC) and
    #         seq.dp.is_increasing(min_inc=1, max_inc=MAX_INC))


def is_global(seq: IPIDSequence) -> bool:
    return seq.s.is_increasing(min_inc=1, max_inc=MAX_INC)


def is_multi_global(seq: IPIDSequence, max_clusters=MULTI_GLOBAL_MAX_CLUSTERS,
                    max_inc=MULTI_GLOBAL_CLUSTER_MAX_INC) -> bool:
    clusters: list[dict[int, np.int32]] = get_clusters(seq.s.sequence, max_diff=max_inc)

    # def check(sequence: list[np.int32]) -> bool:
    #     _seq = sequence.copy()
    #     single_count = 0
    #
    #     while _seq:
    #         inc = [_seq[0]]
    #         for x in _seq[1:]:
    #             if x > inc[-1]:
    #                 inc.append(x)
    #         _seq = [x for x in _seq if x not in inc]
    #
    #         if len(inc) == 1:
    #             single_count += 1
    #             if single_count > 1:
    #                 return False
    #     return True

    # for cluster in clusters:
    #     cluster_sequence = list(cluster.values())
    #     if not check(cluster_sequence):
    #         return False

    return 1 < len(clusters) <= max_clusters


def chi2_test(seq: np.ndarray) -> float:
    bins = 10
    hist, _ = np.histogram(seq, bins=bins, range=(0, MAX_IP_ID + 1))
    chi2, p_chi2 = chisquare(hist)
    return p_chi2


def fft_test(diffs: np.ndarray) -> float:
    # 1. Map to {-1, +1} (median split, robust gegen Bias)
    median = np.median(diffs)
    x = np.where(diffs > median, 1.0, -1.0)

    n = len(x)

    # 2. FFT
    fft_vals = np.fft.fft(x)
    mags = np.abs(fft_vals)[:n // 2]

    # 3. Threshold (NIST)
    T = sqrt(log(1 / 0.05) * n)

    # 4. Expected vs observed peaks
    N0 = 0.95 * n / 2
    N1 = np.sum(mags < T)

    # 5. Test statistic
    d = (N1 - N0) / sqrt(n * 0.95 * 0.05 / 4)

    # 6. p-value
    p_value = erfc(abs(d) / sqrt(2))

    return p_value


def frequency_test(diffs: np.ndarray) -> float:
    # Mapping to {-1, +1}
    median = np.median(diffs)
    x = np.where(diffs > median, 1.0, -1.0)

    n = len(x)

    # Test statistic
    s_obs = abs(np.sum(x)) / sqrt(n)

    # p-value
    p_value = erfc(s_obs / sqrt(2))

    return p_value


def runs_test(diffs: np.ndarray) -> float:
    # Mapping to {0,1}
    median = np.median(diffs)
    x = np.where(diffs > median, 1, 0)

    n = len(x)

    # Proportion of ones
    pi = np.mean(x)

    # Voraussetzung prüfen (NIST)
    if abs(pi - 0.5) >= (2 / sqrt(n)):
        return 0.0  # fails automatically

    # Anzahl Runs zählen
    runs = 1 + np.sum(x[:-1] != x[1:])

    # Erwartungswert und Varianz
    numerator = abs(runs - 2 * n * pi * (1 - pi))
    denominator = 2 * sqrt(2 * n) * pi * (1 - pi)

    p_value = erfc(numerator / denominator)

    return p_value


def cusum_test(diffs: np.ndarray) -> float:
    # Mapping to {-1, +1}
    median = np.median(diffs)
    x = np.where(diffs > median, 1.0, -1.0)
    n = len(x)

    # Forward cumulative sum
    cumsum_fwd = np.cumsum(x)
    z_fwd = np.max(np.abs(cumsum_fwd))

    # Backward cumulative sum
    cumsum_bwd = np.cumsum(x[::-1])
    z_bwd = np.max(np.abs(cumsum_bwd))

    def _p_value_from_z(z: float) -> float:
        if z == 0:
            return 1.0
        # Summe 1 (NIST SP800-22 Formel)
        k_start_1 = int((-n / z + 1) / 4)
        k_end_1 = int((n / z - 1) / 4)
        sum1 = 0.0
        for k in range(k_start_1, k_end_1 + 1):
            sum1 += norm_cdf((4 * k + 1) * z / sqrt(n))
            sum1 -= norm_cdf((4 * k - 1) * z / sqrt(n))

        # Summe 2
        k_start_2 = int((-n / z - 3) / 4)
        k_end_2 = int((n / z - 1) / 4)
        sum2 = 0.0
        for k in range(k_start_2, k_end_2 + 1):
            sum2 += norm_cdf((4 * k + 3) * z / sqrt(n))
            sum2 -= norm_cdf((4 * k + 1) * z / sqrt(n))

        return 1.0 - sum1 + sum2

    p_fwd = _p_value_from_z(z_fwd)
    p_bwd = _p_value_from_z(z_bwd)

    return min(p_fwd, p_bwd)


def norm_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / sqrt(2)))


def nist_test(diffs: np.ndarray) -> float:
    return min(
        fft_test(diffs),
        frequency_test(diffs),
        runs_test(diffs),
        cusum_test(diffs),
    )


def is_random(seq: IPIDSequence) -> bool:
    # if (chi2_test(seq.a.increments) < 1e-9 or
    #         chi2_test(seq.b.increments) < 1e-9):
    #     return False  # Filters REFLECTION, CONSTANT, GLOBAL, LOCAL(=1), LOCAL(>=1)
    z = min(chi2_test(seq.s.increments),
            chi2_test(seq.a.increments),
            chi2_test(seq.b.increments),
            chi2_test(seq.ap.increments),
            chi2_test(seq.bp.increments))
    if z < 1e-9:
        return False  # Filters REFLECTION, CONSTANT, GLOBAL, LOCAL(=1), LOCAL(>=1)

    # clusters: list[dict[int, np.int32]] = get_clusters(seq.full.sequence, max_diff=MULTI_GLOBAL_CLUSTER_MAX_INC)
    # for cluster in clusters:
    #     if len(cluster) < 20:
    #         continue
    #     cluster_sequence = np.array(list(cluster.values()))
    #
    #     if chi2_test(cluster_sequence) < 1e-8:
    #         return False  # Filters MULTI GLOBAL

    return True


def is_anomalous(seq: IPIDSequence, is_mass_scan: bool) -> bool:
    return not has_pattern(seq, is_mass_scan)


def has_pattern(seq: IPIDSequence, is_mass_scan: bool) -> bool:
    checks = (is_constant, is_per_dst, is_per_con, is_per_bucket, is_global)
    if is_mass_scan:
        checks += (is_multi_global, is_random)
    return any(fn(seq) for fn in checks)


def get_pattern(seq: IPIDSequence, is_mass_scan: bool, get_all=False) -> list[Pattern] | Pattern:
    result = []
    if config.detect_reflected_ip_ids and is_reflection(seq):
        result.append(Pattern.REFLECTION)
    if is_constant(seq):
        result.append(Pattern.CONSTANT)
    if is_per_dst(seq):
        result.append(Pattern.PER_DST)
    if is_per_con(seq):
        result.append(Pattern.PER_CON)
    if is_global(seq):
        result.append(Pattern.GLOBAL)
    if is_per_bucket(seq):
        result.append(Pattern.PER_BUCKET)
    if is_mass_scan:
        if is_multi_global(seq):
            result.append(Pattern.PER_CPU)
        if is_random(seq):
            result.append(Pattern.RANDOM)

    if is_anomalous(seq, is_mass_scan):
        result.append(Pattern.FALLBACK)

    return result if get_all else result[0]


# endregion


# TODO: Update is_random, multi global

# region Sequence Generation
def random_ip_id() -> int:
    return random.randint(0, MAX_IP_ID)


def clamp(value: int, min_value: int, max_value: int) -> int:
    return max(min_value, min(value, max_value))


def increment_ip_id(ip_id: int, inc: int) -> int:
    return (ip_id + inc) % (MAX_IP_ID + 1)


def reflection_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    for i in range(length):
        seq.append(config.reflection_send_ip_ids[i % len(config.reflection_send_ip_ids)])
    return IPIDSequence(seq)


def constant_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    s = random_ip_id()
    for i in range(length):
        seq.append(s)
    return IPIDSequence(seq)


def per_dst_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ip_id()
    b = random_ip_id()
    for i in range(length):
        if i % 6 in [0, 1, 4]:
            a = increment_ip_id(a, 1)
            seq.append(a)
        elif i % 6 in [2, 3, 5]:
            b = increment_ip_id(b, 1)
            seq.append(b)
        # if i % 8 in [0, 2, 4, 6]:
        #     a = increment_ip_id(a, 1)
        #     seq.append(a)
        # elif i % 8 in [1, 3, 5, 7]:
        #     b = increment_ip_id(b, 1)
        #     seq.append(b)
    return IPIDSequence(seq)


def per_con_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ip_id()
    b = random_ip_id()
    # seq = [random_ip_id() for _ in range(4)]
    # a = random_ip_id()
    # b = random_ip_id()
    # c = random_ip_id()
    # d = random_ip_id()
    for i in range(length):
        if i % 6 in [1, 4]:
            a = increment_ip_id(a, 1)
            seq.append(a)
        elif i % 6 in [2, 5]:
            b = increment_ip_id(b, 1)
            seq.append(b)
        # if i % 8 in [0, 4]:
        #     a = increment_ip_id(a, 1)
        #     seq.append(a)
        # elif i % 8 in [1, 5]:
        #     b = increment_ip_id(b, 1)
        #     seq.append(b)
        # elif i % 8 in [2, 6]:
        #     c = increment_ip_id(c, 1)
        #     seq.append(c)
        # elif i % 8 in [3, 7]:
        #     d = increment_ip_id(d, 1)
        #     seq.append(d)
        else:
            r = random_ip_id()
            seq.append(r)
    return IPIDSequence(seq)


def per_bucket_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ip_id()
    b = random_ip_id()
    # c = random_ip_id()
    # d = random_ip_id()
    for i in range(length):
        if i % 6 in [1, 4]:
            a = increment_ip_id(a, random.randint(1, LOCAL_GE1_MAX_INC))
            seq.append(a)
        elif i % 6 in [2, 5]:
            b = increment_ip_id(b, random.randint(1, LOCAL_GE1_MAX_INC))
            seq.append(b)
        # if i % 8 in [0, 4]:
        #     a = increment_ip_id(a, random.randint(1, LOCAL_GE1_MAX_INC))
        #     seq.append(a)
        # elif i % 8 in [1, 5]:
        #     b = increment_ip_id(b, random.randint(1, LOCAL_GE1_MAX_INC))
        #     seq.append(b)
        # elif i % 8 in [2, 6]:
        #     c = increment_ip_id(c, random.randint(1, LOCAL_GE1_MAX_INC))
        #     seq.append(c)
        # elif i % 8 in [3, 7]:
        #     d = increment_ip_id(d, random.randint(1, LOCAL_GE1_MAX_INC))
        #     seq.append(d)
        else:
            r = random_ip_id()
            seq.append(r)
    return IPIDSequence(seq)


def global_ip_id_sequence(length: int, max_inc: int = GLOBAL_MAX_INC) -> IPIDSequence:
    seq = []
    s = random_ip_id()
    avg_inc = random.randint(1, max_inc)  # correlated with avg pps of device
    dev_inc = max(int(random.random() * (max_inc - avg_inc)), 1)  # correlated with deviation of pps of device

    for i in range(length):
        s = increment_ip_id(s, clamp(avg_inc + random.randint(-dev_inc, dev_inc), 1, max_inc))
        seq.append(s)
    return IPIDSequence(seq)


def multi_global_ip_id_sequence(length: int, max_clusters=MULTI_GLOBAL_MAX_CLUSTERS,
                                max_inc=MULTI_GLOBAL_CLUSTER_MAX_INC) -> IPIDSequence:
    seq = []
    cluster_count = random.randint(2, max_clusters)

    sizes = [length // cluster_count] * cluster_count
    for i in range(length % cluster_count):
        sizes[i] += 1

    cluster_seqs = {
        i: global_ip_id_sequence(length=sizes[i], max_inc=max_inc).s.sequence.astype(
            int).tolist()
        for i in range(cluster_count)
    }

    while any(cluster_seqs.values()):
        i = random.choice([k for k in cluster_seqs if cluster_seqs[k]])
        seq.append(cluster_seqs[i].pop(0))

    return IPIDSequence(seq)


def random_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    for _ in range(length):
        seq.append(random_ip_id())
    return IPIDSequence(seq)


def fallback_ip_id_sequence(length: int) -> IPIDSequence:
    gen_map = {
        Pattern.CONSTANT: (constant_ip_id_sequence, is_constant),
        Pattern.GLOBAL: (global_ip_id_sequence, is_global),
        Pattern.PER_DST: (per_dst_ip_id_sequence, is_per_dst),
        Pattern.PER_CON: (per_con_ip_id_sequence, is_per_con),
        Pattern.PER_BUCKET: (per_bucket_ip_id_sequence, is_per_bucket)
    }

    pattern, (generator, check) = random.choice(list(gen_map.items()))
    sequence = generator(length).s.sequence.copy()

    n = max(1, length // 10)  # 10% of the length, minimum 1

    op = random.choice(["flip", "offset", "loss", "constant"])
    idx = np.random.choice(length, n, replace=False)

    if op == "flip":
        for i in idx:
            j = (i + 1) % length
            sequence[i], sequence[j] = sequence[j], sequence[i]

    elif op == "offset":
        sequence[idx] = (sequence[idx] + MAX_IP_ID // 2) % (MAX_IP_ID + 1)

    elif op == "loss":
        sequence = np.delete(sequence, idx)

    elif op == "constant":
        for i in idx:
            if i > 0:
                sequence[i] = sequence[i - 1]

    ip_id_seq = IPIDSequence(sequence)
    if check(ip_id_seq):
        return fallback_ip_id_sequence(length)
    return ip_id_seq


pattern_generation_map = {
    Pattern.REFLECTION: reflection_ip_id_sequence,
    Pattern.CONSTANT: constant_ip_id_sequence,
    Pattern.GLOBAL: global_ip_id_sequence,
    Pattern.PER_DST: per_dst_ip_id_sequence,
    Pattern.PER_CON: per_con_ip_id_sequence,
    Pattern.PER_BUCKET: per_bucket_ip_id_sequence,
    Pattern.PER_CPU: multi_global_ip_id_sequence,
    Pattern.RANDOM: random_ip_id_sequence,
    Pattern.FALLBACK: None,
}

# endregion
