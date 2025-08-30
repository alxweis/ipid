import math
import random
from enum import Enum

import numpy as np
from pytimeparse.timeparse import timeparse
from scipy.stats import chisquare

from core.utils import config

MAX_IP_ID = 65535
MIN_STEPS_BEFORE_WRAPAROUND = 3
MAX_INC = math.ceil((MAX_IP_ID + 1) / MIN_STEPS_BEFORE_WRAPAROUND) - 1

GLOBAL_MAX_INC = MAX_INC
GLOBAL_MAX_INC_TOLERANCE = 0.5

LOCAL_GE1_MAX_INC = int(timeparse(config.min_rtt) * 1000)

MULTI_GLOBAL_CLUSTER_MAX_INC = 100
MULTI_GLOBAL_MAX_CLUSTERS = 10

RANDOM_CLUSTER_MAX_INC = 1000

CHI2_TEST_MAX = 1e-5
DIR_SWITCH_MIN = 0.49
DIR_SWITCH_MAX = 0.83
AUTOCORR_MIN = 0.45
AUTOCORR_MAX_LAG = 10


class IPIDSubsequence:
    def __init__(self, sequence: np.ndarray):
        self.sequence: np.ndarray = sequence
        self.increments: np.ndarray = np.diff(self.sequence) % (MAX_IP_ID + 1)

    def is_increasing(self, min_inc: int, max_inc: int) -> bool:
        return np.all((min_inc <= self.increments) & (self.increments <= max_inc))


class IPIDSequence:
    def __init__(self, sequence: list[int] | tuple[int, ...] | np.ndarray):
        arr = np.array(sequence, dtype=np.int32)
        self.full = IPIDSubsequence(arr)
        self.even = IPIDSubsequence(arr[0::2])
        self.odd = IPIDSubsequence(arr[1::2])

    def __len__(self):
        return len(self.full.sequence)


class Pattern(Enum):
    REFLECTION = "Reflection"
    CONSTANT = "Constant"
    GLOBAL = "Global"
    LOCAL_EQ1 = "Local (=1)"  # per-destination/ per-connection counter
    LOCAL_GE1 = "Local (≥1)"  # per-bucket counter
    MULTI_GLOBAL = "Multi Global"  # per-cpu counter when >1 cpu
    RANDOM = "Random"
    FALLBACK = "Fallback"
    NONE = "None"


# region Class Recognition
def nrm_entropy(values: np.ndarray) -> float:
    unique_values, counts = np.unique(values, return_counts=True)
    probabilities = counts / counts.sum()
    entropy = -np.sum(probabilities * np.log2(probabilities))
    max_entropy = np.log2(len(unique_values))  # Max Entropy based on unique values
    return entropy / max_entropy


def get_clusters(values: np.ndarray, max_diff: int) -> list[dict[int, np.int32]]:
    if not values.size:
        return []

    idx_to_val = {i: np.int32(val) for i, val in enumerate(values)}
    idx_to_val = dict(sorted(idx_to_val.items(), key=lambda item: item[1]))

    breaks = []
    val_count = len(idx_to_val)

    for i in range(val_count):
        _, current_val = list(idx_to_val.items())[i]
        _, next_val = list(idx_to_val.items())[(i + 1) % val_count]

        diff = (next_val - current_val + (MAX_IP_ID + 1)) % (MAX_IP_ID + 1)

        if diff > max_diff:
            breaks.append((i + 1) % val_count)

    if not breaks:
        return [dict(sorted(idx_to_val.items()))]

    final_clusters = []
    start_idx = breaks[-1] if breaks else 0

    for break_idx in breaks:
        cluster = {}
        current_idx = start_idx
        while current_idx != break_idx:
            idx, val = list(idx_to_val.items())[current_idx]
            cluster[idx] = val
            current_idx = (current_idx + 1) % val_count

        if cluster:
            final_clusters.append(dict(sorted(cluster.items())))

        start_idx = break_idx

    return final_clusters


def p_value(values: np.ndarray, start_point: int, stop_point: int) -> float:
    intervals = len(values) // 2
    interval_edges = np.linspace(start_point, stop_point, intervals + 1)
    observed_frequencies, _ = np.histogram(values, bins=interval_edges)
    expected_frequencies = np.full(intervals, len(values) / intervals)

    chi2_stat, p = chisquare(f_obs=observed_frequencies, f_exp=expected_frequencies)
    return p


def is_uniform(values: np.ndarray, start_point: int, stop_point: int, alpha: float) -> bool:
    return p_value(values, start_point, stop_point) > alpha


def is_reflection(seq: IPIDSequence) -> bool:
    return all(ip_id == config.reflection_send_ip_ids[i % len(config.reflection_send_ip_ids)]
               for i, ip_id in enumerate(seq.full.sequence.tolist()))


def is_constant(seq: IPIDSequence) -> bool:
    return np.all(seq.full.increments == 0)


def is_local_eq1(seq: IPIDSequence) -> bool:
    return (seq.even.is_increasing(min_inc=1, max_inc=1) and
            seq.odd.is_increasing(min_inc=1, max_inc=1))


def is_local_ge1(seq: IPIDSequence) -> bool:
    return (seq.even.is_increasing(min_inc=1, max_inc=MAX_INC) and
            seq.odd.is_increasing(min_inc=1, max_inc=MAX_INC))


def is_global(seq: IPIDSequence) -> bool:
    return seq.full.is_increasing(min_inc=1, max_inc=MAX_INC)


def is_multi_global(seq: IPIDSequence) -> bool:
    clusters: list[dict[int, np.int32]] = get_clusters(seq.full.sequence, max_diff=MULTI_GLOBAL_CLUSTER_MAX_INC)

    def check(sequence: list[np.int32]) -> bool:
        _seq = sequence.copy()
        counter = 0
        segments = []

        while _seq:
            inc = [_seq[0]]
            for x in _seq[1:]:
                if x > inc[-1]:
                    inc.append(x)
            for x in inc:
                _seq.remove(x)
            segments.append(inc)
            if len(inc) == 1:
                counter += 1
                if counter > 1:
                    return False
        return True

    for cluster in clusters:
        cluster_sequence = list(cluster.values())
        if not check(cluster_sequence):
            return False

    return 1 < len(clusters) <= MULTI_GLOBAL_MAX_CLUSTERS


def chi2_test(seq: IPIDSequence) -> float:
    bins = 16
    hist, _ = np.histogram(seq.full.sequence, bins=bins, range=(0, MAX_IP_ID + 1))
    chi2, p_chi2 = chisquare(hist)
    return p_chi2


def dir_switch_count(seq: IPIDSequence) -> int:
    diff = np.diff(seq.full.sequence)
    signs = np.sign(diff)
    return np.count_nonzero(signs[1:] != signs[:-1]) + 1


def autocorr(seq: IPIDSequence, lag: int) -> float:
    if is_constant(seq):
        return 0
    corr = np.corrcoef(seq.full.sequence[:-lag], seq.full.sequence[lag:])[0, 1]
    return float(abs(corr))


def is_random(seq: IPIDSequence) -> bool:
    # 1) Chi²-Test
    if chi2_test(seq) < CHI2_TEST_MAX:
        return False  # Filters REFLECTION, CONSTANT, LOCAL(=1)

    # 2) Direction-Change
    runs = dir_switch_count(seq)
    if runs < len(seq) * DIR_SWITCH_MIN or runs > len(seq) * DIR_SWITCH_MAX:
        return False  # Filters GLOBAL

    # 3) Autocorrelation
    for lag in range(1, AUTOCORR_MAX_LAG + 1):
        if autocorr(seq, lag) > AUTOCORR_MIN:
            return False

    return True


def is_anomalous(seq: IPIDSequence, is_mass_scan: bool) -> bool:
    return not has_pattern(seq, is_mass_scan)


def has_pattern(seq: IPIDSequence, is_mass_scan: bool) -> bool:
    checks = (is_constant, is_local_eq1, is_local_ge1, is_global)
    if is_mass_scan:
        checks += (is_multi_global, is_random)
    return any(fn(seq) for fn in checks)


def get_pattern(seq: IPIDSequence, is_mass_scan: bool, get_all=False) -> list[Pattern] | Pattern:
    result = []
    if config.detect_reflected_ip_ids and is_reflection(seq):
        result.append(Pattern.REFLECTION)
    if is_constant(seq):
        result.append(Pattern.CONSTANT)
    if is_global(seq):
        result.append(Pattern.GLOBAL)
    if is_local_eq1(seq):
        result.append(Pattern.LOCAL_EQ1)
    if is_local_ge1(seq):
        result.append(Pattern.LOCAL_GE1)

    if is_mass_scan:
        if is_multi_global(seq):
            result.append(Pattern.MULTI_GLOBAL)
        if is_random(seq):
            result.append(Pattern.RANDOM)

    if is_anomalous(seq, is_mass_scan):
        result.append(Pattern.FALLBACK)

    return result if get_all else result[0]


# endregion


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


def local_eq1_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ip_id()
    b = random_ip_id()
    for i in range(length):
        if i % 2 == 0:
            a = increment_ip_id(a, 1)
            seq.append(a)
        else:
            b = increment_ip_id(b, 1)
            seq.append(b)
    return IPIDSequence(seq)


def local_ge1_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ip_id()
    b = random_ip_id()
    for i in range(length):
        if i % 2 == 0:
            a = increment_ip_id(a, random.randint(1, LOCAL_GE1_MAX_INC))
            seq.append(a)
        else:
            b = increment_ip_id(b, random.randint(1, LOCAL_GE1_MAX_INC))
            seq.append(b)
    return IPIDSequence(seq)


def global_ip_id_sequence(length: int, max_inc: int = GLOBAL_MAX_INC) -> IPIDSequence:
    seq = []
    s = random_ip_id()
    tolerance = GLOBAL_MAX_INC_TOLERANCE - 0.1
    avg_inc = random.randint(1, int((1 - tolerance) * max_inc))  # correlated with avg pps of device
    dev_inc = max(int(tolerance * avg_inc), 1)  # correlated with deviation of pps of device

    for i in range(length):
        s = increment_ip_id(s, clamp(avg_inc + random.randint(-dev_inc, dev_inc), 1, max_inc))
        seq.append(s)
    return IPIDSequence(seq)


def multi_global_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    cluster_count = random.randint(2, MULTI_GLOBAL_MAX_CLUSTERS)

    sizes = [length // cluster_count] * cluster_count
    for i in range(length % cluster_count):
        sizes[i] += 1

    cluster_seqs = {
        i: global_ip_id_sequence(length=sizes[i], max_inc=MULTI_GLOBAL_CLUSTER_MAX_INC).full.sequence.astype(
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
        Pattern.LOCAL_EQ1: (local_eq1_ip_id_sequence, is_local_eq1),
        Pattern.LOCAL_GE1: (local_ge1_ip_id_sequence, is_local_ge1)
    }

    pattern, (generator, check) = random.choice(list(gen_map.items()))
    sequence = generator(length).full.sequence.copy()

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
    Pattern.LOCAL_EQ1: local_eq1_ip_id_sequence,
    Pattern.LOCAL_GE1: local_ge1_ip_id_sequence,
    Pattern.MULTI_GLOBAL: multi_global_ip_id_sequence,
    Pattern.RANDOM: random_ip_id_sequence,
    Pattern.FALLBACK: None,
}

# endregion
