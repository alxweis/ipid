import math
import random
from collections import defaultdict
from enum import Enum

import numpy as np
from scipy.stats import chisquare

MAX_IP_ID = 65535
MIN_STEPS_BEFORE_WRAPAROUND = 3
MAX_INC = math.ceil((MAX_IP_ID + 1) / MIN_STEPS_BEFORE_WRAPAROUND) - 1


class IPIDSubsequence:
    def __init__(self, sequence: np.ndarray):
        self.sequence: np.ndarray = sequence
        self.increments: np.ndarray = np.diff(self.sequence) % (MAX_IP_ID + 1)

    def is_increasing(self) -> bool:
        return np.all((1 <= self.increments) & (self.increments <= MAX_INC))


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


def get_clusters(values: np.ndarray):
    sorted_values = sorted(values)

    clusters = []
    current_cluster = [sorted_values[0]]

    for i in range(1, len(sorted_values)):
        # Check the difference to the previous number
        diff = sorted_values[i] - sorted_values[i-1]

        if diff < 100:
            # Numbers belong to the same cluster
            current_cluster.append(sorted_values[i])
        else:
            # New cluster starts
            clusters.append(current_cluster)
            current_cluster = [sorted_values[i]]

    # Add the last cluster
    clusters.append(current_cluster)

    return clusters


def p_value(values: np.ndarray) -> float:
    intervals = len(values) // 2
    interval_edges = np.linspace(0, MAX_IP_ID + 1, intervals + 1)
    observed_frequencies, _ = np.histogram(values, bins=interval_edges)
    expected_frequencies = np.full(intervals, len(values) / intervals)

    chi2_stat, p = chisquare(f_obs=observed_frequencies, f_exp=expected_frequencies)
    return p


def is_uniform(values: np.ndarray, alpha: float) -> bool:
    return p_value(values) > alpha


def is_constant(seq: IPIDSequence) -> bool:
    return np.all(seq.full.increments == 0)


def is_local(seq: IPIDSequence) -> bool:
    return seq.even.is_increasing() and seq.odd.is_increasing()


def is_local_eq1(seq: IPIDSequence) -> bool:
    return (is_local(seq)
            and np.all(seq.even.increments == 1)
            and np.all(seq.odd.increments == 1))


def is_local_ge1(seq: IPIDSequence) -> bool:
    return (is_local(seq)
            and np.all(seq.even.increments >= 1)
            and np.all(seq.odd.increments >= 1))


def is_global(seq: IPIDSequence) -> bool:
    return seq.full.is_increasing()


def is_multi_global(seq: IPIDSequence) -> bool:
    clusters = get_clusters(seq.full.sequence)
    return np.all(seq.full.increments >= 1) and len(clusters) <= len(seq.full.sequence) - 2


def is_random(seq: IPIDSequence) -> bool:
    alpha = 0.01
    return np.all(seq.full.increments >= 1) and is_uniform(seq.full.increments, alpha)


def is_anomalous(seq: IPIDSequence) -> bool:
    return not has_pattern(seq)


def has_pattern(seq: IPIDSequence) -> bool:
    return (
            is_constant(seq)
            or is_local_eq1(seq)
            or is_local_ge1(seq)
            or is_global(seq)
            or is_multi_global(seq)
            or is_random(seq)
    )


def get_pattern(seq: IPIDSequence, get_all=False) -> list[Pattern] | Pattern:
    result = []
    if is_constant(seq):
        result.append(Pattern.CONSTANT)
    if is_global(seq):
        result.append(Pattern.GLOBAL)
    if is_local_eq1(seq):
        result.append(Pattern.LOCAL_EQ1)
    if is_local_ge1(seq):
        result.append(Pattern.LOCAL_GE1)
    if is_multi_global(seq):
        result.append(Pattern.MULTI_GLOBAL)
    if is_random(seq):
        result.append(Pattern.RANDOM)
    if is_anomalous(seq):
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
    max_inc = 2000  # 1 tick = 1ms => Max RTT of 2000ms = 2000 ticks
    for i in range(length):
        if i % 2 == 0:
            a = increment_ip_id(a, random.randint(1, max_inc))
            seq.append(a)
        else:
            b = increment_ip_id(b, random.randint(1, max_inc))
            seq.append(b)
    return IPIDSequence(seq)


def global_ip_id_sequence(length: int, max_inc: int = MAX_INC) -> IPIDSequence:
    seq = []
    s = random_ip_id()
    avg_inc = random.randint(1, MAX_INC)  # correlated with avg pps of device
    dev = max(int(0.5 * avg_inc), 1)  # correlated with deviation of pps of device

    for i in range(length):
        s = increment_ip_id(s, clamp(avg_inc + random.randint(-dev, dev), 1, max_inc))
        seq.append(s)
    return IPIDSequence(seq)


def multi_global_ip_id_sequence(length: int) -> IPIDSequence:
    seq = []
    cluster_count = random.randint(2, 4)

    sizes = [length // cluster_count] * cluster_count
    for i in range(length % cluster_count):
        sizes[i] += 1

    cluster_seqs = {
        i: global_ip_id_sequence(length=sizes[i], max_inc=10).full.sequence.astype(int).tolist()
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


pattern_generation_map = {
    Pattern.CONSTANT: constant_ip_id_sequence,
    Pattern.GLOBAL: global_ip_id_sequence,
    Pattern.LOCAL_EQ1: local_eq1_ip_id_sequence,
    Pattern.LOCAL_GE1: local_ge1_ip_id_sequence,
    Pattern.MULTI_GLOBAL: multi_global_ip_id_sequence,
    Pattern.RANDOM: random_ip_id_sequence
}

# endregion


# region Classifier Testing
sequence_length = 20
sequence_count_per_pattern = 10000
for real_pattern, generator in pattern_generation_map.items():

    true_classified = 0
    false_classified_data = defaultdict(int)

    for i in range(sequence_count_per_pattern):
        seq: IPIDSequence = generator(sequence_length)
        classified_pattern: Pattern = get_pattern(seq)

        if real_pattern.value == classified_pattern.value:
            true_classified += 1
        else:
            false_classified_data[classified_pattern.value] += 1

    false_classified = sequence_count_per_pattern - true_classified
    print(
        f"{real_pattern.value}: total={sequence_count_per_pattern} true_classified={true_classified} false_classified={false_classified} recall={true_classified / (true_classified + false_classified)}"
    )
    print(f"False classified breakdown: {dict(false_classified_data)}")

# endregion
