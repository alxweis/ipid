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
MAX_UNIFORM_INC_TOLERANCE = 0.5

GLOBAL_MAX_INC = MAX_INC
MAX_INC_TOLERANCE = 0.3
MULTI_GLOBAL_MAX_INC = 100
MULTI_GLOBAL_MAX_CLUSTERS = 4
LOCAL_GE1_MAX_INC = int(timeparse(config.max_rtt) * 1000)
UNIFORM_INC_ALPHA = 0.03
RANDOM_ALPHA = 0.05


class IPIDSubsequence:
    def __init__(self, sequence: np.ndarray):
        self.sequence: np.ndarray = sequence
        self.increments: np.ndarray = np.diff(self.sequence) % (MAX_IP_ID + 1)

    def is_increasing(self) -> bool:
        return np.all((1 <= self.increments) & (self.increments <= MAX_INC))

    def is_uniformly_increasing(self, lower_inc_bound: int = None, upper_inc_bound: int = None) -> bool:
        if not self.is_increasing():
            return False

        avg_inc = None
        if not lower_inc_bound or not upper_inc_bound:
            avg_inc = np.mean(self.increments)

        if not lower_inc_bound:
            lower_inc_bound = avg_inc * (1 - MAX_UNIFORM_INC_TOLERANCE)

        if not upper_inc_bound:
            upper_inc_bound = avg_inc * (1 + MAX_UNIFORM_INC_TOLERANCE)

        return np.all((self.increments >= lower_inc_bound) & (self.increments <= upper_inc_bound))

    def has_uniform_increments(self) -> bool:
        return is_uniform(values=self.increments, start_point=0, stop_point=LOCAL_GE1_MAX_INC + 1,
                          alpha=UNIFORM_INC_ALPHA)


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


def get_clusters(values: np.ndarray) -> list[dict[int, np.int32]]:
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

        if diff > MULTI_GLOBAL_MAX_INC:
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
            final_clusters.append(cluster)

        start_idx = break_idx

    for cluster in final_clusters:
        arr = np.array(list(cluster.values()), dtype=np.int32)
        cluster_seq = IPIDSequence(arr)
        if not cluster_seq.full.is_increasing():
            return []

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
    return (seq.even.is_uniformly_increasing(lower_inc_bound=1, upper_inc_bound=1) and
            seq.odd.is_uniformly_increasing(lower_inc_bound=1, upper_inc_bound=1) and
            np.all(seq.even.increments == 1) and
            np.all(seq.odd.increments == 1))


def is_local_ge1(seq: IPIDSequence) -> bool:
    return (seq.even.is_uniformly_increasing(lower_inc_bound=1, upper_inc_bound=LOCAL_GE1_MAX_INC) and
            seq.odd.is_uniformly_increasing(lower_inc_bound=1, upper_inc_bound=LOCAL_GE1_MAX_INC) and
            seq.even.has_uniform_increments() and
            seq.odd.has_uniform_increments() and
            np.all(seq.even.increments >= 1) and
            np.all(seq.odd.increments >= 1))


def is_global(seq: IPIDSequence) -> bool:
    return seq.full.is_uniformly_increasing()


def is_multi_global(seq: IPIDSequence) -> bool:
    clusters = get_clusters(seq.full.sequence)
    return np.all(seq.full.increments >= 1) and 1 < len(clusters) <= MULTI_GLOBAL_MAX_CLUSTERS


def is_random(seq: IPIDSequence) -> bool:
    return np.all(seq.full.increments >= 1) and is_uniform(values=seq.full.increments, start_point=0,
                                                           stop_point=MAX_IP_ID + 1, alpha=RANDOM_ALPHA)


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
    avg_inc = random.randint(1, int((1 - MAX_INC_TOLERANCE) * max_inc))  # correlated with avg pps of device
    dev_inc = max(int(MAX_INC_TOLERANCE * avg_inc), 1)  # correlated with deviation of pps of device

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
        i: global_ip_id_sequence(length=sizes[i], max_inc=MULTI_GLOBAL_MAX_INC).full.sequence.astype(int).tolist()
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
