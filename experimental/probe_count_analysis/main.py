# We have a given random sequence: (A-B-C-D-E-F-...)
import math
import random
from enum import Enum

import numpy as np
from scipy.stats import chisquare

# 3 Indices: (A-B-C)                => Result: Global (F)
# 4 Indices: (A-B-C-D)              => Result: Global (F)
# 5 Indices: (A-B-C-D-E)            => Result: Global (F)
# 6 Indices: (A-B-C-D-E-F)          => Result: Random (C)
# 7 Indices: (A-B-C-D-E-F-G)        => Result: Random (C)
# 8 Indices: (A-B-C-D-E-F-G-H-...)  => Result: Random (C)
# ==> Correct Result:               Random
# ==> My Result:                    Random
# ==> MinStableCorrectCount:        6
# ==> This sequence had to be at least 6 numbers long to determine the result correctly
# Repeat this process for many more random sequences and save the MinStableCorrectCount
# Calculate average and standard deviation value for all MinStableCorrectCount values
# Repeat this process for all patterns (Constant, Local, Global, Random)
# E.g. Result:
# Pattern   Avg MinStableCorrectCount   Std MinStableCorrectCount
# Constant  3                           1
# Local     4                           0.5
# Global    6                           1.5
# Random    8                           1
# During probing, calculate the pattern after each new number in the sequence is obtained. Stop collecting further
# numbers once the current sequence index exceeds the MinStableCorrectCount for the identified pattern
# Define threshold: Avg MinStableCorrectCount + 2 * Std MinStableCorrectCount

MAX_IPID = 65535
MAX_SEQ_LEN = 10
MIN_STEPS_BEFORE_WRAPAROUND = 3
MAX_INC = math.ceil((MAX_IPID + 1) / MIN_STEPS_BEFORE_WRAPAROUND) - 1


# region Class Recognition
class IPIDSubsequence:
    def __init__(self, sequence: np.ndarray):
        self.sequence: np.ndarray = sequence
        self.increments: np.ndarray = np.diff(self.sequence) % (MAX_IPID + 1)

    def is_increasing(self) -> bool:
        return np.all((1 <= self.increments) & (self.increments <= MAX_INC))


class IPIDSequence:
    def __init__(self, sequence: list[int]):
        arr = np.array(sequence, dtype=int)
        self.s = IPIDSubsequence(arr)
        self.a = IPIDSubsequence(arr[0::2])
        self.b = IPIDSubsequence(arr[1::2])


class Pattern(Enum):
    CONSTANT = "constant"
    GLOBAL = "global"
    LOCAL_EQ1 = "local_eq1"
    LOCAL_GE1 = "local_ge1"
    RANDOM = "random"
    ANOMALOUS = "anomalous"
    NONE = "none"


def nrm_entropy(values: np.ndarray) -> float:
    unique_values, counts = np.unique(values, return_counts=True)
    probabilities = counts / counts.sum()
    entropy = -np.sum(probabilities * np.log2(probabilities))
    max_entropy = np.log2(len(unique_values))  # Max Entropy based on unique values
    return entropy / max_entropy


def p_value(values: np.ndarray) -> float:
    intervals = int(math.ceil(math.sqrt(len(values))))
    interval_edges = np.linspace(0, MAX_IPID, intervals + 1)
    observed_frequencies, _ = np.histogram(values, bins=interval_edges)
    total_numbers = len(values)
    expected_frequencies = np.full(intervals, total_numbers / intervals)

    chi2_stat, p = chisquare(f_obs=observed_frequencies, f_exp=expected_frequencies)
    return p


def is_uniform(values: np.ndarray, alpha: float) -> bool:
    return p_value(values) > alpha


def is_constant(seq: IPIDSequence) -> bool:
    return np.all(seq.s.increments == 0)


def is_local(seq: IPIDSequence) -> bool:
    return seq.a.is_increasing() and seq.b.is_increasing()


def is_local_eq1(seq: IPIDSequence) -> bool:
    return (is_local(seq)
            and np.all(seq.a.increments == 1)
            and np.all(seq.b.increments == 1))


def is_local_ge1(seq: IPIDSequence) -> bool:
    return (is_local(seq)
            and np.all(seq.a.increments >= 1)
            and np.all(seq.b.increments >= 1))


def is_global(seq: IPIDSequence) -> bool:
    return seq.s.is_increasing()


def is_random(seq: IPIDSequence) -> bool:
    alpha = 0.01
    return is_uniform(seq.s.increments, alpha) and is_uniform(seq.a.increments, alpha) and is_uniform(seq.b.increments,
                                                                                                      alpha)


def is_anomalous(seq: IPIDSequence) -> bool:
    return not has_pattern(seq)


def has_pattern(seq: IPIDSequence) -> bool:
    return (
            is_constant(seq)
            or is_local_eq1(seq)
            or is_local_ge1(seq)
            or is_global(seq)
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
    if is_random(seq):
        result.append(Pattern.RANDOM)
    if is_anomalous(seq):
        result.append(Pattern.ANOMALOUS)
    return result if get_all else result[0]


# endregion


# region Sequence Generation
def random_ipid() -> int:
    return random.randint(0, MAX_IPID)


def clamp(value: int, min_value: int, max_value: int) -> int:
    return max(min_value, min(value, max_value))


def increment_ipid(ipid: int, inc: int) -> int:
    return (ipid + inc) % (MAX_IPID + 1)


def constant_ipid_sequence() -> IPIDSequence:
    seq = []
    s = random_ipid()
    for i in range(MAX_SEQ_LEN):
        seq.append(s)
    return IPIDSequence(seq)


def local_eq1_ipid_sequence() -> IPIDSequence:
    seq = []
    a = random_ipid()
    b = random_ipid()
    for i in range(MAX_SEQ_LEN):
        if i % 2 == 0:
            a = increment_ipid(a, 1)
            seq.append(a)
        else:
            b = increment_ipid(b, 1)
            seq.append(b)
    return IPIDSequence(seq)


def local_ge1_ipid_sequence() -> IPIDSequence:
    seq = []
    a = random_ipid()
    b = random_ipid()
    max_inc = 2000  # 1 tick = 1ms => Max RTT of 2000ms = 2000 ticks
    for i in range(MAX_SEQ_LEN):
        if i % 2 == 0:
            a = increment_ipid(a, random.randint(1, max_inc))
            seq.append(a)
        else:
            b = increment_ipid(b, random.randint(1, max_inc))
            seq.append(b)
    return IPIDSequence(seq)


def global_ipid_sequence() -> IPIDSequence:
    seq = []
    s = random_ipid()
    avg_inc = random.randint(1, MAX_INC)  # correlated with avg pps of device
    dev = max(int(0.5 * avg_inc), 1)  # correlated with deviation of pps of device

    for i in range(MAX_SEQ_LEN):
        s = increment_ipid(s, clamp(avg_inc + random.randint(-dev, dev), 1, MAX_INC))
        seq.append(s)
    return IPIDSequence(seq)


def random_ipid_sequence() -> IPIDSequence:
    seq = []
    for _ in range(MAX_SEQ_LEN):
        seq.append(random_ipid())
    return IPIDSequence(seq)


pattern_generation_map = {
    Pattern.CONSTANT: constant_ipid_sequence,
    Pattern.GLOBAL: global_ipid_sequence,
    Pattern.LOCAL_EQ1: local_eq1_ipid_sequence,
    Pattern.LOCAL_GE1: local_ge1_ipid_sequence,
    Pattern.RANDOM: random_ipid_sequence
}
# endregion


def analyze_sequence_stability_lengths(sequence_count_per_pattern: int):
    for _, create_seq in pattern_generation_map.items():
        pattern_to_min_stable_lens: dict[Pattern, list[int]] = {}

        for _ in range(sequence_count_per_pattern):
            seq = create_seq()
            # print(f"{seq.s.sequence}:")
            min_stable_len = 0
            last_classified_pattern = Pattern.NONE

            for i in range(2, MAX_SEQ_LEN + 1):
                prefix_seq = IPIDSequence(seq.s.sequence.tolist()[:i])
                classified_pattern = get_pattern(prefix_seq)
                # print(f"{prefix_seq.s.sequence} => {classified_pattern}")

                if last_classified_pattern == Pattern.NONE or classified_pattern == last_classified_pattern:
                    if min_stable_len == 0:
                        min_stable_len = i
                else:
                    min_stable_len = 0

                last_classified_pattern = classified_pattern

            if min_stable_len > 0:
                pattern_to_min_stable_lens.setdefault(last_classified_pattern, []).append(min_stable_len)

        for stable_pattern, min_stable_lens in pattern_to_min_stable_lens.items():
            if min_stable_lens:
                avg = np.mean(min_stable_lens)
                std = np.std(min_stable_lens)
                print(f"{stable_pattern}: avg = {avg:.2f}, std = {std:.2f}")
            else:
                print(f"{stable_pattern}: no stable classification found.")


def main():
    analyze_sequence_stability_lengths(sequence_count_per_pattern=1000)


if __name__ == "__main__":
    main()
