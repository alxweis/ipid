import math
import os.path
import random
from collections import OrderedDict
from enum import Enum

import numpy as np
import pandas as pd
import polars as pl
import seaborn as sns
from matplotlib import pyplot as plt
from scipy.stats import chisquare

from core import EXP_SEQUENCE_STABLE_LEN_ANALYSIS
from core.utils import config

# We have a given random sequence: (A-B-C-D-E-F-...)

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
    def __init__(self, sequence: list[int] | tuple[int, ...] | np.ndarray):
        arr = np.array(sequence, dtype=int)
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


def is_random(seq: IPIDSequence) -> bool:
    alpha = 0.01
    return is_uniform(seq.full.increments, alpha) and is_uniform(seq.even.increments, alpha) and is_uniform(
        seq.odd.increments,
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
        result.append(Pattern.FALLBACK)
    return result if get_all else result[0]


# endregion


# region Sequence Generation
def random_ipid() -> int:
    return random.randint(0, MAX_IPID)


def clamp(value: int, min_value: int, max_value: int) -> int:
    return max(min_value, min(value, max_value))


def increment_ipid(ipid: int, inc: int) -> int:
    return (ipid + inc) % (MAX_IPID + 1)


def constant_ipid_sequence(length: int) -> IPIDSequence:
    seq = []
    s = random_ipid()
    for i in range(length):
        seq.append(s)
    return IPIDSequence(seq)


def local_eq1_ipid_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ipid()
    b = random_ipid()
    for i in range(length):
        if i % 2 == 0:
            a = increment_ipid(a, 1)
            seq.append(a)
        else:
            b = increment_ipid(b, 1)
            seq.append(b)
    return IPIDSequence(seq)


def local_ge1_ipid_sequence(length: int) -> IPIDSequence:
    seq = []
    a = random_ipid()
    b = random_ipid()
    max_inc = 2000  # 1 tick = 1ms => Max RTT of 2000ms = 2000 ticks
    for i in range(length):
        if i % 2 == 0:
            a = increment_ipid(a, random.randint(1, max_inc))
            seq.append(a)
        else:
            b = increment_ipid(b, random.randint(1, max_inc))
            seq.append(b)
    return IPIDSequence(seq)


def global_ipid_sequence(length: int) -> IPIDSequence:
    seq = []
    s = random_ipid()
    avg_inc = random.randint(1, MAX_INC)  # correlated with avg pps of device
    dev = max(int(0.5 * avg_inc), 1)  # correlated with deviation of pps of device

    for i in range(length):
        s = increment_ipid(s, clamp(avg_inc + random.randint(-dev, dev), 1, MAX_INC))
        seq.append(s)
    return IPIDSequence(seq)


def random_ipid_sequence(length: int) -> IPIDSequence:
    seq = []
    for _ in range(length):
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


def calc_min_stable_len(seq: IPIDSequence) -> (Pattern, int):
    min_stable_len = 0
    last_classified_pattern = Pattern.NONE

    for i in range(2, len(seq) + 1):
        prefix_seq = IPIDSequence(seq.full.sequence[:i])
        classified_pattern = get_pattern(prefix_seq)

        if last_classified_pattern == Pattern.NONE or classified_pattern == last_classified_pattern:
            if min_stable_len == 0:
                min_stable_len = i
        else:
            min_stable_len = 0

        last_classified_pattern = classified_pattern

    return last_classified_pattern, min_stable_len


def evaluate(pattern_to_min_stable_lens, output_dir: str, filename: str):
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, filename + ".txt")

    with open(output_file, 'w', encoding='utf-8') as file:
        # Calculate and print average and standard deviation
        for stable_pattern, min_stable_lens in pattern_to_min_stable_lens.items():
            if min_stable_lens:
                avg = np.mean(min_stable_lens)
                std = np.std(min_stable_lens)
                file.write(f"{stable_pattern.value}: avg = {avg:.2f}, std = {std:.2f}\n")
            else:
                file.write(f"{stable_pattern.value}: no stable classification found.\n")

    # Print the content of the file
    with open(output_file, 'r', encoding='utf-8') as file:
        print(file.read())

    # Create boxplot
    plot_stable_len_boxplot(pattern_to_min_stable_lens, output_dir, filename)


def plot_stable_len_boxplot(pattern_to_min_stable_lens: dict[Pattern, list[int]], output_dir: str, filename: str):
    labels = []
    data = []

    for pattern, lengths in pattern_to_min_stable_lens.items():
        if lengths:
            labels.append(pattern.value)
            data.append(lengths)

    # Setting a nicer style for the plot
    sns.set(style="whitegrid")

    # Create the figure and axis
    plt.figure(figsize=(12, 8))

    # Create a horizontal boxplot
    box = plt.boxplot(data, vert=False, patch_artist=True,
                      boxprops=dict(facecolor='skyblue', color='blue'),
                      whiskerprops=dict(color='blue'),
                      capprops=dict(color='blue'),
                      medianprops=dict(color='red'))

    # Customizing the plot labels and title
    plt.yticks(ticks=range(1, len(labels) + 1), labels=labels, fontsize=12)
    plt.xlabel("Sequence Length to Stable Classification", fontsize=14)
    plt.ylabel("IPID Pattern", fontsize=14)
    plt.title("Distribution of Minimum Stable Classification Length for IPID Patterns", fontsize=16)

    # Adding grid for clarity
    plt.grid(True, axis='x', linestyle='--', alpha=0.7)

    # Adjust layout to make sure everything fits nicely
    plt.tight_layout()

    # Save the plot to a file
    output_file = os.path.join(output_dir, filename + ".png")
    plt.savefig(output_file, bbox_inches='tight', dpi=300)
    print(f"Plot saved at {output_file}")
    plt.close()


def analyze_sequence_stable_lens_synthetic(sequence_count_per_pattern: int, sequence_length: int):
    pattern_to_min_stable_lens: OrderedDict[Pattern, list[int]] = OrderedDict(
        (p, []) for p in Pattern
    )

    for _, create_seq in pattern_generation_map.items():
        for _ in range(sequence_count_per_pattern):
            seq = create_seq(length=sequence_length)

            last_classified_pattern, min_stable_len = calc_min_stable_len(seq)

            if min_stable_len > 0:
                pattern_to_min_stable_lens.setdefault(last_classified_pattern, []).append(min_stable_len)

    evaluate(pattern_to_min_stable_lens, EXP_SEQUENCE_STABLE_LEN_ANALYSIS,
             f"min_sequence_stable_lens_synthetic_{sequence_count_per_pattern * len(pattern_generation_map)}_{sequence_length}")


def analyze_sequence_stable_lens_natural(probing_csv: str):
    def parse_sequence(seq_str: str) -> IPIDSequence:
        return IPIDSequence(np.fromstring(seq_str[1:-1], sep=",", dtype=int))

    pattern_to_min_stable_lens: OrderedDict[Pattern, list[int]] = OrderedDict(
        (p, []) for p in Pattern
    )

    sequences = pl.read_csv(probing_csv, columns=[config.ip_id_seq_col_name])
    row_count = sequences.height

    first_seq = parse_sequence(sequences[0, 0])
    sequence_length = len(first_seq)

    for row in sequences.iter_rows():
        seq = parse_sequence(row[0])

        last_classified_pattern, min_stable_len = calc_min_stable_len(seq)

        if min_stable_len > 0:
            pattern_to_min_stable_lens.setdefault(last_classified_pattern, []).append(min_stable_len)

    evaluate(pattern_to_min_stable_lens, os.path.dirname(probing_csv), "min_sequence_stable_lens")
