import os.path
import os.path
from collections import OrderedDict

import numpy as np
import polars as pl
import seaborn as sns
from matplotlib import pyplot as plt

from core import EXP_SEQUENCE_STABLE_LEN_ANALYSIS
from core.classifier import IPIDSequence, Pattern, get_pattern, pattern_generation_map
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
