import os.path
import os.path
from collections import Counter
from itertools import chain

import numpy as np
import polars as pl
import seaborn as sns
from matplotlib import pyplot as plt

from core import EXP_SEQUENCE_STABLE_LEN_ANALYSIS
from core.classifier import IPIDSequence, Pattern, get_pattern, pattern_generation_map
from postproc.main import parse_tuple_column


# We have a given sequence: (A-B-C-D-E-F-...)

# Length = 3: (A-B-C)                => Classification: X
# Length = 4: (A-B-C-D)              => Classification: X
# Length = 5: (A-B-C-D-E)            => Classification: X
# Length = 6: (A-B-C-D-E-F)          => Classification: Y (MIN STABLE LENGTH)
# Length = 7: (A-B-C-D-E-F-G)        => Classification: Y
# Length = 8: (A-B-C-D-E-F-G-H)      => Classification: Y
# Length = 9: (A-B-C-D-E-F-G-H-I)    => Classification: Y
# Length = 10: (A-B-C-D-E-F-G-H-I-J) => Classification: Y (MAX LENGTH)
# ==> Min. Length for Stable Classification:     6
# ==> After 6 numbers the final classification could already be determined


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


def plot_pattern_to_min_stable_lens(pattern_to_min_stable_lens: dict[Pattern, list[int]], sequence_length: int,
                                    output_dir: str, filename: str):
    pattern_to_min_stable_lens = dict(
        sorted(pattern_to_min_stable_lens.items(), key=lambda item: list(Pattern).index(item[0])))

    patterns = list(pattern_to_min_stable_lens.keys())
    all_values = list(chain.from_iterable(pattern_to_min_stable_lens.values()))
    min_value = min(all_values)
    min_stable_lens = np.arange(min_value, sequence_length + 1)

    freq_matrix = np.zeros((len(min_stable_lens), len(patterns)), dtype=float)

    for col_idx, pattern in enumerate(patterns):
        values = pattern_to_min_stable_lens[pattern]
        total = len(values)
        counts = Counter(values)
        for y_val, count in counts.items():
            row_idx = y_val - min_value
            freq_matrix[row_idx, col_idx] = (count / total) * 100  # convert to percent

    plt.figure(figsize=(7, 7))
    sns.heatmap(freq_matrix, annot=True, fmt=".0f", cmap="Blues",
                xticklabels=[p.value for p in patterns],
                yticklabels=min_stable_lens,
                cbar_kws={'label': 'Relative Frequency (%)'})
    plt.gca().collections[0].colorbar.ax.yaxis.label.set_size(16)
    plt.xlabel("Class", fontsize=18)
    plt.xticks(rotation=60, fontsize=16)
    plt.ylabel("Sequence Length", fontsize=18)
    plt.yticks(rotation=0, fontsize=16)
    plt.tight_layout()
    os.makedirs(output_dir, exist_ok=True)
    plt.savefig(os.path.join(output_dir, filename), bbox_inches='tight')
    plt.close()


def analyze_sequence_stable_lens_synthetic(sequence_count_per_pattern: int, sequence_length: int):
    pattern_to_min_stable_lens: dict[Pattern, list[int]] = {}

    for _, create_seq in pattern_generation_map.items():
        for _ in range(sequence_count_per_pattern):
            seq = create_seq(length=sequence_length)

            last_classified_pattern, min_stable_len = calc_min_stable_len(seq)

            if min_stable_len > 0:
                pattern_to_min_stable_lens.setdefault(last_classified_pattern, []).append(min_stable_len)

    plot_pattern_to_min_stable_lens(pattern_to_min_stable_lens, sequence_length,
                                    os.path.join(EXP_SEQUENCE_STABLE_LEN_ANALYSIS,
                                                 f"{sequence_count_per_pattern * len(pattern_generation_map)}_{sequence_length}"),
                                    "result.pdf")


def analyze_sequence_stable_lens_natural(probing_csv: str):
    pattern_to_min_stable_lens: dict[Pattern, list[int]] = {}
    sequence_length = -1

    def process_ip_ids(ip_ids):
        ip_id_sequence = IPIDSequence(ip_ids)

        nonlocal sequence_length
        if sequence_length < 0:
            sequence_length = len(ip_id_sequence.full.sequence)

        classified_pattern, min_stable_len = calc_min_stable_len(ip_id_sequence)
        return classified_pattern.value, min_stable_len

    df = (pl.scan_csv(probing_csv)
          .with_columns(parse_tuple_column(pl.col("IP_ID_SEQUENCE")).alias("ip_ids"))
          .with_columns(pl.col("ip_ids").map_elements(process_ip_ids, return_dtype=pl.Object).alias("result"))
          .with_columns(
        [pl.col("result").map_elements(lambda x: x[0], return_dtype=pl.Utf8).alias("classified_pattern"),
         pl.col("result").map_elements(lambda x: x[1], return_dtype=pl.Int64).alias("min_stable_len")])
          .drop("result")
          .select(["classified_pattern", "min_stable_len"])
          .collect())

    for row in df.iter_rows():
        if row[1] > 0:
            pattern_to_min_stable_lens.setdefault(Pattern(row[0]), []).append(row[1])

    output_dir = os.path.join(os.path.dirname(probing_csv), "analysis")
    os.makedirs(output_dir, exist_ok=True)
    plot_pattern_to_min_stable_lens(pattern_to_min_stable_lens, sequence_length, output_dir,
                                    "min_sequence_stable_lens.pdf")
