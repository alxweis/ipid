import os

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
TARGETS_DIR = "targets"
RESULTS_DIR = "results"
EXPERIMENTAL_RESULTS = os.path.join(RESULTS_DIR, "experimental")
EXP_SEQUENCE_STABLE_LEN_ANALYSIS = os.path.join(EXPERIMENTAL_RESULTS, "min_sequence_stable_len_analysis")
