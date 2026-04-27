import os

DIR_PATH = os.path.dirname(os.path.abspath(__file__))
TARGETS_DIR = "targets"
RESULTS_DIR = "results"
EXPERIMENTAL_RESULTS = os.path.join(RESULTS_DIR, "experimental")
TEST_RESULTS = os.path.join(RESULTS_DIR, "test_default")
EXP_SEQUENCE_STABLE_CLASSIFICATION_LEN = os.path.join(EXPERIMENTAL_RESULTS, "sequence_stable_classification_len")
EXP_INTERSECTIONS = os.path.join(EXPERIMENTAL_RESULTS, "intersections")
