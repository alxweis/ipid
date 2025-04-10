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
