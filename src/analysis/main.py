import pandas as pd


def compare_targets_csvs(file1, file2):
    print(f"Comparing {file1} and {file2}:")
    # Read CSV files
    df1 = pd.read_csv(f"../../{file1}")
    df2 = pd.read_csv(f"../../{file2}")

    # Extract IP columns
    ip_set1 = set(df1['IP'])
    ip_set2 = set(df2['IP'])

    # Find intersection of IPs
    common_ips = ip_set1.intersection(ip_set2)

    # Calculate percentage of common IPs
    percentage_common = (len(common_ips) / len(ip_set1)) * 100

    # Jaccard similarity
    jaccard_similarity = len(common_ips) / len(ip_set1.union(ip_set2))

    # Unique IPs in each file
    unique_ips_file1 = ip_set1 - ip_set2
    unique_ips_file2 = ip_set2 - ip_set1

    # Overlap rate
    overlap_rate = (len(common_ips) / (len(ip_set1) + len(ip_set2) - len(common_ips))) * 100

    # Unique IPs in total (symmetric difference)
    unique_ips_total = ip_set1.symmetric_difference(ip_set2)

    # Print results
    print(f'Number of common IPs: {len(common_ips)}')
    print(f'Percentage of common IPs (File 1): {percentage_common:.2f}%')
    print(f'Jaccard Similarity: {jaccard_similarity:.2f}')
    print(f'Unique IPs in File 1: {len(unique_ips_file1)}')
    print(f'Unique IPs in File 2: {len(unique_ips_file2)}')
    print(f'Overlap Rate: {overlap_rate:.2f}%')
    print(f'Unique IPs in total: {len(unique_ips_total)}')
    print()


compare_targets_csvs("targets/icmp/2025-04-19_21-37-29/targets.csv", "targets/icmp/2025-04-22_12-15-58/targets.csv")
