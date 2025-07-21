import os
import subprocess
import tempfile


def deduplicate_csv(input_csv: str, total_rows: int, column_name: str) -> (int, float):
    sort_csv(input_csv=input_csv, column_names=[column_name])

    column_index = get_column_index(input_csv=input_csv, column_name=column_name) + 1
    temp_csv = tempfile.mktemp(prefix=f"{os.path.basename(input_csv)}.dedup.", dir=".")

    awk_cmd = f"awk -F, '!seen[${column_index}]++' {input_csv} > {temp_csv}"
    subprocess.run(awk_cmd, shell=True, check=True)

    os.replace(temp_csv, input_csv)

    unique_rows = count_rows(input_csv)
    removed_rows = total_rows - unique_rows
    removed_rows_percent = (removed_rows / total_rows * 100) if total_rows > 0 else 0
    return removed_rows, removed_rows_percent


def get_header_csv(input_csv: str) -> str:
    result = subprocess.check_output(['head', '-n', '1', input_csv], text=True)
    return result.strip()


def replace_header_csv(input_csv: str, new_header: str) -> bool:
    try:
        subprocess.run(
            ['sed', '-i', f'1s/.*/{new_header}/', input_csv],
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def count_rows(input_csv: str) -> int:
    result = subprocess.check_output(['wc', '-l', input_csv], text=True)
    return int(result.strip().split()[0])


def get_column_index(input_csv: str, column_name: str) -> int:
    header = subprocess.check_output(
        ['head', '-n', '1', input_csv], text=True
    ).strip()
    columns = header.split(',')
    column_index = columns.index(column_name)
    return column_index


def sort_csv(input_csv: str, column_names: list[str]) -> bool:
    try:
        column_indices = [get_column_index(input_csv=input_csv, column_name=col_name) for col_name in column_names]
        sort_keys = [f'-k{index + 1},{index + 1}n' for index in column_indices]
        temp_csv = tempfile.mktemp(prefix=f"{os.path.basename(input_csv)}.sort.", dir=".")

        with open(temp_csv, 'w') as f:
            subprocess.run(['sort', '-t,', *sort_keys, '-T', '.', input_csv], stdout=f, check=True)

        os.replace(temp_csv, input_csv)
        return True
    except (subprocess.CalledProcessError, ValueError, IndexError, FileNotFoundError):
        return False
