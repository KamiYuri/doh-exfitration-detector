import pandas as pd

from pathlib import Path


def convert_label_to_int(data: pd.DataFrame, labels) -> pd.DataFrame:
    data['label'] = data['label'].apply(lambda x: labels.index(x))

    return data


def load_csv_files(directory: Path, **kwargs) -> list[Path]:
    return list(directory.rglob('*.csv'))


def load_csv(file_path: Path, **kwargs) -> pd.DataFrame:
    # Load the dataset
    data = pd.read_csv(file_path, **kwargs)
    total_flows = data['flow_id'].nunique()

    print('Dataset loaded successfully!')
    print(f"Flows in the dataset: {total_flows}")

    return data


def save_csv(data: pd.DataFrame, file_path: Path, **kwargs):
    data.to_csv(file_path, **kwargs)

    print(f"Dataset saved successfully to {file_path}")


def gen_dataset_headers(num_bytes: int) -> list[str]:
    headers = ["flow_id"]
    headers = headers + [f'byte_{i}' for i in range(num_bytes)]
    headers = headers + ["label"]

    return headers


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(description='Modify the dataset')
    parser.add_argument('-b', '--bunch', action='store_true', help='Modify a bunch of files')
    parser.add_argument('-f', '--file', type=str, help='The file or folder to modify')
    parser.add_argument('-o', '--output', type=str, help='The output file or folder')
    parser.add_argument('-n', '--nrows', type=int, help='Number of rows to load')
    parser.add_argument('--num-bytes', type=int, help='Number of bytes in the dataset')

    parser.add_argument('-r', '--remove', action='store_true', help='Remove zero flows')
    parser.add_argument('--modify-flow', type=str, help='Add prefix to flow_id')

    parser.add_argument('-s', '--split', action='store_true', help='Split the dataset')
    parser.add_argument('--train-ratio', type=float, help='Train ratio for the split')
    parser.add_argument('--val-ratio', type=float, help='Validation ratio for the split')

    return parser.parse_args()


if __name__ == '__main__':
    data = load_csv(Path.cwd() / 'datasets' / 'iodine.csv', nrows=1000)

    data = convert_label_to_int(data, labels=['benign', 'dns2tcp', 'dnscat2', 'iodine'])

    print(data.head(100))
