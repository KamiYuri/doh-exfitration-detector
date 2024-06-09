import pandas as pd

from pathlib import Path


def convert_label_to_int(data: pd.DataFrame, labels) -> pd.DataFrame:
    data['label'] = data['label'].apply(lambda x: labels.index(x))

    return data


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


if __name__ == '__main__':
    data = load_csv(Path.cwd() / 'datasets' / 'iodine.csv', nrows=1000)

    data = convert_label_to_int(data, labels=['benign', 'dns2tcp', 'dnscat2', 'iodine'])

    print(data.head(100))