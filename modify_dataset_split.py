import argparse
from pathlib import Path

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit


def run():
    parser = argparse.ArgumentParser(description='Parse pcap files and generate a dataset')
    parser.add_argument('-f', '--file', type=str, required=True, help='Path of the input file')

    args = parser.parse_args()

    file = Path(args.file)

    columns_to_check = [f'byte_{i}' for i in range(1, 513)]

    # Load the dataset
    data = pd.read_csv(file)
    total_flows = data['flow_id'].nunique()

    print('Dataset loaded successfully!')
    print(f"Flows in the dataset: {total_flows}")

    # Remove flows with all zero values
    print("Removing flows with all zero values...")
    data = data.groupby('flow_id').filter(lambda x: not (x[columns_to_check] == 0).all().all())
    print(f"Removed {total_flows - data['flow_id'].nunique()} flows with all zero values.")

    # Split the dataset into training and testing sets
    base_train_inds, test_inds = next(
        GroupShuffleSplit(test_size=.20, n_splits=2, random_state=42).split(data, groups=data['flow_id']))

    base_train = data.iloc[base_train_inds]
    test = data.iloc[test_inds]

    # Split the training set into training and validation sets
    train_inds, val_inds = next(
        GroupShuffleSplit(test_size=.20, n_splits=2, random_state=42).split(base_train, groups=base_train['flow_id']))

    train = base_train.iloc[train_inds]
    val = base_train.iloc[val_inds]

    # Save the datasets
    train.to_csv(Path.cwd() / 'split_dataset' / f"{file.stem}_train.csv", index=False)
    val.to_csv(Path.cwd() / 'split_dataset' / f"{file.stem}_val.csv", index=False)
    test.to_csv(Path.cwd() / 'split_dataset' / f"{file.stem}_test.csv", index=False)

    print('\nDatasets split successfully!')

    # Calculate the ratio of the datasets
    print(f"Training set: {len(train) / len(data) * 100:.2f}%, {train['flow_id'].nunique()} flows")
    print(f"Validation set: {len(val) / len(data) * 100:.2f}%, {val['flow_id'].nunique()} flows")
    print(f"Testing set: {len(test) / len(data) * 100:.2f}%, {test['flow_id'].nunique()} flows")


if __name__ == '__main__':
    run()
