from sklearn.model_selection import GroupShuffleSplit
from pandas import DataFrame


def split_dataset(dataset: DataFrame, train_ratio: float = 0.8) -> tuple[DataFrame, DataFrame]:
    """
    Split a dataset into a training and test dataset.
    :param dataset: The dataset to split.
    :param split_ratio: The ratio of the split.
    :return: A tuple containing the training and test datasets.
    """
    train_inds, test_inds = next(
        GroupShuffleSplit(train_size=train_ratio, n_splits=2, random_state=42).split(dataset, groups=dataset['flow_id']))

    return dataset.iloc[train_inds], dataset.iloc[test_inds]