from pandas import DataFrame


def run(data: DataFrame, columns_to_check: list[str]) -> DataFrame:
    total_flows = data['flow_id'].nunique()

    print("Removing flows with all zero values...")
    data = data.groupby('flow_id').filter(lambda x: not (x[columns_to_check] == 0).all().all())
    print(f"Removed {total_flows - data['flow_id'].nunique()} flows with all zero values.")

    return data
