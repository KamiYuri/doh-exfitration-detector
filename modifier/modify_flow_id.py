import dask.dataframe as dd


def run(df: dd.DataFrame, prefix: str) -> dd.DataFrame:
    return df.assign(flow_id=prefix + df['flow_id'].astype(str)).persist()
