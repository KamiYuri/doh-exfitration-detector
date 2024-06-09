import dask.dataframe as dd

def add_prefix(prefix: str, df: dd.DataFrame) -> dd.DataFrame:
    return df.assign(flow_id=prefix + df['flow_id'].astype(str)).persist()


    