import pandas as pd

def load_dataset(csv_path):
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"[INFO] Dataset loaded with {len(df)} rows")

    # Drop incomplete rows
   # df = df.dropna()

    return df
