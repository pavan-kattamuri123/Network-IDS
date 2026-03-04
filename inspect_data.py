import pandas as pd
import os

dataset_path = os.path.join("docs", "dataset_full.csv")
try:
    df = pd.read_csv(dataset_path, nrows=5)
    print("Columns:", df.columns.tolist())
    print("Number of columns:", len(df.columns))
except Exception as e:
    print(f"Error reading dataset: {e}")
