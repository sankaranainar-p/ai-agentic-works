import pandas as pd

df = pd.read_excel('Sample-Student-Data.xlsx')
print(df.head())
print("Columns:", df.columns.tolist())
