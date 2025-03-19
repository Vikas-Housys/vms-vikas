import pandas as pd

# Specify the Excel file path
file_path = "VMS-Project Report.xlsx"  # Change this to your actual file path

# Read the Excel file
df = pd.read_excel(file_path, engine='openpyxl')

# Print the data
print(df)

