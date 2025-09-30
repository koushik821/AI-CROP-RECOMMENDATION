import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset
data = pd.read_csv("../dataset/dataset.csv")  # Make sure this file exists

# Check that 'label' is in the CSV
if "label" not in data.columns:
    print("❌ Error: 'label' column not found in dataset.")
    print(f"Columns available: {data.columns.tolist()}")
    exit()

# Features and target
X = data.drop("label", axis=1)
y = data["label"]

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "crop_model.pkl")
print("✅ Model trained and saved as crop_model.pkl")
