import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# ==========================
# LOAD DATASET
# ==========================

df = pd.read_csv(
    "../datasets/phishing_website_/PhiUSIIL_Phishing_URL_Dataset.csv"
)

print("Dataset Shape:", df.shape)

# ==========================
# REMOVE NON-NUMERIC COLUMNS
# ==========================

drop_columns = [
    "FILENAME",
    "URL",
    "Domain",
    "TLD",
    "Title"
]

df = df.drop(columns=drop_columns)

# ==========================
# FEATURES & LABEL
# ==========================

X = df.drop("label", axis=1)
y = df["label"]

print("\nFeature Count:", X.shape[1])

print("\nLabel Distribution:")
print(y.value_counts())

# ==========================
# TRAIN TEST SPLIT
# ==========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# ==========================
# RANDOM FOREST MODEL
# ==========================

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1
)

print("\nTraining Model...")

model.fit(X_train, y_train)

# ==========================
# PREDICTIONS
# ==========================

predictions = model.predict(X_test)

# ==========================
# EVALUATION
# ==========================

accuracy = accuracy_score(y_test, predictions)

print("\nAccuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# ==========================
# FEATURE IMPORTANCE
# ==========================

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 15 Important Features:\n")
print(feature_importance.head(15))

# Save feature importance
feature_importance.to_csv(
    "../models/website_feature_importance.csv",
    index=False
)

# ==========================
# SAVE MODEL
# ==========================

joblib.dump(
    model,
    "../models/website_phishing_model.pkl"
)

print("\nWebsite Model Saved Successfully!")

print("\nSaved Files:")
print(joblib.load if False else "website_phishing_model.pkl")