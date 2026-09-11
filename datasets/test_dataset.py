import pandas as pd
import re
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# -----------------------------
# Load Dataset
# -----------------------------
df = pd.read_csv("phising_email_/Phishing_Email.csv")

# Remove unwanted column
df = df.drop("Unnamed: 0", axis=1)

# Check missing values
print("Missing Values:")
print(df.isnull().sum())

# Remove rows with missing values
df = df.dropna()

# -----------------------------
# Text Cleaning Function
# -----------------------------
def clean_text(text):
    text = str(text).lower()

    # Remove URLs
    text = re.sub(r"http\S+", "", text)

    # Remove special characters and numbers
    text = re.sub(r"[^a-zA-Z\s]", "", text)

    # Remove extra spaces
    text = re.sub(r"\s+", " ", text).strip()

    return text

# Apply cleaning
df["Email Text"] = df["Email Text"].apply(clean_text)

# -----------------------------
# Convert Labels
# -----------------------------
df["Email Type"] = df["Email Type"].map({
    "Safe Email": 0,
    "Phishing Email": 1
})

print("\nDataset Shape:", df.shape)

print("\nClass Distribution:")
print(df["Email Type"].value_counts())

# -----------------------------
# Features and Labels
# -----------------------------
X = df["Email Text"]
y = df["Email Type"]

# -----------------------------
# NLP - TF-IDF
# -----------------------------
vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000
)

X = vectorizer.fit_transform(X)

# -----------------------------
# Train-Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------
# Model Training
# -----------------------------
model = LogisticRegression(max_iter=1000)

model.fit(X_train, y_train)

# -----------------------------
# Predictions
# -----------------------------
predictions = model.predict(X_test)

# -----------------------------
# Evaluation
# -----------------------------
accuracy = accuracy_score(y_test, predictions)

print("\nModel Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# -----------------------------
# Save Model
# -----------------------------
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")

print("\nModel saved successfully!")

# -----------------------------
# Test Custom Email
# -----------------------------
sample_email = """
URGENT! Your bank account has been suspended.
Click here immediately to verify your credentials.
"""

# Clean sample email
sample_email = clean_text(sample_email)

# Convert to TF-IDF
sample_vector = vectorizer.transform([sample_email])

# Predict
prediction = model.predict(sample_vector)

# Probability
probability = model.predict_proba(sample_vector)

print("\nCustom Email Test:")

if prediction[0] == 1:
    print("Prediction: Phishing Email")
else:
    print("Prediction: Safe Email")

print("Confidence:", round(max(probability[0]) * 100, 2), "%")