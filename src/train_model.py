import pandas as pd
import re
import joblib
import os

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# =========================
# DEBUGGING
# =========================
print("Current Directory:")
print(os.getcwd())

print("\nDatasets Folder:")
print(os.listdir("../datasets"))

# =========================
# LOAD DATASET
# =========================

# OPTION 1 (Recommended)
df = pd.read_csv(
    r"C:\Users\ZAINAB IMDAD\Desktop\AI-CyberShield\datasets\phishing_email_\Phishing_Email.csv"
)

# =========================
# CLEAN DATA
# =========================

if "Unnamed: 0" in df.columns:
    df = df.drop("Unnamed: 0", axis=1)

df = df.dropna()

# =========================
# TEXT CLEANING
# =========================

def clean_text(text):
    text = str(text).lower()

    text = re.sub(r"http\S+", "", text)
    text = re.sub(r"[^a-zA-Z\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()

    return text

df["Email Text"] = df["Email Text"].apply(clean_text)

# =========================
# LABEL ENCODING
# =========================

df["Email Type"] = df["Email Type"].map({
    "Safe Email": 0,
    "Phishing Email": 1
})

# =========================
# FEATURES & LABELS
# =========================

X = df["Email Text"]
y = df["Email Type"]

# =========================
# NLP - TF-IDF
# =========================

vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000
)

X = vectorizer.fit_transform(X)

# =========================
# TRAIN TEST SPLIT
# =========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# =========================
# TRAIN MODEL
# =========================

model = LogisticRegression(max_iter=1000)

model.fit(X_train, y_train)

# =========================
# PREDICTIONS
# =========================

predictions = model.predict(X_test)

# =========================
# EVALUATION
# =========================

accuracy = accuracy_score(y_test, predictions)

print("\nModel Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))

# =========================
# SAVE MODEL
# =========================

joblib.dump(model, "../models/phishing_model.pkl")
joblib.dump(vectorizer, "../models/tfidf_vectorizer.pkl")

print("\nModel saved successfully!")

print("\nSaved Files:")
print(os.listdir("../models"))