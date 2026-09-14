import joblib
import re
import os

# Check current working directory
print("Current Directory:")
print(os.getcwd())

# Load saved model and vectorizer
model = joblib.load("../models/phishing_model.pkl")
vectorizer = joblib.load("../models/tfidf_vectorizer.pkl")

# Text cleaning function
def clean_text(text):
    text = str(text).lower()

    # Remove URLs
    text = re.sub(r"http\S+", "", text)

    # Remove special characters
    text = re.sub(r"[^a-zA-Z\s]", "", text)

    # Remove extra spaces
    text = re.sub(r"\s+", " ", text).strip()

    return text

# Get email from user
print("Paste your email below.")
print("When finished, type END on a new line.\n")

lines = []

while True:
    line = input()

    if line.strip().upper() == "END":
        break

    lines.append(line)

email = "\n".join(lines)
# Clean email
email = clean_text(email)

# Convert to TF-IDF features
email_vector = vectorizer.transform([email])

# Predict
prediction = model.predict(email_vector)

# Get confidence score
probability = model.predict_proba(email_vector)
confidence = round(max(probability[0]) * 100, 2)

print("\n========================")

if prediction[0] == 1:
    print("Prediction: PHISHING EMAIL")
else:
    print("Prediction: SAFE EMAIL")

print("Confidence:", confidence, "%")

print("========================")