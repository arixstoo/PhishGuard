import pandas as pd  # data processing, CSV file I/O (e.g. pd.read_csv)
import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Download NLTK data files (only needed once)
nltk.download("punkt")
nltk.download("stopwords")
nltk.download("wordnet")


# LOADING DATA
print("\n\n\nLOADING DATA")

# Define the column names
column_names = ["label", "SMS"]

# Load the dataset and assign the column names
data = pd.read_csv(
    "SpamCollectionSMS.txt", delimiter="\t", header=None, names=column_names, encoding="utf-8"
)
data.info()


# NLP FIRST STEPS OF CLEANING AND LEMMA....
print("\n\n\nNLP FIRST STEPS")


# Step 1: Clean the text data
def clean_text(textt):
    textt = textt.lower()  # Convert to lowercase
    textt = re.sub(r"\d+", "", textt)  # Remove digits
    textt = re.sub(r"[^\w\s]", "", textt)  # Remove punctuation
    textt = textt.strip()  # Remove leading/trailing whitespace
    return textt


data["cleaned_message"] = data["SMS"].apply(clean_text)

# Step 2: Tokenize the messages
data["tokenized_message"] = data["cleaned_message"].apply(word_tokenize)

# Step 3: Remove stop words
stop_words = set(stopwords.words("english"))
data["tokenized_message"] = data["tokenized_message"].apply(
    lambda x: [word for word in x if word not in stop_words]
)

# Step 4: Apply stemming or lemmatization (Choose one)

# Stemming
stemmer = PorterStemmer()
data["stemmed_message"] = data["tokenized_message"].apply(
    lambda x: [stemmer.stem(word) for word in x]
)

# OR

# Lemmatization
# lemmatizer = WordNetLemmatizer()
# data['lemmatized_message'] = data['tokenized_message'].apply(lambda x: [lemmatizer.lemmatize(word) for word in x])

# Join the tokenized messages back into strings for TF-IDF vectorizer
data["processed_message"] = data["tokenized_message"].apply(lambda x: " ".join(x))

# Display the DataFrame to check the preprocessing steps
print(data[["cleaned_message", "tokenized_message", "stemmed_message"]].head(10))


# USING THE BEST WAY TO FINISH THE NLP PROCESS
print("\n\n\nNLP FINAL STEP")

# Apply TF-IDF Vectorization
tfidf_vectorizer = TfidfVectorizer(max_features=3000)
X = tfidf_vectorizer.fit_transform(data["processed_message"])

# Convert labels to binary format
y = data["label"].map({"ham": 0, "spam": 1})

# Display the shapes of X and y
print(X.shape, y.shape)


# THE MODEL
print("\n\n\nCREATING THE MODEL AND TESTING IT")

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a Logistic Regression model
model = LogisticRegression()
model.fit(X_train, y_train)

# Make predictions
y_pred = model.predict(X_test)

# Evaluate the model
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(f"Classification Report:\n{classification_report(y_test, y_pred)}")


# TESTING THE PERFORMENCE OF THE MODEL
print("\n\n\nTESTING THE PERFORMENCE OF THE MODEL ON MESSAGES OUT OF THE DATA")

# Perform Cross-Validation
cv_scores = cross_val_score(model, X, y, cv=50, scoring="accuracy")

# Print Cross-Validation Results
# print(f'Cross-Validation Accuracy Scores: {cv_scores}')
print(f"Mean Cross-Validation Accuracy: {cv_scores.mean()}")
print(f"Standard Deviation of Cross-Validation Accuracy: {cv_scores.std()}")


# SAVING THE MODEL SO I CAN JUST LOAD IT AND USE IT ANOTHER TIME
print("\n\n\nSAVING THE MODEL")

# Save the trained model
joblib.dump(model, "spam_classifier_model.joblib")

# Save the TF-IDF vectorizer
joblib.dump(tfidf_vectorizer, "tfidf_vectorizer.joblib")

print("Model and vectorizer saved successfully.")
