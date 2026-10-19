[![CI](https://github.com/arixstoo/PhishGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/arixstoo/PhishGuard/actions/workflows/ci.yml)


# **SMS Spam Detector (96%)**

#### Hi there 👋 it's arixstoo again !
## Project Description
This project is a machine learning-based SMS spam detection system, developed using Python. The system classifies SMS messages as either spam or not spam by leveraging natural language processing (NLP) techniques and a Logistic Regression model. The model is trained on a labeled dataset of SMS messages and uses TF-IDF for feature extraction.

The project was developed to demonstrate text processing, feature extraction, and model training, with the final model being saved for deployment in a production environment where it can classify new SMS messages in real-time.



## Technologies Used
**- Programming Language: Python**

**- Libraries**: **Pandas** for data processing / **NLTK** for natural language processing / **Scikit-learn** for machine learning and model evaluation / **Joblib** for model serialization

**- NLP Techniques: Tokenization** / **Stop Words** Removal / **Stemming** (or Lemmatization) / TF-IDF **Vectorization**

**- Model: Logistic Regression**



## Project Structure

### **Data Loading and Preprocessing:**
The dataset is loaded and cleaned, including the removal of punctuation, conversion to lowercase, tokenization, and stop words removal.

Optional stemming or lemmatization is applied to reduce words to their base forms.

### **Feature Extraction:**
TF-IDF vectorization is used to convert text data into numerical features for the model.

### **Model Training and Evaluation:**
The Logistic Regression model is trained on the preprocessed data.

Model performance is evaluated using accuracy scores, classification reports, and cross-validation.

### **Model Saving:**
The trained model and TF-IDF vectorizer are saved using joblib for future use.



## Key Features
**SMS Spam Classification:** The system can classify new SMS messages as spam or not spam using the trained Logistic Regression model.

**Model Performance Evaluation:** Includes accuracy scores, classification reports, and cross-validation to assess the model's generalization to unseen data.



## Instructions for Execution
### Clone the Repository:
Write on the bash: git clone https://github.com/arixstoo/SMS-Spam-Detector-96

### Install Dependencies:
Ensure you have Python installed and all the libraries used in the project.

### Run the Project:
Execute the Python script to train the model or use the pre-trained model for predictions.



## 🧰 Languages and Tools
        
<img align="left" alt="GitHub" width="30px" style="padding-right:10px;" src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/github/github-original.svg" />
<img align="left" alt="Git" width="30px" style="padding-right:10px;" src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/git/git-original.svg" />
<img align="left" alt="VsCode" width="30px" style="padding-right:10px;" src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/vscode/vscode-original.svg" />
<img align="left" alt="Python" width="30px" style="padding-right:10px;" src="https://cdn.jsdelivr.net/gh/devicons/devicon@latest/icons/python/python-original.svg" />
<br />


## 📊 Reach me here:

[LinkedIn]: <a href="https://www.linkedin.com/in/saidi-mohamed-rostom-21b3b525a/" target="_blank">arixstoo</a>
<br />
[E-mail]: saidi.rostom26@gmail.com
<br />
[Discord]: arixstoo
