# HACKTVIS PhishGuard 🛡️

### AI-Powered Phishing URL & Website Detection System

HACKTVIS PhishGuard is a Python-based cybersecurity project designed to analyze URLs and websites to identify potential phishing threats using Machine Learning and static website analysis.

The system analyzes URL characteristics, inspects website metadata, generates a risk assessment, and creates downloadable PDF security reports.

## 🚀 Features

- **URL Analysis:** Examines URL structure, domain characteristics, suspicious keywords, and obfuscation indicators.
- **Machine Learning Detection:** Uses a Random Forest classifier to estimate phishing and legitimate probabilities.
- **Website Analysis:** Performs static HTML inspection and extracts website information.
- **Risk Assessment:** Calculates an experimental risk score and risk level.
- **PDF Reports:** Generates downloadable security analysis reports.
- **Scan History:** Stores previous scans using SQLite.
- **Web Dashboard:** Provides a Flask-based interface for URL scanning and viewing scan history.

## 🧠 Technologies Used

- Python
- Flask
- Scikit-learn
- Pandas
- NumPy
- BeautifulSoup
- Requests
- SQLite
- Joblib
- ReportLab
- HTML & CSS

## 📂 Project Structure

text
HACKTVIS-PhishGuard/
│
├── web_app.py
├── app.py
├── requirements.txt
├── models/
│   └── phishing_model.pkl
│
├── src/
│   ├── train_model.py
│   ├── predict.py
│   ├── live_predict.py
│   ├── url_analyzer.py
│   ├── website_analyzer.py
│   ├── feature_builder.py
│   ├── database.py
│   ├── report.py
│   └── reputation.py
│
├── data/
├── reports/
└── tests/

## ⚙️ Installation

Clone the repository:


git clone https://github.com/chiragpurandare-ui/HACKTVIS-PhishGuard.git

Move into the project directory:

cd HACKTVIS-PhishGuard

Create a virtual environment:

python3 -m venv venv

Activate it:

source venv/bin/activate


Install dependencies:

pip install -r requirements.txt

## ▶️ Run the Application

Start the Flask web application:

python web_app.py

Open your browser:

http://127.0.0.1:5000

## 🔍 How It Works

1. Enter a website URL.
2. The system extracts URL-based features.
3. The website is inspected using static HTML analysis.
4. The trained ML model estimates the likelihood of phishing.
5. The system calculates an experimental risk score.
6. A PDF report is generated.
7. Scan information is saved in the SQLite database.

## ⚠️ Limitations

- Predictions are experimental and may produce false positives or false negatives.
- Model validation results do not guarantee real-world accuracy.
- External threat-intelligence and reputation databases are not currently integrated.
- The system is a research and educational project, not a replacement for professional security tools.
- Website analysis is static; JavaScript is not executed.

## 🔐 Responsible Use

This project is intended for cybersecurity education, defensive research, and authorized website security analysis.

Only analyze websites when you have permission to do so. Do not use this project for credential collection, unauthorized surveillance, or other harmful activities.

## 👨‍💻 Developer

**ECHO_GORUP**

Project: HACKTVIS PhishGuard

GitHub: https://github.com/chiragpurandare-ui

---

⭐ If you find this project interesting, consider starring the repository!
