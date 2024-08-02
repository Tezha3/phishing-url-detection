from flask import Flask, render_template, request
import pickle
import numpy as np
import whois
import tldextract
import requests
from bs4 import BeautifulSoup
import pandas as pd
from urllib.parse import urlparse
import re
import datetime
from xgboost import XGBClassifier
import json

app = Flask(__name__)

# Load the pre-trained model
model = XGBClassifier()
model.load_model('xgb_model_top_features.json')

# Feature extraction functions
def extract_nb_www(url):
    return url.lower().count('www')

def extract_nb_hyperlinks(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        return len(soup.find_all('a'))
    except requests.exceptions.RequestException:
        return 0

def extract_phish_hints(url):
    phish_hints = ['login', 'signin', 'bank', 'account']
    return sum(hint in url.lower() for hint in phish_hints)

def extract_ip(url):
    try:
        ip = urlparse(url).hostname
        return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) is not None
    except:
        return False

def extract_length_words_raw(url):
    return len(url.split('/'))

def extract_longest_word_path(url):
    path = urlparse(url).path
    words = path.split('/')
    if words:
        return len(max(words, key=len))
    return 0

def extract_ratio_digits_host(url):
    host = urlparse(url).hostname
    if host:
        return sum(char.isdigit() for char in host) / len(host)
    return 0

def extract_domain_in_title(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        html_content = response.text
        
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.title.string if soup.title else ''
        
        domain_info = tldextract.extract(url)
        domain_name = domain_info.domain
        
        return int(domain_name.lower() in title.lower())
    except requests.exceptions.RequestException:
        return 0
    except Exception:
        return 0

def extract_nb_dots(url):
    return url.count('.')

def extract_nb_hyphens(url):
    return url.count('-')

def extract_nb_qm(url):
    return url.count('?')

def extract_domain_age(url):
    try:
        domain_name = tldextract.extract(url).registered_domain
        domain_info = whois.whois(domain_name)
    except Exception:
        return 1

    creation_date = domain_info.creation_date
    expiration_date = domain_info.expiration_date

    if isinstance(creation_date, str):
        try:
            creation_date = datetime.datetime.strptime(creation_date, '%Y-%m-%d')
        except ValueError:
            return 1

    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.datetime.strptime(expiration_date, '%Y-%m-%d')
        except ValueError:
            return 1

    if creation_date is None or expiration_date is None:
        return 1
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    try:
        age_of_domain = abs((expiration_date - creation_date).days)
    except Exception:
        return -1
    return age_of_domain

def extract_nb_underscore(url):
    return url.count('_')

def extract_nb_slash(url):
    return url.count('/')

def extract_nb_eq(url):
    return url.count('=')

def extract_ratio_extHyperlinks(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')
        links = soup.find_all('a')
        external_links = [link for link in links if 'http' in link.get('href', '')]
        return len(external_links) / len(links) if links else 0
    except requests.exceptions.RequestException:
        return 0

def extract_ratio_digits_url(url):
    return sum(char.isdigit() for char in url) / len(url)

def extract_nb_space(url):
    return url.count(' ')

def extract_longest_words_raw(url):
    words = url.split('/')
    if words:
        return len(max(words, key=len))
    return 0

def extract_length_hostname(url):
    host = urlparse(url).hostname
    if host:
        return len(host)
    return 0

# Function to extract all features
def extract_features(url):
    features = {
        'nb_www': extract_nb_www(url),
        'nb_hyperlinks': extract_nb_hyperlinks(url),
        'phish_hints': extract_phish_hints(url),
        'ip': extract_ip(url),
        'length_words_raw': extract_length_words_raw(url),
        'longest_word_path': extract_longest_word_path(url),
        'ratio_digits_host': extract_ratio_digits_host(url),
        'domain_in_title': extract_domain_in_title(url),
        'nb_dots': extract_nb_dots(url),
        'nb_hyphens': extract_nb_hyphens(url),
        'nb_qm': extract_nb_qm(url),
        'domain_age': extract_domain_age(url),
        'nb_underscore': extract_nb_underscore(url),
        'nb_slash': extract_nb_slash(url),
        'nb_eq': extract_nb_eq(url),
        'ratio_extHyperlinks': extract_ratio_extHyperlinks(url),
        'ratio_digits_url': extract_ratio_digits_url(url),
        'nb_space': extract_nb_space(url),
        'longest_words_raw': extract_longest_words_raw(url),
        'length_hostname': extract_length_hostname(url),
    }
    return pd.DataFrame([features])

@app.route('/')
def home():
    return render_template('home.html')
@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['input_url'].strip()

    if not url:
        return render_template('home.html', error_message="Please enter a URL.")
    
    extracted_features = extract_features(url)
    prediction = model.predict(extracted_features)
    result = "Phishing" if prediction == 1 else "Legitimate"
    probability = model.predict_proba(extracted_features)[0][prediction[0]]

    percentage = probability * 100

    features = {
        'nb_www': extract_nb_www(url),
        'nb_hyperlinks': extract_nb_hyperlinks(url),
        'phish_hints': extract_phish_hints(url),
        'ip': extract_ip(url),
        'length_words_raw': extract_length_words_raw(url),
        'longest_word_path': extract_longest_word_path(url),
        'ratio_digits_host': extract_ratio_digits_host(url),
        'domain_in_title': extract_domain_in_title(url),
        'nb_dots': extract_nb_dots(url),
        'nb_hyphens': extract_nb_hyphens(url),
        'nb_qm': extract_nb_qm(url),
        'domain_age': extract_domain_age(url),
        'nb_underscore': extract_nb_underscore(url),
        'nb_slash': extract_nb_slash(url),
        'nb_eq': extract_nb_eq(url),
        'ratio_extHyperlinks': extract_ratio_extHyperlinks(url),
        'ratio_digits_url': extract_ratio_digits_url(url),
        'nb_space': extract_nb_space(url),
        'longest_words_raw': extract_longest_words_raw(url),
        'length_hostname': extract_length_hostname(url),
    }

    print(features)
    cleaned_features = {k: (1 if v is True else 0 if v is False else 0 if v is None else v) for k, v in features.items()}

    numerical_values = list(cleaned_features.values())

    numerical_values_json = json.dumps(numerical_values)
    print(numerical_values_json)

    return render_template('result.html', result=result, percentage=percentage, extracted_features=features, values=numerical_values_json)

@app.route('/guidelines')
def guidelines():
    return render_template('features.html') 

@app.route('/phishing_examples')
def phishing_examples():
    return render_template('phishing_examples.html')

@app.route('/whatisphishing')
def whatisphishing():
    return render_template('whatisphishing.html') 


if __name__ == '__main__':
    app.run(debug=True)
