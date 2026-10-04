# Email Security Scanner

A Python-based email security scanner that monitors a Gmail inbox for newly received emails, extracts links, checks them against Google Safe Browsing and URLhaus, and automatically applies a **"Suspicious Link"** label to emails containing detected malicious links.

## Features

* Monitors Gmail for new emails
* Extracts URLs from incoming messages
* Checks URLs against:

  * Google Safe Browsing
  * URLhaus
* Flags an email if either service identifies a malicious link
* Automatically creates/applies the `Suspicious Link` Gmail label
* Runs continuously and checks for new emails every 10 seconds
* Keeps local logs of scan results

## Requirements

* Windows, Linux, or macOS
* Python 3.10+
* A Gmail account
* A Google Cloud project with the Gmail API enabled
* Gmail OAuth credentials
* Google Safe Browsing API key
* URLhaus API key

## 1. Install Python Dependencies

From the project directory, run:

pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib requests


## 2. Set Up Gmail API

Create a project in the [Google Cloud Console](https://console.cloud.google.com/).

Enable the **Gmail API** for the project.

Create an **OAuth Client ID**:

1. Go to **APIs & Services → Credentials**
2. Create an OAuth Client ID
3. Select **Desktop app**
4. Download the credentials file
5. Rename it to:


credentials.json


Place it in the project folder.

**Do not upload `credentials.json` to GitHub.**

When the scanner is run for the first time, Google will open a browser window and ask you to authorize Gmail access. After authorization, a `token.json` file will be created automatically.

`token.json` is also sensitive and must not be uploaded.

## 3. Google Safe Browsing API Key

Create a Google Safe Browsing API key through Google Cloud.

Save only the API key in:


google_safe_browsing_key.txt


Place the file in the project directory.

Do not upload this file to GitHub.

## 4. URLhaus API Key

Create an API key through URLhaus/Abuse.ch.

Save the key in:


urlhaus_key.txt


Place the file in the project directory.

Do not upload this file to GitHub.

## 5. Run the Scanner

Once everything is configured, run:

python scanner.py

`scanner.py` automatically starts the rest of the scanning process.

You do **not** need to manually run `link_checker.py` or `flag_emails.py`.

The process is:


New Gmail email
       ↓
scanner.py
       ↓
Extract links
       ↓
link_checker.py
       ↓
Google Safe Browsing + URLhaus
       ↓
flag_emails.py
       ↓
"Suspicious Link" Gmail label


## Files You Need to Create

A new installation should contain these files after setup:

email-security-scanner/
├── scanner.py
├── link_checker.py
├── flag_emails.py
├── .gitignore
├── credentials.json              # Create/download yourself
├── google_safe_browsing_key.txt  # Create yourself
└── urlhaus_key.txt               # Create yourself

The following files are generated automatically and should remain private:

token.json
scanner_state.json
emails.txt
links.txt
link_sources.json
link_results.txt

## Security

Never commit or upload the following files to GitHub:

credentials.json
token.json
google_safe_browsing_key.txt
urlhaus_key.txt
emails.txt
links.txt
link_sources.json
link_results.txt
scanner_state.json
