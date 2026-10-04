
import os
import re
import json
import time
import base64
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

import link_checker


# ============================================================
# SETTINGS
# ============================================================

# How often to check Gmail
CHECK_INTERVAL = 10

# Only emails received within this many seconds
# will actually be scanned.
EMAIL_LOOKBACK_SECONDS = 30

# Gmail searches this larger window because Gmail's
# search index can take a little time to update.
GMAIL_SEARCH_SECONDS = 120

# Maximum messages returned by Gmail
MESSAGES_TO_CHECK = 20

# Number of quota retries
MAX_QUOTA_RETRIES = 3

# Starting delay between quota retries
QUOTA_RETRY_DELAY = 5

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify"
]

CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE = "token.json"

EMAILS_FILE = "emails.txt"
LINKS_FILE = "links.txt"
LINK_SOURCES_FILE = "link_sources.json"

STATE_FILE = "scanner_state.json"


# ============================================================
# GMAIL LOGIN
# ============================================================

def get_gmail_service():

    creds = None

    if os.path.exists(TOKEN_FILE):

        creds = Credentials.from_authorized_user_file(
            TOKEN_FILE,
            SCOPES
        )

    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:

            creds.refresh(
                Request()
            )

        else:

            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE,
                SCOPES
            )

            creds = flow.run_local_server(
                port=0
            )

        with open(
            TOKEN_FILE,
            "w"
        ) as token:

            token.write(
                creds.to_json()
            )

    return build(
        "gmail",
        "v1",
        credentials=creds
    )


# ============================================================
# BASE64 DECODING
# ============================================================

def decode_data(data):

    if not data:
        return ""

    try:

        return base64.urlsafe_b64decode(
            data.encode("UTF-8")
        ).decode(
            "UTF-8",
            errors="ignore"
        )

    except Exception:

        return ""


# ============================================================
# EXTRACT EMAIL TEXT
# ============================================================

def extract_email_text(payload):

    plain_text = ""
    html_text = ""

    mime_type = payload.get(
        "mimeType",
        ""
    )

    body = payload.get(
        "body",
        {}
    )

    if body.get("data"):

        decoded = decode_data(
            body.get("data")
        )

        if mime_type == "text/plain":

            plain_text += decoded

        elif mime_type == "text/html":

            html_text += decoded

    for part in payload.get(
        "parts",
        []
    ):

        p_text, h_text = extract_email_text(
            part
        )

        plain_text += "\n" + p_text
        html_text += "\n" + h_text

    return plain_text, html_text


# ============================================================
# EXTRACT LINKS
# ============================================================

def extract_links(
    plain_text,
    html_text
):

    links = set()

    # HTML href links
    html_links = re.findall(
        r'href=["\'](https?://[^"\']+)["\']',
        html_text,
        flags=re.IGNORECASE
    )

    for link in html_links:

        links.add(
            link
        )

    # Plain text links
    text_links = re.findall(
        r'https?://[^\s<>"\']+',
        plain_text,
        flags=re.IGNORECASE
    )

    for link in text_links:

        link = link.rstrip(
            '.,!?;:)]}'
        )

        links.add(
            link
        )

    return sorted(
        links
    )


# ============================================================
# GET EMAIL DATE
# ============================================================

def get_email_datetime(headers):

    for header in headers:

        if header["name"].lower() == "date":

            try:

                dt = parsedate_to_datetime(
                    header["value"]
                )

                if dt.tzinfo is None:

                    dt = dt.replace(
                        tzinfo=timezone.utc
                    )

                return dt.astimezone(
                    timezone.utc
                )

            except Exception:

                return None

    return None


# ============================================================
# GET HEADER
# ============================================================

def get_header(
    headers,
    name
):

    for header in headers:

        if header["name"].lower() == name.lower():

            return header["value"]

    return ""


# ============================================================
# LOAD PROCESSED IDS
# ============================================================

def load_processed_ids():

    if not os.path.exists(
        STATE_FILE
    ):

        return set()

    try:

        with open(
            STATE_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(
                f
            )

            return set(
                data.get(
                    "processed_message_ids",
                    []
                )
            )

    except Exception:

        return set()


# ============================================================
# SAVE PROCESSED IDS
# ============================================================

def save_processed_ids(
    processed_ids
):

    # Prevent scanner_state.json from growing forever.
    ids = list(
        processed_ids
    )[-1000:]

    with open(
        STATE_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            {
                "processed_message_ids": ids
            },
            f,
            indent=4
        )


# ============================================================
# GMAIL REQUEST WITH QUOTA RETRY
# ============================================================

def execute_with_retry(
    request
):

    retry_delay = QUOTA_RETRY_DELAY

    for attempt in range(
        MAX_QUOTA_RETRIES + 1
    ):

        try:

            return request.execute()

        except HttpError as e:

            status = e.resp.status
            error_text = str(e)

            quota_error = (
                status == 429
                or "rateLimitExceeded" in error_text
                or "quotaExceeded" in error_text
                or "Quota exceeded" in error_text
            )

            if not quota_error:

                raise

            if attempt >= MAX_QUOTA_RETRIES:

                print(
                    "\nGmail quota is still exceeded "
                    "after several retries."
                )

                raise

            print(
                f"\nGmail quota reached. "
                f"Waiting {retry_delay} seconds "
                f"before retry "
                f"{attempt + 1}/"
                f"{MAX_QUOTA_RETRIES}..."
            )

            time.sleep(
                retry_delay
            )

            retry_delay *= 2

    return None


# ============================================================
# SAVE EMAIL
# ============================================================

def save_email(
    email_data
):

    with open(
        EMAILS_FILE,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n" + "=" * 70 + "\n"
        )

        f.write(
            f"Subject: "
            f"{email_data['subject']}\n"
        )

        f.write(
            f"From: "
            f"{email_data['sender']}\n"
        )

        f.write(
            f"Date: "
            f"{email_data['date']}\n"
        )

        f.write(
            f"Links found: "
            f"{len(email_data['links'])}\n"
        )

        for link in email_data["links"]:

            f.write(
                f"  {link}\n"
            )


# ============================================================
# UPDATE LINKS.TXT
# ============================================================

def update_links_file(
    new_emails
):

    existing_links = set()

    if os.path.exists(
        LINKS_FILE
    ):

        with open(
            LINKS_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                line = line.strip()

                if line:

                    existing_links.add(
                        line
                    )

    for email in new_emails:

        for link in email["links"]:

            existing_links.add(
                link
            )

    with open(
        LINKS_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        for link in sorted(
            existing_links
        ):

            f.write(
                link + "\n"
            )


# ============================================================
# UPDATE LINK SOURCES
# ============================================================

def update_link_sources(
    new_emails
):

    sources = {}

    if os.path.exists(
        LINK_SOURCES_FILE
    ):

        try:

            with open(
                LINK_SOURCES_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                sources = json.load(
                    f
                )

        except Exception:

            sources = {}

    for email in new_emails:

        source = {
            "message_id": email["message_id"],
            "subject": email["subject"],
            "sender": email["sender"]
        }

        for link in email["links"]:

            if link not in sources:

                sources[link] = []

            if source not in sources[link]:

                sources[link].append(
                    source
                )

    with open(
        LINK_SOURCES_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            sources,
            f,
            indent=4
        )


# ============================================================
# GET RECENT EMAILS
# ============================================================

def get_recent_emails(
    service,
    processed_ids
):

    now = datetime.now(
        timezone.utc
    )

    cutoff = now - timedelta(
        seconds=EMAIL_LOOKBACK_SECONDS
    )

    print(
        f"\nLooking for emails from the last "
        f"{EMAIL_LOOKBACK_SECONDS} seconds..."
    )

    # --------------------------------------------------------
    # Gmail search window
    #
    # We deliberately search 2 minutes instead of 30 seconds.
    # Gmail's search index may take some time to update.
    #
    # The local timestamp check below still guarantees that
    # only emails from the last 30 seconds are processed.
    # --------------------------------------------------------

    try:

        messages_result = execute_with_retry(
            service.users().messages().list(
                userId="me",
                maxResults=MESSAGES_TO_CHECK,
                q="in:anywhere newer_than:2m"
            )
        )

    except HttpError as e:

        print(
            f"\nUnable to query Gmail:\n{e}"
        )

        return []

    if not messages_result:

        return []

    messages = messages_result.get(
        "messages",
        []
    )

    if not messages:

        return []

    recent_emails = []

    # Gmail normally returns newest first.
    # Reverse to process oldest recent email first.

    for message in reversed(
        messages
    ):

        message_id = message["id"]

        # ----------------------------------------------------
        # Don't download an email we've already processed.
        # ----------------------------------------------------

        if message_id in processed_ids:

            continue

        try:

            full_message = execute_with_retry(
                service.users().messages().get(
                    userId="me",
                    id=message_id,
                    format="full"
                )
            )

            if not full_message:

                continue

            payload = full_message.get(
                "payload",
                {}
            )

            headers = payload.get(
                "headers",
                []
            )

            email_datetime = get_email_datetime(
                headers
            )

            if not email_datetime:

                continue

            # ------------------------------------------------
            # IMPORTANT:
            #
            # This is the actual 30-second filter.
            # ------------------------------------------------

            if email_datetime < cutoff:

                continue

            # Ignore messages with future timestamps
            if email_datetime > now:

                continue

            subject = get_header(
                headers,
                "Subject"
            )

            sender = get_header(
                headers,
                "From"
            )

            plain_text, html_text = extract_email_text(
                payload
            )

            links = extract_links(
                plain_text,
                html_text
            )

            email_data = {
                "message_id": message_id,
                "subject": subject,
                "sender": sender,
                "date": email_datetime.isoformat(),
                "links": links
            }

            recent_emails.append(
                email_data
            )

            # Mark it processed so it isn't checked again
            processed_ids.add(
                message_id
            )

        except HttpError as e:

            print(
                f"\nError processing message "
                f"{message_id}:"
            )

            print(
                e
            )

        except Exception as e:

            print(
                f"\nError processing message "
                f"{message_id}: {e}"
            )

    return recent_emails


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 70
    )

    print(
        "GMAIL EMAIL SECURITY SCANNER"
    )

    print(
        "=" * 70
    )

    print(
        f"Checking Gmail every "
        f"{CHECK_INTERVAL} seconds."
    )

    print(
        f"Only emails from the last "
        f"{EMAIL_LOOKBACK_SECONDS} seconds "
        f"will actually be scanned."
    )

    print(
        f"Gmail search window: "
        f"{GMAIL_SEARCH_SECONDS} seconds."
    )

    print(
        "\nStarting Gmail connection..."
    )

    service = get_gmail_service()

    print(
        "Gmail connection successful."
    )

    processed_ids = load_processed_ids()

    while True:

        try:

            print(
                "\n" + "=" * 70
            )

            print(
                f"SCAN STARTED: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

            new_emails = get_recent_emails(
                service,
                processed_ids
            )

            if not new_emails:

                print(
                    "No new emails from the last "
                    f"{EMAIL_LOOKBACK_SECONDS} seconds."
                )

            else:

                print(
                    f"\nFound {len(new_emails)} "
                    f"new email(s)."
                )

                total_links = 0

                for email in new_emails:

                    print(
                        f"\nSubject: "
                        f"{email['subject']}"
                    )

                    print(
                        f"From: "
                        f"{email['sender']}"
                    )

                    print(
                        f"Links found: "
                        f"{len(email['links'])}"
                    )

                    for link in email["links"]:

                        print(
                            f"  {link}"
                        )

                    total_links += len(
                        email["links"]
                    )

                    save_email(
                        email
                    )

                update_links_file(
                    new_emails
                )

                update_link_sources(
                    new_emails
                )

                if total_links > 0:

                    print(
                        "\nSending only the new "
                        "email links to "
                        "link checker..."
                    )

                    link_checker.check_emails(
                        new_emails,
                        service
                    )

                else:

                    print(
                        "\nNo links found in "
                        "the new emails."
                    )

            save_processed_ids(
                processed_ids
            )

            print(
                f"\nWaiting {CHECK_INTERVAL} seconds..."
            )

            time.sleep(
                CHECK_INTERVAL
            )

        except KeyboardInterrupt:

            print(
                "\n\nScanner stopped."
            )

            save_processed_ids(
                processed_ids
            )

            break

        except HttpError as e:

            print(
                f"\nGmail API error:"
            )

            print(
                e
            )

            print(
                "\nWaiting before trying again..."
            )

            time.sleep(
                CHECK_INTERVAL
            )

        except Exception as e:

            print(
                f"\nScanner error: {e}"
            )

            print(
                f"Retrying in "
                f"{CHECK_INTERVAL} seconds..."
            )

            time.sleep(
                CHECK_INTERVAL
            )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()

