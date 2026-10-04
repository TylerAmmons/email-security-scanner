
import os
import time
import requests

import flag_emails


# ============================================================
# SETTINGS
# ============================================================

GOOGLE_KEY_FILE = "google_safe_browsing_key.txt"
URLHAUS_KEY_FILE = "urlhaus_key.txt"

RESULTS_FILE = "link_results.txt"

DELAY_BETWEEN_REQUESTS = 2

GOOGLE_SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

URLHAUS_URL = (
    "https://urlhaus-api.abuse.ch/v1/url/"
)


# ============================================================
# LOAD FILE
# ============================================================

def load_file(filename):

    if not os.path.exists(filename):

        raise FileNotFoundError(
            f"Could not find {filename}"
        )

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as file:

        return file.read().strip()


# ============================================================
# GOOGLE SAFE BROWSING
# ============================================================

def check_google_safe_browsing(url, api_key):

    payload = {
        "client": {
            "clientId": "email-security-scanner",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": [
                "ANY_PLATFORM"
            ],
            "threatEntryTypes": [
                "URL"
            ],
            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:

        response = requests.post(
            GOOGLE_SAFE_BROWSING_URL,
            params={
                "key": api_key
            },
            json=payload,
            timeout=15
        )

        if response.status_code != 200:

            return {
                "status": "ERROR",
                "threat": False,
                "threat_types": [],
                "error": (
                    f"HTTP {response.status_code}: "
                    f"{response.text[:300]}"
                )
            }

        data = response.json()

        matches = data.get(
            "matches",
            []
        )

        if matches:

            threat_types = []

            for match in matches:

                threat_type = match.get(
                    "threatType"
                )

                if threat_type:
                    threat_types.append(
                        threat_type
                    )

            return {
                "status": "THREAT",
                "threat": True,
                "threat_types": sorted(
                    set(threat_types)
                ),
                "error": ""
            }

        return {
            "status": "CLEAN",
            "threat": False,
            "threat_types": [],
            "error": ""
        }

    except Exception as e:

        return {
            "status": "ERROR",
            "threat": False,
            "threat_types": [],
            "error": str(e)
        }


# ============================================================
# URLHAUS
# ============================================================

def check_urlhaus(url, api_key):

    try:

        response = requests.post(
            URLHAUS_URL,
            headers={
                "Auth-Key": api_key
            },
            data={
                "url": url
            },
            timeout=15
        )

        if response.status_code != 200:

            return {
                "status": "ERROR",
                "threat": False,
                "url_status": "",
                "threat_type": "",
                "error": (
                    f"HTTP {response.status_code}: "
                    f"{response.text[:300]}"
                )
            }

        data = response.json()

        query_status = data.get(
            "query_status",
            ""
        )

        # URL is known to URLhaus.

        if query_status == "ok":

            return {
                "status": "THREAT",
                "threat": True,
                "url_status": data.get(
                    "url_status",
                    ""
                ),
                "threat_type": data.get(
                    "threat",
                    ""
                ),
                "error": ""
            }

        # URL is not in URLhaus.

        if query_status in (
            "no_results",
            "no_results_found"
        ):

            return {
                "status": "CLEAN",
                "threat": False,
                "url_status": "",
                "threat_type": "",
                "error": ""
            }

        return {
            "status": "ERROR",
            "threat": False,
            "url_status": "",
            "threat_type": "",
            "error": (
                f"Unexpected URLhaus query_status: "
                f"{query_status}"
            )
        }

    except Exception as e:

        return {
            "status": "ERROR",
            "threat": False,
            "url_status": "",
            "threat_type": "",
            "error": str(e)
        }


# ============================================================
# CHECK ONE LINK
# ============================================================

def check_link(url, google_key, urlhaus_key):

    print()
    print(
        f"Checking: {url}"
    )

    google_result = check_google_safe_browsing(
        url,
        google_key
    )

    print(
        f"  Google Safe Browsing: "
        f"{google_result['status']}"
    )

    if google_result["threat_types"]:

        print(
            f"    Threat types: "
            f"{', '.join(google_result['threat_types'])}"
        )

    if google_result["error"]:

        print(
            f"    Error: "
            f"{google_result['error']}"
        )

    time.sleep(
        DELAY_BETWEEN_REQUESTS
    )

    urlhaus_result = check_urlhaus(
        url,
        urlhaus_key
    )

    print(
        f"  URLhaus: "
        f"{urlhaus_result['status']}"
    )

    if urlhaus_result["threat_type"]:

        print(
            f"    Threat type: "
            f"{urlhaus_result['threat_type']}"
        )

    if urlhaus_result["error"]:

        print(
            f"    Error: "
            f"{urlhaus_result['error']}"
        )

    # --------------------------------------------------------
    # FINAL DECISION
    # --------------------------------------------------------

    # Either service reporting a threat is enough.

    if (
        google_result["threat"]
        or
        urlhaus_result["threat"]
    ):

        final_status = "MALICIOUS"

        detected_by = []

        if google_result["threat"]:
            detected_by.append(
                "Google Safe Browsing"
            )

        if urlhaus_result["threat"]:
            detected_by.append(
                "URLhaus"
            )

        print()
        print(
            "  RESULT: MALICIOUS"
        )

        print(
            "  Detected by: "
            + ", ".join(detected_by)
        )

    # Both services failed.

    elif (
        google_result["status"] == "ERROR"
        and
        urlhaus_result["status"] == "ERROR"
    ):

        final_status = "ERROR"

        print()
        print(
            "  RESULT: ERROR"
        )

    # At least one service successfully checked
    # the URL and neither reported a threat.

    else:

        final_status = "NOT FLAGGED"

        print()
        print(
            "  RESULT: NOT FLAGGED"
        )

    return {
        "url": url,
        "result": final_status,
        "google": google_result,
        "urlhaus": urlhaus_result
    }


# ============================================================
# APPEND TO LOG
# ============================================================

def append_result_to_log(result, sources):

    with open(
        RESULTS_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            "-" * 70 + "\n"
        )

        file.write(
            f"URL: {result['url']}\n"
        )

        file.write(
            f"Result: {result['result']}\n"
        )

        # ----------------------------------------------------
        # GOOGLE
        # ----------------------------------------------------

        google = result["google"]

        file.write(
            "Google Safe Browsing:\n"
        )

        file.write(
            f"  Status: {google['status']}\n"
        )

        if google["threat_types"]:

            file.write(
                "  Threat Types: "
                + ", ".join(
                    google["threat_types"]
                )
                + "\n"
            )

        if google["error"]:

            file.write(
                f"  Error: {google['error']}\n"
            )

        # ----------------------------------------------------
        # URLHAUS
        # ----------------------------------------------------

        urlhaus = result["urlhaus"]

        file.write(
            "URLhaus:\n"
        )

        file.write(
            f"  Status: {urlhaus['status']}\n"
        )

        if urlhaus["url_status"]:

            file.write(
                f"  URL Status: "
                f"{urlhaus['url_status']}\n"
            )

        if urlhaus["threat_type"]:

            file.write(
                f"  Threat Type: "
                f"{urlhaus['threat_type']}\n"
            )

        if urlhaus["error"]:

            file.write(
                f"  Error: {urlhaus['error']}\n"
            )

        # ----------------------------------------------------
        # SOURCE EMAILS
        # ----------------------------------------------------

        file.write(
            "Source Emails:\n"
        )

        if sources:

            for source in sources:

                file.write(
                    f"  Message ID: "
                    f"{source['message_id']}\n"
                )

                file.write(
                    f"  Subject: "
                    f"{source['subject']}\n"
                )

                file.write(
                    f"  Sender: "
                    f"{source['sender']}\n"
                )

        else:

            file.write(
                "  No source email information found.\n"
            )

        file.write(
            "\n"
        )


# ============================================================
# CHECK EMAILS
# ============================================================

def check_emails(emails, gmail_service):

    if not emails:

        return []

    # --------------------------------------------------------
    # LOAD API KEYS
    # --------------------------------------------------------

    google_key = load_file(
        GOOGLE_KEY_FILE
    )

    urlhaus_key = load_file(
        URLHAUS_KEY_FILE
    )

    # --------------------------------------------------------
    # BUILD UNIQUE URL → EMAIL SOURCES
    # --------------------------------------------------------

    link_sources = {}

    for email in emails:

        for link in email["links"]:

            if link not in link_sources:

                link_sources[link] = []

            source = {
                "message_id": email["message_id"],
                "subject": email["subject"],
                "sender": email["sender"]
            }

            # Prevent duplicate entries.

            already_exists = any(
                item["message_id"] == email["message_id"]
                for item in link_sources[link]
            )

            if not already_exists:

                link_sources[link].append(
                    source
                )

    if not link_sources:

        print()
        print(
            "No links found in the new emails."
        )

        return []

    print()
    print(
        "=" * 70
    )

    print(
        f"CHECKING {len(link_sources)} UNIQUE LINK(S)"
    )

    print(
        "=" * 70
    )

    results = []

    # --------------------------------------------------------
    # CHECK EACH UNIQUE URL
    # --------------------------------------------------------

    for url, sources in link_sources.items():

        result = check_link(
            url,
            google_key,
            urlhaus_key
        )

        result["sources"] = sources

        results.append(
            result
        )

        # Keep a permanent log.

        append_result_to_log(
            result,
            sources
        )

        time.sleep(
            DELAY_BETWEEN_REQUESTS
        )

    # --------------------------------------------------------
    # DIRECTLY SEND RESULTS TO FLAGGER
    # --------------------------------------------------------

    print()
    print(
        "Sending fresh results directly to flag_emails.py..."
    )

    try:

        flag_emails.flag_messages(
            results,
            gmail_service
        )

    except Exception as e:

        print()
        print(
            f"ERROR IN FLAGGING SYSTEM: {e}"
        )

    return results


# ============================================================
# STANDALONE MODE
# ============================================================

if __name__ == "__main__":

    print(
        "link_checker.py is designed to be started "
        "by scanner.py."
    )

    print(
        "Run: python scanner.py"
    )

