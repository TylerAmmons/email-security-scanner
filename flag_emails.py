
from googleapiclient.errors import HttpError


# ============================================================
# SETTINGS
# ============================================================

LABEL_NAME = "Suspicious Link"


# ============================================================
# GET OR CREATE GMAIL LABEL
# ============================================================

def get_label_id(service):
    """
    Find the Suspicious Link label.
    Create it if it does not already exist.
    """

    try:
        response = service.users().labels().list(
            userId="me"
        ).execute()

    except HttpError as e:
        print()
        print("ERROR: Could not retrieve Gmail labels.")
        print(e)
        return None

    labels = response.get(
        "labels",
        []
    )

    # --------------------------------------------------------
    # LOOK FOR EXISTING LABEL
    # --------------------------------------------------------

    for label in labels:

        if label.get("name") == LABEL_NAME:

            print(
                f"Using existing Gmail label: {LABEL_NAME}"
            )

            return label.get("id")

    # --------------------------------------------------------
    # CREATE LABEL
    # --------------------------------------------------------

    print(
        f"Gmail label '{LABEL_NAME}' does not exist."
    )

    print(
        "Creating it..."
    )

    try:

        response = service.users().labels().create(
            userId="me",
            body={
                "name": LABEL_NAME,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show"
            }
        ).execute()

        label_id = response.get(
            "id"
        )

        print(
            f"Created Gmail label: {LABEL_NAME}"
        )

        return label_id

    except HttpError as e:

        print()
        print(
            "ERROR: Could not create Gmail label."
        )

        print(e)

        return None


# ============================================================
# CHECK WHETHER EMAIL ALREADY HAS LABEL
# ============================================================

def email_already_labeled(service, message_id, label_id):

    try:

        message = service.users().messages().get(
            userId="me",
            id=message_id,
            format="minimal"
        ).execute()

        label_ids = message.get(
            "labelIds",
            []
        )

        return label_id in label_ids

    except HttpError as e:

        print(
            f"Could not check message {message_id}: {e}"
        )

        return False


# ============================================================
# APPLY LABEL
# ============================================================

def apply_label(service, message_id, label_id):

    # --------------------------------------------------------
    # DON'T APPLY IT TWICE
    # --------------------------------------------------------

    if email_already_labeled(
        service,
        message_id,
        label_id
    ):

        print(
            "  Gmail Label: ALREADY APPLIED"
        )

        return True

    # --------------------------------------------------------
    # APPLY LABEL
    # --------------------------------------------------------

    try:

        service.users().messages().modify(
            userId="me",
            id=message_id,
            body={
                "addLabelIds": [
                    label_id
                ]
            }
        ).execute()

    except HttpError as e:

        print()
        print(
            f"ERROR: Could not label message {message_id}"
        )

        print(e)

        return False

    # --------------------------------------------------------
    # VERIFY
    # --------------------------------------------------------

    if email_already_labeled(
        service,
        message_id,
        label_id
    ):

        print(
            "  Gmail Label: APPLIED"
        )

        return True

    print(
        "  Gmail Label: FAILED VERIFICATION"
    )

    return False


# ============================================================
# FLAG MESSAGES
# ============================================================

def flag_messages(results, service):

    """
    Receives fresh results directly from link_checker.py.

    results format:

    [
        {
            "url": "...",
            "result": "MALICIOUS",
            "google": {...},
            "urlhaus": {...},
            "sources": [
                {
                    "message_id": "...",
                    "subject": "...",
                    "sender": "..."
                }
            ]
        }
    ]
    """

    if not results:

        print(
            "No results were sent to the Gmail flagger."
        )

        return

    print()
    print("=" * 70)
    print("GMAIL FLAGGING")
    print("=" * 70)

    # --------------------------------------------------------
    # GET LABEL
    # --------------------------------------------------------

    label_id = get_label_id(
        service
    )

    if not label_id:

        print()
        print(
            "Unable to get the Gmail label."
        )

        print(
            "No emails were flagged."
        )

        return

    # --------------------------------------------------------
    # KEEP TRACK OF MESSAGES
    # --------------------------------------------------------

    already_processed = set()

    flagged_count = 0
    skipped_count = 0
    failed_count = 0

    # --------------------------------------------------------
    # PROCESS RESULTS
    # --------------------------------------------------------

    for result in results:

        url = result.get(
            "url",
            ""
        )

        status = result.get(
            "result",
            ""
        )

        sources = result.get(
            "sources",
            []
        )

        print()
        print(
            f"URL: {url}"
        )

        print(
            f"Result: {status}"
        )

        # ----------------------------------------------------
        # ONLY MALICIOUS LINKS ARE FLAGGED
        # ----------------------------------------------------

        if status != "MALICIOUS":

            print(
                "No Gmail label needed."
            )

            skipped_count += 1

            continue

        # ----------------------------------------------------
        # MAKE SURE WE HAVE SOURCE EMAILS
        # ----------------------------------------------------

        if not sources:

            print(
                "WARNING: No source email was provided."
            )

            failed_count += 1

            continue

        # ----------------------------------------------------
        # FLAG EACH SOURCE EMAIL
        # ----------------------------------------------------

        for source in sources:

            message_id = source.get(
                "message_id"
            )

            subject = source.get(
                "subject",
                "(no subject)"
            )

            sender = source.get(
                "sender",
                "(unknown sender)"
            )

            if not message_id:

                print(
                    "WARNING: Source has no message ID."
                )

                failed_count += 1

                continue

            # Prevent processing the exact same Gmail
            # message more than once during this run.

            if message_id in already_processed:

                print(
                    f"Message {message_id} was already processed."
                )

                continue

            already_processed.add(
                message_id
            )

            print()
            print(
                "Flagging email:"
            )

            print(
                f"  Subject: {subject}"
            )

            print(
                f"  Sender: {sender}"
            )

            print(
                f"  Message ID: {message_id}"
            )

            success = apply_label(
                service,
                message_id,
                label_id
            )

            if success:

                flagged_count += 1

            else:

                failed_count += 1

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("GMAIL FLAGGING COMPLETE")
    print("=" * 70)

    print(
        f"Emails flagged: {flagged_count}"
    )

    print(
        f"Results skipped: {skipped_count}"
    )

    print(
        f"Failures: {failed_count}"
    )

    print()


# ============================================================
# STANDALONE WARNING
# ============================================================

if __name__ == "__main__":

    print(
        "flag_emails.py is designed to be called by "
        "link_checker.py."
    )

    print()
    print(
        "Start the complete system with:"
    )

    print(
        "    python scanner.py"
    )

