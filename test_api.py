import os
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Load environment variables from .env file
load_dotenv()
TEST_RECIPIENT_EMAIL = 'dm@fortunehestia.in' # <--- IMPORTANT: CHANGE THIS!
# Get SendGrid API Key and Sender Email from environment variables
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDGRID_SENDER_EMAIL = os.getenv('SENDGRID_SENDER_EMAIL')

# --- CONFIGURATION (UPDATE THESE) ---
# Use an email address you can check (your personal email for testing)
TEST_RECIPIENT_EMAIL = 'your_personal_email@example.com' # <--- IMPORTANT: CHANGE THIS!
TEST_SUBJECT = "SendGrid Test from Local Script"
TEST_BODY = "<p>This is a test email sent from a standalone Python script using your SendGrid API Key.</p>"
# --- END CONFIGURATION ---

print(f"Attempting to send email from: {SENDGRID_SENDER_EMAIL}")
print(f"Using SendGrid API Key (first 10 chars): {SENDGRID_API_KEY[:10]}...")
print(f"Using SendGrid API Key (last 5 chars): ...{SENDGRID_API_KEY[-5:]}")


if not SENDGRID_API_KEY:
    print("Error: SENDGRID_API_KEY not found. Make sure it's in your .env file.")
elif not SENDGRID_SENDER_EMAIL:
    print("Error: SENDGRID_SENDER_EMAIL not found. Make sure it's in your .env file.")
elif not TEST_RECIPIENT_EMAIL or TEST_RECIPIENT_EMAIL == 'your_personal_email@example.com':
    print("Error: Please set TEST_RECIPIENT_EMAIL to a real email address in test_sendgrid.py.")
else:
    message = Mail(
        from_email=SENDGRID_SENDER_EMAIL,
        to_emails=TEST_RECIPIENT_EMAIL,
        subject=TEST_SUBJECT,
        html_content=TEST_BODY
    )
    try:
        sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
        response = sendgrid_client.send(message)
        print("\n--- SendGrid API Response ---")
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {response.body}")
        print(f"Response Headers: {response.headers}")

        if response.status_code >= 200 and response.status_code < 300:
            print(f"\nSUCCESS: Email sent to {TEST_RECIPIENT_EMAIL}!")
            print("Check the recipient's inbox and your SendGrid Activity Feed.")
        else:
            print(f"\nFAILURE: SendGrid returned an error status code.")
            print("This indicates an issue with your API key, sender verification, or SendGrid account limits.")

    except Exception as e:
        print(f"\nAN EXCEPTION OCCURRED: {e}")
        print("This usually means a problem with network connectivity, invalid API key format, or other Python/library issues.")

