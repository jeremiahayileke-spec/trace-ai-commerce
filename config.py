import os
from dotenv import load_dotenv

load_dotenv()

PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
PAYPAL_BASE_URL = os.getenv(
    "PAYPAL_BASE_URL",
    "https://api-m.sandbox.paypal.com"
)

print("PayPal Client ID loaded:", bool(PAYPAL_CLIENT_ID))
print("PayPal Client Secret loaded:", bool(PAYPAL_CLIENT_SECRET))
print("PayPal Base URL:", PAYPAL_BASE_URL)