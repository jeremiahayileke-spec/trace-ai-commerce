# TRACE
### AI Commerce Incident Detection, Evidence and Resolution

TRACE is an AI-commerce incident response system that detects when submitted AI-agent purchase activity deviates from a human-authorised purchasing mission.

## Workflow

DETECT → TRACE → EXPLAIN → PROVE → RESOLVE

- DETECT: Check submitted agent events against mission constraints.
- TRACE: Associate events with missions and PayPal orders.
- EXPLAIN: Use Google Gemini to explain policy findings.
- PROVE: Retrieve evidence and verify PayPal Sandbox order contents.
- RESOLVE: Record human review and resolution decisions.

## Technology

- Python
- FastAPI
- SQLite
- PayPal REST API (Sandbox)
- Google Gemini
- Uvicorn

## Features

- Create purchasing missions with budgets and restrictions.
- Submit agent activity events.
- Detect budget overruns and prohibited items.
- Generate AI-assisted explanations.
- Retrieve evidence and incident reports.
- Verify PayPal Sandbox orders.
- Record human reviews and resolutions.

## Setup

Requirements: Python, PayPal Sandbox credentials and a Google Gemini API key.

1. Clone the repository.
2. Create a virtual environment:

   `python -m venv venv`

3. Activate it on Windows:

   `.\venv\Scripts\Activate.ps1`

4. Install dependencies:

   `pip install -r backend/requirements.txt`

5. Create a `.env` file using `.env.example` and add your own credentials.

6. Start the application:

   `uvicorn app:app --reload`

Open `http://127.0.0.1:8000/docs` for API documentation.

## Environment Variables

- PAYPAL_CLIENT_ID
- PAYPAL_CLIENT_SECRET
- PAYPAL_BASE_URL
- GEMINI_API_KEY

Never publish actual API keys.

## Important Limitations

- The PayPal integration is configured for Sandbox testing.
- Agent events are submitted to TRACE; TRACE does not independently intercept external AI-agent actions.
- Gemini explains policy findings but does not replace the deterministic policy engine.
- PayPal order verification shows retrieved order contents; it does not independently prove every submitted agent event occurred.
- Human resolution records do not automatically execute refunds or modify PayPal orders.
- The application has a separate PayPal capture endpoint. It must only be used with appropriate authorisation and testing conditions.

## License

See LICENSE.