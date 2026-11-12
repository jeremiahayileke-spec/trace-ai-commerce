import os
import json
import base64
import hashlib
import sqlite3
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from uuid import uuid4

import requests
from dotenv import load_dotenv

from policy import _matches_prohibited

load_dotenv(override=True)

PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET")
PAYPAL_BASE_URL = os.getenv(
    "PAYPAL_BASE_URL",
    "https://api-m.sandbox.paypal.com"
).rstrip("/")


def get_access_token():
    if not PAYPAL_CLIENT_ID or not PAYPAL_CLIENT_SECRET:
        raise RuntimeError(
            "Missing PayPal API credentials. Check your .env file."
        )

    credentials = f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}"
    encoded_credentials = base64.b64encode(
        credentials.encode("utf-8")
    ).decode("utf-8")

    response = requests.post(
        f"{PAYPAL_BASE_URL}/v1/oauth2/token",
        headers={
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"grant_type": "client_credentials"},
        timeout=30,
    )
    response.raise_for_status()

    return response.json()["access_token"]


# ============================================================
# PROVENANCE HELPERS
# ============================================================

def credential_fingerprint():
    """Identify WHICH PayPal app and environment TRACE is using.

    PayPal orders belong to the REST app that created them, so an order
    can only be read back with the same client ID in the same
    environment. The fingerprint is a short hash of the client ID, so it
    can be stored and compared without keeping the ID itself.
    """
    client_id = PAYPAL_CLIENT_ID or ""

    return {
        "environment": (
            "sandbox"
            if "sandbox" in PAYPAL_BASE_URL.lower()
            else "live_or_custom"
        ),
        "base_url": PAYPAL_BASE_URL,
        "client_id_fingerprint": (
            hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:10]
            if client_id
            else None
        ),
        "client_id_hint": (
            f"...{client_id[-4:]}" if len(client_id) >= 8 else None
        ),
    }


def error_summary(response):
    """The useful parts of a PayPal error body, never the whole thing."""
    if response is None:
        return None

    try:
        body = response.json()
    except ValueError:
        return {"raw": (response.text or "")[:300]}

    if isinstance(body, dict):
        return {
            key: body[key]
            for key in (
                "name",
                "message",
                "debug_id",
                "details",
                "error",
                "error_description",
            )
            if key in body
        }

    return {"raw": str(body)[:300]}


def lookup_order(order_id):
    """Look an order up WITHOUT raising, and say exactly what happened.

    Returns {"ok", "stage", "http_status", "order" | "error"} where stage
    is one of: config, auth, network, lookup.
    """
    try:
        token = get_access_token()

    except RuntimeError as exc:
        return {
            "ok": False,
            "stage": "config",
            "http_status": None,
            "error": {"message": str(exc)},
        }

    except requests.HTTPError as exc:
        response = exc.response
        return {
            "ok": False,
            "stage": "auth",
            "http_status": (
                response.status_code if response is not None else None
            ),
            "error": error_summary(response),
        }

    except requests.RequestException as exc:
        return {
            "ok": False,
            "stage": "network",
            "http_status": None,
            "error": {"message": type(exc).__name__},
        }

    try:
        response = requests.get(
            f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )

    except requests.RequestException as exc:
        return {
            "ok": False,
            "stage": "network",
            "http_status": None,
            "error": {"message": type(exc).__name__},
        }

    if response.status_code == 200:
        return {
            "ok": True,
            "stage": "lookup",
            "http_status": 200,
            "order": response.json(),
        }

    return {
        "ok": False,
        "stage": "lookup",
        "http_status": response.status_code,
        "error": error_summary(response),
    }


def _save_snapshot(mission_id, payload, order, excluded_event_ids):
    """Keep what TRACE sent and what PayPal answered, with provenance."""
    from database import get_connection

    fingerprint = credential_fingerprint()

    try:
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO paypal_order_snapshots (
                    snapshot_id, mission_id, paypal_order_id,
                    request_json, response_json, excluded_event_ids,
                    client_id_fingerprint, base_url, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"SNP-{uuid4().hex[:8].upper()}",
                    mission_id,
                    order["id"],
                    json.dumps(payload),
                    json.dumps(order),
                    json.dumps(excluded_event_ids),
                    fingerprint["client_id_fingerprint"],
                    fingerprint["base_url"],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    except Exception as exc:
        print(f"TRACE SNAPSHOT ERROR: {type(exc).__name__}: {exc}")
        # The order already exists at PayPal, so do not fail creation.
        print(f"TRACE: could not save order snapshot: {exc}")


# ORDER CREATION

def _parse_prohibited(raw):
    """Accept a JSON list or a legacy comma-separated string."""
    raw = raw or ""

    if isinstance(raw, str):
        try:
            parsed = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            parsed = [
                item.strip()
                for item in raw.split(",")
                if item.strip()
            ]
    else:
        parsed = raw

    if not isinstance(parsed, list):
        return []

    return [str(item) for item in parsed]


def create_order(mission_id):
    from database import get_connection

    with get_connection() as connection:
        mission = connection.execute(
            """
            SELECT mission_id, objective, max_budget, currency,
                   prohibited_add_ons
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission is None:
            raise ValueError("Mission not found.")

        events = connection.execute(
            """
            SELECT event_id, event_type, item_name, description, amount
            FROM agent_events
            WHERE mission_id = ?
            ORDER BY rowid
            """,
            (mission_id,),
        ).fetchall()

    prohibited = _parse_prohibited(mission["prohibited_add_ons"])

    # The order contains the selected product and any ALLOWED add-ons.
    # Prohibited add-ons are deliberately left out of the PayPal order;
    # the agent's record of adding them is kept for the audit trail and is
    # later reconciled through POST /missions/{id}/resolutions.
    total = Decimal("0.00")
    items = []
    excluded_prohibited = []

    for event in events:
        event_type = event["event_type"]

        if event_type not in ("product_selected", "add_on_added"):
            continue

        event_text = (
            f"{event['item_name'] or ''} "
            f"{event['description'] or ''}"
        )

        if event_type == "add_on_added" and _matches_prohibited(
            event_text, prohibited
        ):
            excluded_prohibited.append(event["event_id"])
            continue

        if event["amount"] is None:
            raise ValueError(
                f"Missing amount for event {event['event_id']}."
            )

        try:
            amount = Decimal(str(event["amount"]))
        except InvalidOperation as exc:
            raise ValueError(
                f"Invalid amount for event {event['event_id']}."
            ) from exc

        if not amount.is_finite() or amount < 0:
            raise ValueError(
                f"Invalid amount for event {event['event_id']}."
            )

        # PayPal requires item amounts to add up exactly, so round each
        # item to cents first and total the rounded values.
        amount = amount.quantize(Decimal("0.01"))

        total += amount
        items.append(
            (
                (event["item_name"] or event["description"] or "Item")[:127],
                amount,
            )
        )

    if total <= 0:
        raise ValueError(
            "Cannot create PayPal order: no verified product total. "
            "Record a product_selected event with an amount first."
        )

    budget = Decimal(str(mission["max_budget"]))

    if total > budget:
        raise ValueError(
            "Cannot create PayPal order: verified total "
            f"{total:.2f} exceeds the authorised budget {budget:.2f}."
        )

    token = get_access_token()

    currency = mission["currency"]

    # The unit description is deliberately neutral. The mission objective
    # can mention prohibited terms ("no protection plans"), which would
    # make TRACE's own capture checks flag the order as containing them.
    description = f"TRACE mission {mission['mission_id']}"

    # Line items are the evidence PayPal itself holds about what is being
    # bought, so TRACE can later check the live order, not just its own log.
    paypal_items = [
        {
            "name": name,
            "quantity": "1",
            "unit_amount": {
                "currency_code": currency,
                "value": f"{amount:.2f}",
            },
            "category": "PHYSICAL_GOODS",
        }
        for name, amount in items
    ]

    payload = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "reference_id": mission["mission_id"],
                "custom_id": mission["mission_id"],
                "description": description,
                "amount": {
                    "currency_code": currency,
                    "value": f"{total:.2f}",
                    "breakdown": {
                        "item_total": {
                            "currency_code": currency,
                            "value": f"{total:.2f}",
                        }
                    },
                },
                "items": paypal_items,
            }
        ],
    }

    response = requests.post(
        f"{PAYPAL_BASE_URL}/v2/checkout/orders",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            # Ask PayPal to echo the full order back, not just the ID,
            # so the creation snapshot holds PayPal's own record.
            "Prefer": "return=representation",
        },
        json=payload,
        timeout=30,
    )
    response.raise_for_status()

    order = response.json()
    _save_snapshot(mission_id, payload, order, excluded_prohibited)
    print("TRACE: snapshot call completed")
    return order


def _save_snapshot(mission_id, payload, order, excluded_event_ids):
    from database import get_connection
    import traceback

    print("SNAPSHOT: FUNCTION ENTERED")

    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO paypal_order_snapshots (
                    snapshot_id, mission_id, paypal_order_id,
                    request_json, response_json, excluded_event_ids,
                    client_id_fingerprint, base_url, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"SNP-{uuid4().hex[:8].upper()}",
                    mission_id,
                    order["id"],
                    json.dumps(payload),
                    json.dumps(order),
                    json.dumps(excluded_event_ids),
                    credential_fingerprint()["client_id_fingerprint"],
                    credential_fingerprint()["base_url"],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            print("SNAPSHOT: INSERTED", cursor.rowcount)

    except Exception:
        traceback.print_exc()


def create_canary_order():
    """A $1.00 sandbox order used only to prove the credentials can
    create an order and read it straight back. It is never captured."""
    token = get_access_token()

    payload = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "reference_id": "TRACE-CANARY",
                "custom_id": "TRACE-CANARY",
                "description": "TRACE credential round-trip test",
                "amount": {"currency_code": "USD", "value": "1.00"},
            }
        ],
    }

    response = requests.post(
        f"{PAYPAL_BASE_URL}/v2/checkout/orders",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )
    response.raise_for_status()

    return response.json()


# ============================================================
# ORDER LOOKUP AND CAPTURE
# ============================================================

def get_order(order_id):
    token = get_access_token()

    response = requests.get(
        f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    response.raise_for_status()

    return response.json()


def capture_order(order_id):
    token = get_access_token()

    response = requests.post(
        f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}/capture",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={},
        timeout=30,
    )
    response.raise_for_status()

    return response.json()


def paypal_diagnostics(order_id):
    token = get_access_token()

    response = requests.get(
        f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )

    return {
        "api_environment": (
            "sandbox"
            if "sandbox" in PAYPAL_BASE_URL.lower()
            else "live_or_custom"
        ),
        "http_status": response.status_code,
        "paypal_response": response.json()
        if response.content
        else None,
    }