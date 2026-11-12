import json
import re
import requests
import paypal

from database import get_connection, initialize_database
from policy import _normalize_words, _matches_prohibited
import importlib
from datetime import datetime, timezone
from typing import Literal
from decimal import Decimal, InvalidOperation
from uuid import uuid4
from pydantic import BaseModel, Field
from fastapi import APIRouter, FastAPI, HTTPException
from paypal import (
    get_access_token,
    create_order,
    capture_order,
    get_order,
)

# Diagnostics are an optional extension; keep the core API importable when
# that extension is not installed/deployed alongside this module.
try:
    _trace_diagnostics = importlib.import_module("trace_diagnostics")
except ModuleNotFoundError as error:
    if error.name != "trace_diagnostics":
        raise
    diagnostics_router = APIRouter()

    def create_order_or_raise(*args, **kwargs):
        raise RuntimeError("TRACE diagnostics extension is unavailable.")

    def load_creation_snapshot(*args, **kwargs):
        raise RuntimeError("TRACE diagnostics extension is unavailable.")
else:
    diagnostics_router = _trace_diagnostics.router
    create_order_or_raise = _trace_diagnostics.create_order_or_raise
    load_creation_snapshot = _trace_diagnostics.load_creation_snapshot

def analyze_with_gemini(mission, events, deterministic_result):
    prompt = f"""
You are TRACE, an AI-commerce incident response analyst.

Explain the incident using only the supplied evidence.

MISSION:
{json.dumps(mission, default=str)}

AGENT EVENTS:
{json.dumps(events, default=str)}

DETERMINISTIC POLICY ANALYSIS:
{json.dumps(deterministic_result, default=str)}

Instructions:
1. Explain what happened in simple, precise language.
2. Identify the policy violations already detected.
3. Explain the evidence supporting each violation.
4. Recommend a safe next step for human review.
5. Do not invent facts or claim that a payment was captured.
6. Never authorize payments, captures, refunds, or other transactions.
7. If no violation exists, explain that no drift was detected.

Return a concise incident explanation.
"""

    try:
        response = gemini_client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        return response.text or "Gemini returned an empty explanation."

    except Exception as error:
        print(f"Gemini analysis error: {error}")
        return "AI explanation temporarily unavailable. Deterministic analysis remains authoritative."


app = FastAPI(title="TRACE API")
from google import genai
import os

gemini_client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY")
)

initialize_database()


# ============================================================
# MODELS
# ============================================================

class MissionCreate(BaseModel):
    objective: str
    max_budget: Decimal = Field(gt=0)
    currency: str = "USD"
    prohibited_add_ons: list[str] = Field(default_factory=list)


class AgentEventCreate(BaseModel):
    event_type: Literal[
        "product_selected",
        "add_on_added",
        "order_submitted",
        "payment_captured",
    ]
    description: str
    amount: Decimal | None = None
    item_name: str | None = None


class IncidentReviewCreate(BaseModel):
    decision: Literal[
        "approve_pause",
        "dismiss",
        "approve_capture",
    ]
    reason: str = Field(min_length=5, max_length=1000)
    reviewer: str = Field(min_length=2, max_length=100)


# ============================================================
# POLICY HELPERS
# ============================================================

def _assess_capture_readiness(order_id: str) -> dict:
    import json
    from decimal import Decimal, InvalidOperation

    blockers = []
    paypal_error = None
    paypal_order = None
    paypal_status = "UNAVAILABLE"
    budget = None
    recorded_total = Decimal("0.00")
    effective_total = Decimal("0.00")
    resolved_event_ids = []

   
    # 1. Load the mission, its latest order-specific review,
    #    its remediation records, and all mission events.
    with get_connection() as connection:
        mission_row = connection.execute(
            """
            SELECT mission_id, objective, max_budget, currency,
                   prohibited_add_ons, paypal_order_id
            FROM missions
            WHERE paypal_order_id = ?
            """,
            (order_id,),
        ).fetchone()

        if mission_row is None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Capture blocked: this order is not linked "
                    "to a TRACE mission."
                ),
            )

        mission = dict(mission_row)

        # One review query only; reviews are order-specific.
        review_row = connection.execute(
            """
            SELECT review_id, incident_id, decision, reason,
                   reviewer, created_at, paypal_order_id
            FROM incident_reviews
            WHERE mission_id = ?
              AND paypal_order_id = ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
            """,
            (mission["mission_id"], order_id),
        ).fetchone()

        latest_review = (
            dict(review_row) if review_row is not None else None
        )

        # One resolution query only.
        resolutions = [
            dict(row)
            for row in connection.execute(
                """
                SELECT resolution_id, event_id, resolution_type,
                       reason, reviewer, evidence_json, created_at
                FROM incident_resolutions
                WHERE mission_id = ?
                  AND paypal_order_id = ?
                ORDER BY created_at, rowid
                """,
                (mission["mission_id"], order_id),
            ).fetchall()
        ]

        # Agent events are mission-scoped, not order-scoped.
        # Include amount because the assessment calculates totals.
        events = [
            dict(row)
            for row in connection.execute(
                """
SELECT event_id, event_type, item_name, description, amount
FROM agent_events
WHERE mission_id = ?
ORDER BY timestamp, rowid
                """,
                (mission["mission_id"],),
            ).fetchall()
        ]

    # The existing resolution-validation logic uses this variable.
    resolution_rows = resolutions

    # 2. The current order must have its own explicit human approval.
    if latest_review is None:
        blockers.append({
            "code": "human_review_required",
            "message": "No human review is recorded for this PayPal order.",
        })
    elif latest_review["decision"] != "approve_capture":
        blockers.append({
            "code": "capture_not_approved",
            "message": (
                "The latest human review for this order does not "
                "explicitly approve capture."
            ),
        })

    # 3. Validate mission policy data.
    try:
        budget = Decimal(str(mission["max_budget"]))
        prohibited = json.loads(
            mission["prohibited_add_ons"] or "[]"
        )

        if not budget.is_finite() or budget <= 0:
            raise ValueError("Invalid mission budget")

        if (
            not isinstance(prohibited, list)
            or not all(isinstance(item, str) for item in prohibited)
        ):
            raise ValueError("Invalid prohibited-add-on rules")

    except (ValueError, TypeError, InvalidOperation):
        prohibited = []
        blockers.append({
            "code": "policy_data_invalid",
            "message": "Mission policy data is invalid; capture is blocked.",
        })

    # 4. Validate the saved resolution evidence.
    #    A resolution only applies to its own event and PayPal order.
    event_by_id = {event["event_id"]: event for event in events}

    for resolution in resolution_rows:
        event = event_by_id.get(resolution["event_id"])

        if event is None or (
            resolution["resolution_type"]
            != "prohibited_add_on_removed_before_checkout"
        ):
            blockers.append({
                "code": "resolution_invalid",
                "message": "A recorded resolution does not match a valid event.",
                "resolution_id": resolution["resolution_id"],
            })
            continue

        if (
            event["event_type"] != "add_on_added"
           or not _matches_prohibited(
    f"{event.get('item_name') or ''} "
    f"{event.get('description') or ''}",
    prohibited,
)
        ):
            blockers.append({
                "code": "resolution_invalid",
                "message": (
                    "The resolution does not match a prohibited "
                    "add-on event."
                ),
                "resolution_id": resolution["resolution_id"],
            })
            continue

        try:
            evidence = json.loads(resolution["evidence_json"])

            if not isinstance(evidence, dict):
                raise ValueError("Invalid resolution evidence")

            saved_units = evidence.get("purchase_units", [])
            saved_total = Decimal(
                str(evidence.get("verified_order_total", ""))
            )

            evidence_valid = (
                evidence.get("order_id") == order_id
                and evidence.get("affected_event_id")
                == resolution["event_id"]
                and evidence.get("currency") == mission["currency"]
                and evidence.get("order_status") in ("CREATED", "APPROVED")
                and saved_total.is_finite()
                and saved_total >= 0
                and saved_total <= budget
                and isinstance(saved_units, list)
                and bool(saved_units)
            )

            saved_amount_total = Decimal("0.00")

            if evidence_valid:
                for unit in saved_units:
                    amount_data = unit.get("amount") or {}

                    if (
                        unit.get("custom_id") != mission["mission_id"]
                        or amount_data.get("currency_code")
                        != mission["currency"]
                    ):
                        evidence_valid = False
                        break

                    amount = Decimal(str(amount_data.get("value", "")))

                    if not amount.is_finite() or amount < 0:
                        evidence_valid = False
                        break

                    saved_amount_total += amount

                    item_text = " ".join([
                        str(unit.get("description") or ""),
                        " ".join(
                            str(item.get("name") or "")
                            for item in unit.get("items", [])
                            if isinstance(item, dict)
                        ),
                    ])

                    if _matches_prohibited(item_text, prohibited):
                        evidence_valid = False
                        break

            if (
                evidence_valid
                and saved_amount_total == saved_total
            ):
                resolved_event_ids.append(resolution["event_id"])
            else:
                blockers.append({
                    "code": "resolution_evidence_invalid",
                    "message": (
                        "Saved resolution evidence failed validation."
                    ),
                    "resolution_id": resolution["resolution_id"],
                })

        except (
            ValueError,
            TypeError,
            InvalidOperation,
            json.JSONDecodeError,
            AttributeError,
        ):
            blockers.append({
                "code": "resolution_evidence_invalid",
                "message": (
                    "Saved resolution evidence could not be validated."
                ),
                "resolution_id": resolution["resolution_id"],
            })

    # 5. Calculate original and effective event totals.
    #    Original events are preserved for the audit trail.
    #    A valid resolution excludes only its specific add-on event.
    resolved_set = set(resolved_event_ids)
    unresolved_prohibited_events = []

    try:
        for event in events:
            if event["event_type"] not in (
                "product_selected",
                "add_on_added",
            ):
                continue

            amount = Decimal(str(event["amount"] or "0"))

            if not amount.is_finite() or amount < 0:
                raise ValueError("Invalid event amount")

            recorded_total += amount

            resolved = (
                event["event_id"] in resolved_set
                and event["event_type"] == "add_on_added"
            )

            if not resolved:
                effective_total += amount

            if (
                _matches_prohibited(
                    f"{event.get('item_name') or ''} "
                    f"{event.get('description') or ''}",
                    prohibited,
                )
                and not resolved
            ):
                unresolved_prohibited_events.append(event)
                blockers.append({
                    "code": "prohibited_add_on",
                    "message": (
                        "A prohibited add-on remains unresolved: "
                        f"{event.get('item_name') or event.get('description') or event['event_id']}."
                    ),
                    "event_id": event["event_id"],
                    "item_name": event.get("item_name") or event.get("description"),
                })

        if budget is not None and effective_total > budget:
            blockers.append({
                "code": "budget_exceeded",
                "message": (
                    f"Effective recorded total {effective_total:.2f} "
                    f"{mission['currency']} exceeds the authorized "
                    f"budget of {budget:.2f} {mission['currency']}."
                ),
            })

    except (ValueError, TypeError, InvalidOperation):
        blockers.append({
            "code": "event_data_invalid",
            "message": "Agent event amounts could not be validated.",
        })

    # 6. Retrieve and verify the current live PayPal order.
    try:
        paypal_order = get_order(order_id)
        paypal_status = paypal_order.get("status", "UNKNOWN")

    except requests.HTTPError as exc:
        response = exc.response
        status_code = (
            response.status_code if response is not None else None
        )
        paypal_error = (
            f"PayPal order lookup failed with HTTP {status_code}."
            if status_code is not None
            else "PayPal order lookup failed."
        )
        blockers.append({
            "code": "paypal_order_unavailable",
            "message": paypal_error,
        })

    except requests.RequestException:
        paypal_error = "PayPal could not be reached to verify the order."
        blockers.append({
            "code": "paypal_unreachable",
            "message": paypal_error,
        })

    # 7. Verify order identity, buyer approval, amount, and contents.
    if paypal_order is not None:
        if paypal_order.get("id") != order_id:
            blockers.append({
                "code": "paypal_order_mismatch",
                "message": "PayPal returned a different order ID.",
            })

        if paypal_status != "APPROVED":
            blockers.append({
                "code": "buyer_approval_required",
                "message": (
                    f"PayPal order status is {paypal_status}; "
                    "buyer approval is required."
                ),
            })

        units = paypal_order.get("purchase_units", [])

        if not units:
            blockers.append({
                "code": "purchase_units_missing",
                "message": "PayPal returned no purchase units.",
            })
        else:
            live_total = Decimal("0.00")
            amounts_valid = True

            for unit in units:
                if unit.get("custom_id") != mission["mission_id"]:
                    blockers.append({
                        "code": "mission_association_mismatch",
                        "message": (
                            "PayPal order does not match this mission."
                        ),
                    })

                amount_data = unit.get("amount") or {}

                if (
                    amount_data.get("currency_code")
                    != mission["currency"]
                ):
                    blockers.append({
                        "code": "currency_mismatch",
                        "message": (
                            "PayPal order currency differs from "
                            "the mission currency."
                        ),
                    })

                try:
                    amount = Decimal(
                        str(amount_data.get("value", ""))
                    )

                    if not amount.is_finite() or amount < 0:
                        raise InvalidOperation

                    live_total += amount

                except (InvalidOperation, ValueError, TypeError):
                    amounts_valid = False
                    blockers.append({
                        "code": "paypal_amount_invalid",
                        "message": "PayPal returned an invalid amount.",
                    })

                item_text = " ".join([
                    str(unit.get("description") or ""),
                    " ".join(
                        str(item.get("name") or "")
                        for item in unit.get("items", [])
                        if isinstance(item, dict)
                    ),
                ])

                if _matches_prohibited(item_text, prohibited):
                    blockers.append({
                        "code": "paypal_prohibited_item",
                        "message": (
                            "The live PayPal order includes "
                            "a prohibited item."
                        ),
                    })

            if amounts_valid:
                if budget is not None and live_total > budget:
                    blockers.append({
                        "code": "paypal_budget_exceeded",
                        "message": (
                            f"PayPal total {live_total:.2f} "
                            f"{mission['currency']} exceeds the "
                            f"{budget:.2f} {mission['currency']} budget."
                        ),
                    })

                if live_total != effective_total:
                    blockers.append({
                        "code": "event_order_total_mismatch",
                        "message": (
                            f"Live PayPal total is {live_total:.2f} "
                            f"{mission['currency']}, but the effective "
                            f"event total is {effective_total:.2f} "
                            f"{mission['currency']}. The difference "
                            "must be reconciled before capture."
                        ),
                    })

    capture_allowed = not blockers

    return {
        "mission_id": mission["mission_id"],
        "order_id": order_id,
        "latest_review_id": (
            latest_review["review_id"] if latest_review else None
        ),
        "latest_decision": (
            latest_review["decision"] if latest_review else None
        ),
        "paypal_status": paypal_status,
        "capture_allowed": capture_allowed,
        "blockers": blockers,
        "recorded_event_total": str(recorded_total),
        "effective_policy_total": str(effective_total),
        "resolved_event_ids": resolved_event_ids,
        "reason": (
            "All capture checks passed."
            if capture_allowed
            else "Capture blocked: " + " ".join(
                blocker["message"] for blocker in blockers
            )
        ),
        "paypal_error": paypal_error,
        "payment_action_executed": False,
    }
    


# ============================================================
# ROOT AND PAYPAL ENDPOINTS
# ============================================================

@app.get("/")
def root():
    return {
        "project": "TRACE",
        "status": "running",
        "message": (
            "TRACE API is running. Use the mission endpoints "
            "to inspect recorded agent activity."
        ),
    }


@app.get("/paypal/test")
def paypal_test():
    token = get_access_token()

    return {
        "paypal": "connected",
        "token_received": bool(token),
    }


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

    prohibited = json.loads(mission["prohibited_add_ons"] or "[]")
    if not isinstance(prohibited, list) or not all(
        isinstance(item, str) for item in prohibited
    ):
        raise ValueError("Invalid prohibited-add-on rules.")

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
                event_type,
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
        for name, amount, _event_type in items
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
        f"{paypal.PAYPAL_BASE_URL}/v2/checkout/orders",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )
    response.raise_for_status()

    order = response.json()

    paypal._save_snapshot(
        mission_id,
        payload,
        order,
        excluded_prohibited,
    )

    return order


@app.post("/paypal/create-order/{mission_id}")
def paypal_create_order(mission_id: str):
    with get_connection() as connection:
        mission = connection.execute(
            """
            SELECT mission_id, paypal_order_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

    if mission is None:
        raise HTTPException(
            status_code=404,
            detail="Mission not found",
        )

    if mission["paypal_order_id"]:
        raise HTTPException(
            status_code=409,
            detail="This mission already has a linked PayPal order.",
        )

    try:
        order = create_order(mission_id)

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except requests.HTTPError as exc:
        response = exc.response
        raise HTTPException(
            status_code=502,
            detail={
                "message": "PayPal rejected order creation.",
                "paypal_status_code": (
                    response.status_code if response is not None else None
                ),
            },
        ) from exc

    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="Could not contact PayPal.",
        ) from exc

    order_id = order["id"]
    print("PAYPAL CREATED ORDER ID:", order_id)
    print("PAYPAL CREATED ORDER STATUS:", order.get("status"))
    print("PAYPAL BASE URL:", paypal.PAYPAL_BASE_URL)

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE missions
            SET paypal_order_id = ?
            WHERE mission_id = ?
            """,
            (order_id, mission_id),
        )

    return {
        "message": "PayPal order created and linked",
        "mission_id": mission_id,
        "order_id": order_id,
        "status": order["status"],
        "payment_action_executed": False,
    }

@app.get("/paypal/order/{order_id}")
def paypal_order_status(order_id: str):
    try:
        order = get_order(order_id)

    except requests.HTTPError as exc:
        response = exc.response
        status_code = (
            response.status_code
            if response is not None
            else None
        )

        paypal_error = {}

        if response is not None:
            try:
                body = response.json()

                if isinstance(body, dict):
                    paypal_error = {
                        key: body[key]
                        for key in (
                            "name",
                            "message",
                            "debug_id",
                            "details",
                        )
                        if key in body
                    }
            except ValueError:
                pass

        # Always 502: this is an upstream (PayPal) failure, not a missing
        # route on this API. PayPal's own status is included in the detail.
        raise HTTPException(
            status_code=502,
            detail={
                "message": "PayPal order lookup failed.",
                "paypal_status_code": status_code,
                "paypal_error": paypal_error,
            },
        ) from exc

    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="Could not contact PayPal to retrieve the order.",
        ) from exc

    return {
        "order_id": order["id"],
        "status": order["status"],
        "details": order,
    }


# MISSION ENDPOINTS
@app.post("/missions")
def create_mission(mission: MissionCreate):
    mission_id = f"TRC-{uuid4().hex[:8].upper()}"

    mission_data = {
        "mission_id": mission_id,
        **mission.model_dump(mode="json"),
    }

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO missions (
                mission_id,
                objective,
                max_budget,
                currency,
                prohibited_add_ons
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                mission_id,
                mission.objective,
                str(mission.max_budget),
                mission.currency,
                json.dumps(mission.prohibited_add_ons),
            ),
        )

    return {
        "message": "Mission created and saved",
        "mission": mission_data,
    }


@app.post("/missions/{mission_id}/events")
def record_agent_event(
    mission_id: str,
    event: AgentEventCreate,
):
    with get_connection() as connection:
        mission = connection.execute(
            """
            SELECT mission_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission is None:
            raise HTTPException(
                status_code=404,
                detail="Mission not found",
            )

        event_record = {
            "event_id": f"EVT-{uuid4().hex[:8].upper()}",
            "mission_id": mission_id,
            "event_type": event.event_type,
            "description": event.description,
            "amount": (
                str(event.amount)
                if event.amount is not None
                else None
            ),
            "item_name": event.item_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        connection.execute(
            """
            INSERT INTO agent_events (
                event_id,
                mission_id,
                event_type,
                description,
                amount,
                item_name,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_record["event_id"],
                mission_id,
                event_record["event_type"],
                event_record["description"],
                event_record["amount"],
                event_record["item_name"],
                event_record["timestamp"],
            ),
        )

    return {
        "message": "Agent event recorded and saved",
        "event": event_record,
    }


@app.get("/missions/{mission_id}/analyze")
def analyze_mission(mission_id: str):
    with get_connection() as connection:
        mission_row = connection.execute(
            """
            SELECT *
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission_row is None:
            raise HTTPException(
                status_code=404,
                detail="Mission not found",
            )

        event_rows = connection.execute(
            """
            SELECT *
            FROM agent_events
            WHERE mission_id = ?
            ORDER BY timestamp, rowid
            """,
            (mission_id,),
        ).fetchall()

    mission = dict(mission_row)
    events = [dict(row) for row in event_rows]

    prohibited_terms = json.loads(
        mission.get("prohibited_add_ons") or "[]"
    )

    budget = Decimal(str(mission["max_budget"]))
    total = Decimal("0.00")
    violations = []

    for event in events:
        event_type = event["event_type"]
        amount = Decimal(str(event["amount"] or "0"))
        description = event.get("description") or ""
        item_name = event.get("item_name") or description or event["event_id"]
        if event_type in ("product_selected", "add_on_added"):
            total += amount

        if (
            event_type == "add_on_added"
            and _matches_prohibited(
                f"{item_name} {description}",
                prohibited_terms,
            )
        ):
            violations.append({
                "type": "prohibited_add_on",
                "item": item_name or description,
                "amount": str(amount),
                "evidence": event.get("description") or "",
                "event_id": event["event_id"],
            })

    if total > budget:
        violations.append({
            "type": "budget_exceeded",
            "budget": str(budget),
            "observed_total": str(total),
            "excess": str(total - budget),
        })

    deterministic_result = {
        "mission_id": mission_id,
        "analysis": (
            "drift_detected"
            if violations
            else "no_drift_detected"
        ),
        "authorized_budget": str(budget),
        "observed_total": str(total),
        "violations": violations,
        "events_analyzed": len(events),
    }

    ai_explanation = analyze_with_gemini(
        mission,
        events,
        deterministic_result,
    )

    return {
        **deterministic_result,
        "ai_explanation": ai_explanation,
    }

@app.get("/missions/{mission_id}/agent-evidence")
def get_agent_evidence(mission_id: str):
    with get_connection() as connection:
        mission_row = connection.execute(
            """
            SELECT mission_id, objective, max_budget, currency,
                   prohibited_add_ons, paypal_order_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission_row is None:
            raise HTTPException(
                status_code=404,
                detail="Mission not found",
            )

        mission = dict(mission_row)

        event_rows = connection.execute(
            """
            SELECT event_id, event_type, description, amount,
                   item_name, timestamp
            FROM agent_events
            WHERE mission_id = ?
            ORDER BY timestamp, rowid
            """,
            (mission_id,),
                ).fetchall()

        review_rows = connection.execute(
            """
            SELECT review_id, incident_id, decision, reason,
                   reviewer, created_at
            FROM incident_reviews
            WHERE mission_id = ?
            ORDER BY created_at, rowid
            """,
            (mission_id,),
        ).fetchall()

    events = [dict(row) for row in event_rows]
    human_reviews = [dict(row) for row in review_rows]
    budget = Decimal(str(mission["max_budget"]))
    prohibited = json.loads(
        mission["prohibited_add_ons"] or "[]"
    )

    total = Decimal("0.00")
    violations = []

    for event in events:
        amount = Decimal(str(event["amount"] or "0"))

        if event["event_type"] in (
            "product_selected",
            "add_on_added",
        ):
            total += amount

        item_name = event.get("item_name") or event["description"]

        if (
            event["event_type"] == "add_on_added"
            and _matches_prohibited(
                f"{item_name} {event['description'] or ''}",
                prohibited,
            )
        ):
            violations.append({
                "type": "prohibited_add_on",
                "event_id": event["event_id"],
                "item": item_name,
                "amount": str(amount),
                "evidence": event["description"],
            })

    if total > budget:
        violations.append({
            "type": "budget_exceeded",
            "authorized_budget": str(budget),
            "observed_total": str(total),
            "excess": str(total - budget),
        })

    return {
        "mission_id": mission_id,
        "incident_id": f"INC-{mission_id}",
        "objective": mission["objective"],
        "authorized_budget": str(budget),
        "currency": mission["currency"],
        "observed_total": str(total),
        "paypal_order_linked": bool(mission["paypal_order_id"]),
        "events": events,
        "violations": violations,
        "human_reviews": human_reviews,
        "analysis": (
            "drift_detected" if violations
            else "no_drift_detected"
        ),
        "payment_action_executed": False,
    }


# PAYPAL ORDER LINKING AND EVIDENCE

@app.post("/missions/{mission_id}/link-paypal-order")
def link_paypal_order(
    mission_id: str,
    order_id: str,
):
    with get_connection() as connection:
        mission = connection.execute(
            """
            SELECT mission_id, paypal_order_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

    if mission is None:
        raise HTTPException(
            status_code=404,
            detail="Mission not found",
        )

    try:
        order = get_order(order_id)

    except requests.HTTPError as exc:
        response = exc.response
        status_code = (
            response.status_code
            if response is not None
            else None
        )

        if status_code == 404:
            raise HTTPException(
                status_code=404,
                detail="PayPal order not found",
            ) from exc

        raise HTTPException(
            status_code=502,
            detail={
                "message": "Could not verify the PayPal order",
                "paypal_status_code": status_code,
            },
        ) from exc

    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail="Could not contact PayPal to verify the order",
        ) from exc

    purchase_units = order.get("purchase_units", [])

    matching_mission = any(
        unit.get("custom_id") == mission_id
        for unit in purchase_units
    )

    if not matching_mission:
        raise HTTPException(
            status_code=400,
            detail=(
                "PayPal order does not match this TRACE mission"
            ),
        )

    with get_connection() as connection:
        existing = connection.execute(
            """
            SELECT paypal_order_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if existing["paypal_order_id"] not in (None, order_id):
            raise HTTPException(
                status_code=409,
                detail=(
                    "This mission already has a different PayPal order"
                ),
            )

        connection.execute(
            """
            UPDATE missions
            SET paypal_order_id = ?
            WHERE mission_id = ?
            """,
            (order_id, mission_id),
        )

    return {
        "message": "PayPal order verified and linked",
        "mission_id": mission_id,
        "order_id": order_id,
        "paypal_status": order.get("status"),
    }

# TRACE INCIDENT REPORT



# HUMAN REVIEW ENDPOINTS

@app.post("/missions/{mission_id}/mission-review")
def review_mission(
    mission_id: str,
    review: IncidentReviewCreate,
):
    if review.decision == "approve_capture":
        raise HTTPException(
            status_code=400,
            detail=(
                "Capture approval requires a linked PayPal order. "
                "Use the order-specific review endpoint."
            ),
        )

    with get_connection() as connection:
        mission = connection.execute(
            """
            SELECT mission_id, paypal_order_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission is None:
            raise HTTPException(
                status_code=404,
                detail="Mission not found",
            )

        review_id = f"REV-{uuid4().hex[:8].upper()}"
        incident_id = f"INC-{mission_id}"
        created_at = datetime.now(timezone.utc).isoformat()

        connection.execute(
            """
            INSERT INTO incident_reviews (
                review_id,
                incident_id,
                mission_id,
                decision,
                reason,
                reviewer,
                created_at,
                paypal_order_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review_id,
                incident_id,
                mission_id,
                review.decision,
                review.reason,
                review.reviewer,
                created_at,
                mission["paypal_order_id"],
            ),
        )

    return {
        "message": "Mission-level human review recorded",
        "review_id": review_id,
        "incident_id": incident_id,
        "mission_id": mission_id,
        "paypal_order_id": mission["paypal_order_id"],
        "decision": review.decision,
        "reason": review.reason,
        "reviewer": review.reviewer,
        "created_at": created_at,
        "payment_action_executed": False,
    }




@app.post("/missions/{mission_id}/review")
def review_incident(
    mission_id: str,
    review: IncidentReviewCreate,
):
    with get_connection() as connection:
        mission = connection.execute(
            """
            SELECT mission_id, paypal_order_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission is None:
            raise HTTPException(
                status_code=404,
                detail="Mission not found",
            )

        if not mission["paypal_order_id"]:
            raise HTTPException(
                status_code=409,
                detail="Mission has no linked PayPal order",
            )

        review_id = f"REV-{uuid4().hex[:8].upper()}"
        incident_id = f"INC-{mission_id}"
        created_at = datetime.now(timezone.utc).isoformat()

        connection.execute(
            """
            INSERT INTO incident_reviews (
                review_id,
                incident_id,
                mission_id,
                decision,
                reason,
                reviewer,
                created_at,
                paypal_order_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review_id,
                incident_id,
                mission_id,
                review.decision,
                review.reason,
                review.reviewer,
                created_at,
                mission["paypal_order_id"],
            ),
        )

    return {
        "message": "Human review recorded",
        "review_id": review_id,
        "incident_id": incident_id,
        "mission_id": mission_id,
        "paypal_order_id": mission["paypal_order_id"],
        "decision": review.decision,
        "reason": review.reason,
        "reviewer": review.reviewer,
        "created_at": created_at,
        "payment_action_executed": False,
        "capture_readiness": _assess_capture_readiness(
            mission["paypal_order_id"]
        ),
    }

@app.get("/missions/{mission_id}/reviews")
def get_incident_reviews(mission_id: str):
    with get_connection() as connection:
        mission = connection.execute(
            """
            SELECT mission_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission is None:
            raise HTTPException(
                status_code=404,
                detail="Mission not found",
            )

        reviews = connection.execute(
            """
            SELECT review_id, incident_id, decision,
                   reason, reviewer, created_at
            FROM incident_reviews
            WHERE mission_id = ?
            ORDER BY created_at DESC, rowid DESC
            """,
            (mission_id,),
        ).fetchall()

    return {
        "mission_id": mission_id,
        "reviews": [dict(review) for review in reviews],
        "review_count": len(reviews),
    }
@app.get("/missions/{mission_id}/incident-report")
def get_incident_report(mission_id: str):
    # 1. Load the mission and its current order-specific records.
    with get_connection() as connection:
        mission_row = connection.execute(
            """
            SELECT *
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission_row is None:
            raise HTTPException(
                status_code=404,
                detail="Mission not found",
            )

        mission = dict(mission_row)
        order_id = mission["paypal_order_id"]

        if not order_id:
            raise HTTPException(
                status_code=404,
                detail="No PayPal order linked to this mission",
            )

        event_rows = connection.execute(
            """
            SELECT event_id, event_type, description,
                   amount, item_name, timestamp
            FROM agent_events
            WHERE mission_id = ?
            ORDER BY timestamp, rowid
            """,
            (mission_id,),
        ).fetchall()

        review_row = connection.execute(
            """
            SELECT review_id, incident_id, decision, reason,
                   reviewer, created_at, paypal_order_id
            FROM incident_reviews
            WHERE mission_id = ?
              AND paypal_order_id = ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
            """,
            (mission_id, order_id),
        ).fetchone()

        resolution_rows = connection.execute(
            """
            SELECT resolution_id, event_id, resolution_type,
                   reason, reviewer, evidence_json, created_at
            FROM incident_resolutions
            WHERE mission_id = ?
              AND paypal_order_id = ?
            ORDER BY created_at, rowid
            """,
            (mission_id, order_id),
        ).fetchall()

    events = [dict(row) for row in event_rows]
    latest_review = dict(review_row) if review_row else None
    resolutions = [dict(row) for row in resolution_rows]

    prohibited_add_ons = json.loads(
        mission["prohibited_add_ons"] or "[]"
    )
    budget = Decimal(str(mission["max_budget"]))

    # 2. Obtain the current order's validated remediation status.
    #    Only resolutions validated by the assessment can affect
    #    the effective policy total.
    capture_readiness = _assess_capture_readiness(order_id)

    resolved_event_ids = set(
        capture_readiness.get("resolved_event_ids", [])
    )

    # 3. Calculate the historical recorded total.
    #    Never subtract resolved events from this audit total.
    event_total = sum(
        (
            Decimal(str(event["amount"] or "0"))
            for event in events
            if event["event_type"] in (
                "product_selected",
                "add_on_added",
            )
        ),
        Decimal("0.00"),
    )

    # 4. Calculate the effective total for the current order.
    effective_event_total = sum(
        (
            Decimal(str(event["amount"] or "0"))
            for event in events
            if event["event_type"] in (
                "product_selected",
                "add_on_added",
            )
            and event["event_id"] not in resolved_event_ids
        ),
        Decimal("0.00"),
    )

    # 5. Preserve historical violations for the audit trail.
    #    Budget violations use event_total, NOT effective_event_total.
    violations = []

    if event_total > budget:
        violations.append({
            "type": "budget_exceeded",
            "authorized_budget": str(budget),
            "recorded_event_total": str(event_total),
            "excess_amount": str(event_total - budget),
        })

    for event in events:
        if event["event_type"] == "add_on_added":
            description = event.get("description") or ""
            item_name = event.get("item_name") or description or event["event_id"]

            if _matches_prohibited(
                f"{item_name} {description}",
                prohibited_add_ons,
            ):
                violations.append({
                    "type": "prohibited_add_on",
                    "item": item_name,
                    "amount": str(event["amount"] or "0"),
                    "event_id": event["event_id"],
                    "resolution_status": (
                        "resolved_for_current_order"
                        if event["event_id"] in resolved_event_ids
                        else "unresolved"
                    ),
                })

    # 6. Retrieve live PayPal evidence.
    paypal_evidence_available = True
    paypal_evidence_error = None
    paypal_status_code = None

    try:
        order = get_order(order_id)

    except requests.RequestException as exc:
        paypal_evidence_available = False

        response = (
            exc.response
            if isinstance(exc, requests.HTTPError)
            else None
        )

        paypal_status_code = (
            response.status_code
            if response is not None
            else None
        )

        if paypal_status_code == 404:
            paypal_evidence_error = (
                "PayPal returned 404 RESOURCE_NOT_FOUND "
                "for the linked order."
            )
        elif paypal_status_code is not None:
            paypal_evidence_error = (
                f"PayPal order lookup failed with HTTP "
                f"{paypal_status_code}."
            )
        else:
            paypal_evidence_error = (
                "PayPal could not be reached to verify the linked order."
            )

        order = {
            "id": order_id,
            "status": "UNAVAILABLE",
            "intent": None,
            "purchase_units": [],
        }

    purchase_units = order.get("purchase_units", [])
    paypal_status = order.get("status", "UNKNOWN")

    paypal_amounts = [
        {
            "currency": (unit.get("amount") or {}).get(
                "currency_code"
            ),
            "amount": (unit.get("amount") or {}).get("value"),
            "description": unit.get("description"),
            "custom_id": unit.get("custom_id"),
        }
        for unit in purchase_units
    ]

    paypal_total = sum(
        (
            Decimal(
                str((unit.get("amount") or {}).get("value", "0"))
            )
            for unit in purchase_units
        ),
        Decimal("0.00"),
    )

    plan_confirmed_in_order = any(
        "protection" in str(
            unit.get("description", "")
        ).lower()
        or any(
            "protection" in str(item.get("name", "")).lower()
            for item in (unit.get("items") or [])
            if isinstance(item, dict)
        )
        for unit in purchase_units
    )

    # 7. Distinguish historical violations from current policy status.
    unresolved_prohibited_events = [
        {
            "event_id": event["event_id"],
            "item_name": event["item_name"],
            "amount": str(event["amount"] or "0"),
        }
        for event in events
        if (
            event["event_type"] == "add_on_added"
            and _matches_prohibited(
    f"{event.get('item_name') or ''} "
    f"{event.get('description') or ''}",
    prohibited_add_ons,
)
            and event["event_id"] not in resolved_event_ids
        )
    ]

    effective_budget_excess = max(
        effective_event_total - budget,
        Decimal("0.00"),
    )

    current_policy_passes = (
        effective_budget_excess == Decimal("0.00")
        and not unresolved_prohibited_events
    )

    # 8. Recommend an action based on the current order state
    #    and the review associated with this exact order.
    if not paypal_evidence_available:
        recommended_action = {
            "action": "verify_payment_status",
            "reason": (
                "The current PayPal order could not be verified. "
                "Keep the order on hold until its status is confirmed."
            ),
            "requires_human_approval": True,
            "payment_action_executed": False,
        }

    elif (
        latest_review
        and latest_review["decision"] == "approve_pause"
    ):
        recommended_action = {
            "action": "keep_order_on_hold",
            "reason": (
                "The latest human review explicitly places this order "
                "on hold. Capture remains blocked pending the required "
                "review and PayPal buyer approval."
            ),
            "requires_human_approval": True,
            "payment_action_executed": False,
        }

    elif violations and paypal_status == "COMPLETED":
        recommended_action = {
            "action": "review_captured_payment",
            "reason": (
                "Historical policy violations were detected. Inspect "
                "the completed PayPal transaction before deciding "
                "whether further action is necessary."
            ),
            "requires_human_approval": True,
            "payment_action_executed": False,
        }

    elif violations:
        recommended_action = {
            "action": "pause_and_request_human_review",
            "reason": (
                "Historical agent actions violated mission constraints. "
                "Review the recorded violations and current remediation "
                "before allowing a payment action."
            ),
            "requires_human_approval": True,
            "payment_action_executed": False,
        }

    elif paypal_status in ("CREATED", "APPROVED"):
        recommended_action = {
            "action": "await_buyer_approval",
            "reason": (
                "No historical policy violations were detected, but "
                "the current order has not been captured."
            ),
            "requires_human_approval": True,
            "payment_action_executed": False,
        }

    else:
        recommended_action = {
            "action": "no_resolution_required",
            "reason": "No historical mission violations were detected.",
            "requires_human_approval": False,
            "payment_action_executed": False,
        }

    # 9. Build an explanation that distinguishes historical amounts
    #    from the amount relevant to the current order.
    explanation_parts = []

    if violations:
        explanation_parts.append(
            "TRACE detected historical policy drift in the "
            "agent's recorded actions."
        )

        for violation in violations:
            if violation["type"] == "budget_exceeded":
                explanation_parts.append(
                    f"The historical recorded event total was {event_total:.2f} "
                    f"{mission['currency']}, exceeding the authorized budget "
                    f"of {budget:.2f} {mission['currency']} by "
                    f"{event_total - budget:.2f} {mission['currency']}."
                )
            elif violation["type"] == "prohibited_add_on":
                explanation_parts.append(
                    "The agent event log records a prohibited add-on: "
                    f"{violation['item']} "
                    f"({violation['amount']} {mission['currency']})."
                )

    else:
        explanation_parts.append(
            "TRACE did not detect historical violations in "
            "the recorded agent actions."
        )

    explanation_parts.append(
        f"The effective policy total for the current order is "
        f"{effective_event_total:.2f} {mission['currency']}, "
        f"against an authorized budget of {budget:.2f} "
        f"{mission['currency']}."
    )

    if paypal_evidence_available:
        explanation_parts.append(
            f"The linked PayPal order is currently {paypal_status} "
            f"for {paypal_total:.2f} {mission['currency']}."
        )

        if plan_confirmed_in_order:
            explanation_parts.append(
                "PayPal order evidence references a protection plan; "
                "inspect the transaction details before concluding "
                "that the plan was charged."
            )
        else:
            explanation_parts.append(
                "The available PayPal evidence does not confirm that "
                "the prohibited add-on was purchased or charged."
            )
    else:
        explanation_parts.append(
            "PayPal order details are unavailable, so the current "
            "financial outcome cannot be verified."
        )

    if resolved_event_ids:
        explanation_parts.append(
            "TRACE has validated remediation for the applicable "
            "event or events on this order. The original agent "
            "events and historical violations remain preserved."
        )

    explanation = " ".join(explanation_parts)

    # 10. Prepare readable resolution records, retaining their evidence.
    remediation_records = []

    for resolution in resolutions:
        try:
            evidence = json.loads(
                resolution["evidence_json"] or "{}"
            )
        except (ValueError, TypeError):
            evidence = None

        remediation_records.append({
            "resolution_id": resolution["resolution_id"],
            "event_id": resolution["event_id"],
            "resolution_type": resolution["resolution_type"],
            "reason": resolution["reason"],
            "reviewer": resolution["reviewer"],
            "created_at": resolution["created_at"],
            "validated_for_current_order": (
                resolution["event_id"] in resolved_event_ids
            ),
            "evidence": evidence,
        })

    # 11. Return historical evidence and current state separately.
    return {
        "explanation": explanation,
        "incident_id": f"INC-{mission_id}",

        "mission": {
            "mission_id": mission_id,
            "objective": mission["objective"],
            "authorized_budget": str(budget),
            "currency": mission["currency"],
            "prohibited_add_ons": prohibited_add_ons,
        },

        "agent_evidence": {
            "events": events,
            "recorded_event_total": str(event_total),
        },

        "paypal_evidence": {
            "available": paypal_evidence_available,
            "error": paypal_evidence_error,
            "http_status_code": paypal_status_code,
            "order_id": order.get("id"),
            "status": paypal_status,
            "intent": order.get("intent"),
            "purchase_units": paypal_amounts,
        },

        # These are historical violations. They are not deleted
        # when remediation is recorded for the current order.
        "violations": violations,

        "remediation": {
            "records": remediation_records,
            "resolved_event_ids": sorted(resolved_event_ids),
            "effective_policy_total": str(effective_event_total),
            "effective_budget_excess": str(effective_budget_excess),
            "unresolved_prohibited_events": (
                unresolved_prohibited_events
            ),
            "current_policy_passes": current_policy_passes,
        },

        "human_review": latest_review,

        "capture_readiness": capture_readiness,

        "assessment": {
            "recommended_action": recommended_action,
            "drift_detected": bool(violations),
            "current_policy_passes": current_policy_passes,
            "paypal_order_confirms_protection_plan": (
                plan_confirmed_in_order
                if paypal_evidence_available
                else None
            ),
            "financial_outcome": (
                "Unverified: PayPal order details are unavailable"
                if not paypal_evidence_available
                else "Order not yet captured"
                if paypal_status in ("CREATED", "APPROVED")
                else "PayPal reports the order as completed; inspect payment details"
                if paypal_status == "COMPLETED"
                else "Check PayPal payment details before concluding"
            ),
        },
    }

# CAPTURE AUTHORIZATION AND CONTROLLED CAPTURE


@app.get("/paypal/capture-authorization/{order_id}")
def check_capture_authorization(order_id: str):
    """Read-only preflight. Never executes capture."""
    result = _assess_capture_readiness(order_id)
    return result

@app.post("/paypal/capture/{order_id}")
def paypal_capture_order(order_id: str):
    # Read-only preflight happens before any payment action.
    assessment = _assess_capture_readiness(order_id)

    if not assessment["capture_allowed"]:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Capture blocked by TRACE preflight checks.",
                "assessment": assessment,
                "payment_action_executed": False,
            },
        )

    try:
        captured_order = capture_order(order_id)
    except requests.HTTPError as exc:
        response = exc.response
        status_code = (
            response.status_code
            if response is not None
            else None
        )

        raise HTTPException(
            status_code=502,
            detail={
                "message": "PayPal did not confirm the capture request.",
                "paypal_status_code": status_code,
                "instruction": (
                    "Check the live PayPal order status before retrying. "
                    "Do not assume capture succeeded or failed."
                ),
            },
        ) from exc

    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "PayPal could not be reached for capture. "
                "Verify the order status before retrying."
            ),
        ) from exc

    return {
        "message": "PayPal capture request completed.",
        "mission_id": assessment["mission_id"],
        "order_id": captured_order.get("id"),
        "status": captured_order.get("status"),
        "review_id": assessment["latest_review_id"],
        "payment_action_executed": True,
        "details": captured_order,
    }




# DEBUG ENDPOINTS

@app.get("/debug/missions")
def debug_missions():
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT mission_id FROM missions ORDER BY rowid"
        ).fetchall()

    return {
        "mission_ids": [row["mission_id"] for row in rows],
        "count": len(rows),
    }


@app.get("/debug/missions/{mission_id}")
def debug_mission(mission_id: str):
    with get_connection() as connection:
        mission = connection.execute(
            """
            SELECT *
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission is None:
            raise HTTPException(
                status_code=404,
                detail="Mission not found",
            )

        events = connection.execute(
            """
            SELECT *
            FROM agent_events
            WHERE mission_id = ?
            ORDER BY timestamp, rowid
            """,
            (mission_id,),
        ).fetchall()

    return {
        "mission": dict(mission),
        "events": [dict(event) for event in events],
    }


@app.get("/debug/protection-match")
def debug_protection_match():
    prohibited_terms = [
        "subscriptions",
        "protection plans",
        "extended warranties",
        "other add-ons",
    ]

    item_name = "Protection Plan"

    return {
        "item_name_normalized": item_name.lower(),
        "prohibited_terms": prohibited_terms,
        "matches": [
            term
            for term in prohibited_terms
            if _matches_prohibited(item_name, [term])
        ],
    }
class IncidentResolutionCreate(BaseModel):
    event_id: str
    reason: str = Field(min_length=10, max_length=1000)
    reviewer: str = Field(min_length=2, max_length=100)

@app.post("/missions/{mission_id}/resolutions")
def resolve_prohibited_add_on(
    mission_id: str,
    resolution: IncidentResolutionCreate,
):
    with get_connection() as connection:
        mission_row = connection.execute(
            """
            SELECT mission_id, max_budget, currency,
                   prohibited_add_ons, paypal_order_id
            FROM missions
            WHERE mission_id = ?
            """,
            (mission_id,),
        ).fetchone()

        if mission_row is None:
            raise HTTPException(404, "Mission not found")

        mission = dict(mission_row)
        order_id = mission["paypal_order_id"]

        if not order_id:
            raise HTTPException(
                409,
                "Resolution blocked: no PayPal order is linked.",
            )

        event_row = connection.execute(
            """
            SELECT event_id, event_type, amount, item_name, description
            FROM agent_events
            WHERE event_id = ? AND mission_id = ?
            """,
            (resolution.event_id, mission_id),
        ).fetchone()

        if event_row is None:
            raise HTTPException(
                404,
                "The specified event does not belong to this mission.",
            )

        event = dict(event_row)

        if event["event_type"] != "add_on_added":
            raise HTTPException(
                409,
                "This resolution applies only to an add-on event.",
            )

        prohibited = json.loads(
            mission["prohibited_add_ons"] or "[]"
        )

        event_text = " ".join([
            str(event["item_name"] or ""),
            str(event["description"] or ""),
        ])

        if not _matches_prohibited(event_text, prohibited):
            raise HTTPException(
                409,
                "The selected event does not match a prohibited add-on.",
            )

        existing = connection.execute(
            """
            SELECT resolution_id
            FROM incident_resolutions
            WHERE mission_id = ?
              AND paypal_order_id = ?
              AND event_id = ?
              AND resolution_type =
                  'prohibited_add_on_removed_before_checkout'
            """,
            (mission_id, order_id, resolution.event_id),
        ).fetchone()

        if existing is not None:
            raise HTTPException(
                409,
                "This event already has a resolution for this order.",
            )

    # Verify live evidence with PayPal before recording remediation.
    try:
        order = get_order(order_id)
    except requests.HTTPError as exc:
        status_code = (
            exc.response.status_code
            if exc.response is not None
            else None
        )
        raise HTTPException(
            status_code=502,
            detail={
                "message": (
                    "Resolution blocked because PayPal evidence "
                    "could not be verified."
                ),
                "paypal_status_code": status_code,
            },
        ) from exc
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        ) from exc

    if order.get("id") != order_id:
        raise HTTPException(
            409,
            "Resolution blocked: PayPal returned a different order.",
        )

    if order.get("status") not in ("CREATED", "APPROVED"):
        raise HTTPException(
            409,
            "Resolution blocked: order is not in a pre-capture state.",
        )

    units = order.get("purchase_units", [])

    if not units or any(
        unit.get("custom_id") != mission_id
        for unit in units
    ):
        raise HTTPException(
            409,
            "Resolution blocked: order evidence does not match the mission.",
        )

    budget = Decimal(str(mission["max_budget"]))

    total = Decimal("0")
    try:
        for unit in units:
            amount_data = unit.get("amount", {})
            if amount_data.get("currency_code") != mission["currency"]:
                raise HTTPException(
                    409,
                    "Resolution blocked: PayPal order currency does not match mission currency.",
                )
            amount = Decimal(str(amount_data.get("value", "")))

            if not amount.is_finite() or amount < 0:
                raise ValueError("Invalid PayPal amount")

            total += amount

            item_text = " ".join([
                str(unit.get("description") or ""),
                " ".join(
                    str(item.get("name") or "")
                    for item in unit.get("items", [])
                    if isinstance(item, dict)
                ),
            ])

            if _matches_prohibited(item_text, prohibited):
                raise HTTPException(
                    409,
                    "Resolution blocked: the prohibited add-on still "
                    "appears in the PayPal order.",
                )

        if total > budget:
            raise HTTPException(
                409,
                "Resolution blocked: PayPal order exceeds the budget.",
            )

    except (InvalidOperation, ValueError) as exc:
        raise HTTPException(
            409,
            "Resolution blocked: PayPal amount could not be validated.",
        ) from exc

    evidence = {
        "order_id": order_id,
        "order_status": order["status"],
        "purchase_units": units,
        "verified_order_total": str(total),
        "currency": mission["currency"],
        "affected_event_id": event["event_id"],
        "affected_item": event["item_name"] or event["description"],
        "human_attestation": resolution.reason,
    }

    resolution_id = f"RSN-{uuid4().hex[:8].upper()}"
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO incident_resolutions (
                resolution_id, incident_id, mission_id,
                paypal_order_id, event_id, resolution_type,
                reason, reviewer, evidence_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resolution_id,
                f"INC-{mission_id}",
                mission_id,
                order_id,
                event["event_id"],
                "prohibited_add_on_removed_before_checkout",
                resolution.reason,
                resolution.reviewer,
                json.dumps(evidence),
                created_at,
            ),
        )

    return {
        "message": (
            "Remediation recorded with PayPal evidence. "
            "Historical agent events were preserved."
        ),
        "resolution_id": resolution_id,
        "mission_id": mission_id,
        "paypal_order_id": order_id,
        "event_id": event["event_id"],
        "resolution_type": (
            "prohibited_add_on_removed_before_checkout"
        ),
        "reviewer": resolution.reviewer,
        "created_at": created_at,
        "payment_action_executed": False,
        "capture_authorized": False,
    }

@app.get("/paypal/connection-check")
def paypal_connection_check():
    try:
        get_access_token()
        return {"connected": True}
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="PayPal authentication check failed."
        )