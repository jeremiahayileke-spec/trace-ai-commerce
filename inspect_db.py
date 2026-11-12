from database import get_connection

with get_connection() as connection:
    connection.execute(
        """
        DELETE FROM paypal_order_snapshots
        WHERE snapshot_id = ?
        """,
        ("TEST-e57129b2",)
    )

    remaining = connection.execute(
        """
        SELECT * FROM paypal_order_snapshots
        WHERE snapshot_id = ?
        """,
        ("TEST-e57129b2",)
    ).fetchone()

    print("TEST RECORD:", "STILL EXISTS" if remaining else "REMOVED")