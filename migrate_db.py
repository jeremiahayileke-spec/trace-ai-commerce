from database import initialize_database, get_connection

initialize_database()

with get_connection() as connection:
    columns = connection.execute(
        "PRAGMA table_info(paypal_order_snapshots)"
    ).fetchall()

    print("SNAPSHOT TABLE COLUMNS:")
    for column in columns:
        print(column["name"])