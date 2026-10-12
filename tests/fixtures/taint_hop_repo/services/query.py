import sqlite3


def run_query(sql):
    db = sqlite3.connect("orders.db")
    return db.execute(sql).fetchall()
