def f(cursor, user):
    # ruleid: sql-injection-format
    cursor.execute(f"SELECT * FROM t WHERE n='{user}'")
    # ruleid: sql-injection-format
    cursor.execute("SELECT * FROM t WHERE n='%s'" % user)
    # ruleid: sql-injection-format
    cursor.execute("SELECT * FROM t WHERE n='{}'".format(user))
    # ok: sql-injection-format
    cursor.execute("SELECT * FROM t WHERE n=%s", (user,))
    # ok: sql-injection-format
    cursor.execute("SELECT 1")
    # ok: sql-injection-format
    logger.info(f"query for {user}")
