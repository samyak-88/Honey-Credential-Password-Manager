def log_access(conn, user_id, credential_id, device_id, access_type, access_result="success", ip=None):
    """Insert one ACCESS_LOG row. Never receives or stores a password."""
    cur = conn.execute(
        "INSERT INTO ACCESS_LOG (user_id, credential_id, device_id, access_type, access_result, ip_address) "
        "VALUES (?,?,?,?,?,?)",
        (user_id, credential_id, device_id, access_type, access_result, ip))
    return cur.lastrowid
