from database.schema import create_schema, verify_schema
from database.triggers import create_triggers


def init_database():
    """Idempotent: create DB file, 7 tables, trigger; return schema problems (if any)."""
    create_schema()
    create_triggers()
    return verify_schema()
