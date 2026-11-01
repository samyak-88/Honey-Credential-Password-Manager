"""Entry point:  python main.py"""
from database import init_database
from database.connection import get_db_path
from ui.menu import main_menu


def main():
    problems = init_database()
    if problems:
        print("SCHEMA PROBLEMS:")
        for p in problems:
            print(" -", p)
        raise SystemExit(1)
    print(f"Database ready: {get_db_path()}\nSchema verified: 7 tables, all columns/foreign keys match, trigger installed.")
    try:
        main_menu()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye.")


if __name__ == "__main__":
    main()
