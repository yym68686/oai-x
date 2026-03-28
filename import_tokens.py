import argparse
import os

from token_store import import_token_files_sync


def main() -> None:
    parser = argparse.ArgumentParser(description="Import token_*.json files into PostgreSQL")
    parser.add_argument(
        "patterns",
        nargs="*",
        default=["token_*.json"],
        help="Glob patterns for token JSON files",
    )
    parser.add_argument("--database-url", help="PostgreSQL connection string")
    args = parser.parse_args()

    if args.database_url:
        os.environ["DATABASE_URL"] = args.database_url

    imported, failed = import_token_files_sync(args.patterns)
    print(f"Imported: {imported}")
    print(f"Failed: {failed}")


if __name__ == "__main__":
    main()
