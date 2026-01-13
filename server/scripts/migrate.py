from __future__ import annotations

from server.avp_server.db import run_migrations

if __name__ == "__main__":
    run_migrations()
    print("migrations applied")
