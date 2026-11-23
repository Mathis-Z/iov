"""Serve only the dashboard, without Celery or Redis:

    python -m dashboard --demo            # bundled sample data
    python -m dashboard --port 8050       # live indexer, from .env

Run from wazuh-integration/src (or with it on PYTHONPATH). Inside the ETSO
container the dashboard is already served by app.py at /dashboard/.
"""
import argparse
import os


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m dashboard", description=__doc__.splitlines()[0])
    parser.add_argument("--demo", action="store_true", help="serve the bundled demo data instead of the indexer")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8050)
    args = parser.parse_args()

    if args.demo:
        # Before config is imported, which reads the environment once.
        os.environ["DASHBOARD_DATA_SOURCE"] = "demo"

    import uvicorn
    from fastapi import FastAPI
    from fastapi.responses import RedirectResponse

    from dashboard.routes import router, static

    app = FastAPI(title="ETSO dashboard")
    app.include_router(router)
    app.mount("/dashboard/static", static, name="dashboard-static")
    app.get("/", include_in_schema=False)(lambda: RedirectResponse(url="/dashboard/"))

    print(f"Dashboard: http://{args.host}:{args.port}/dashboard/")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
