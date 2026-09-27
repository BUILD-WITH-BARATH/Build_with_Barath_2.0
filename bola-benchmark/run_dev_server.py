"""Local dev entrypoint for Windows.

`python -m uvicorn app:app` creates its event loop (via asyncio.run()) before
importing app.py, so setting the Windows event-loop policy from inside app.py
is too late to take effect - uvicorn's own Proactor loop already exists by
then. This script sets the policy first, then hands off to uvicorn, so the
loop it creates is already the Selector variant.

Not used in production (Docker/Linux has no Proactor-vs-Selector distinction -
this file only matters for local development on Windows).
"""
import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000)
