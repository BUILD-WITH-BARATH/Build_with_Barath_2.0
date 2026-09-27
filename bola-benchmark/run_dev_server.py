"""Local dev entrypoint for Windows.

History of this file, for whoever touches it next:

1. Originally set asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())
   before importing uvicorn, to avoid a ConnectionResetError log flood that
   Windows' default ProactorEventLoop produces under real browser preflight/
   retry traffic. That flood is noisy but harmless - it's Starlette's own
   exception logging for a callback firing after the peer already closed the
   connection, not a failure uvicorn or the app needs to react to.

2. That policy-based approach turned out to be silently ineffective on newer
   Python (asyncio.run() no longer reliably honors it) - the flood kept
   happening even with the policy set.

3. So it was switched to asyncio.Runner(loop_factory=asyncio.SelectorEventLoop),
   which does force a real SelectorEventLoop.

4. That did NOT fix the actual problem it was chasing by then: real POST
   requests over actual sockets hanging indefinitely, confirmed directly with
   curl (independent of the browser or CORS) on this same machine. Verified
   the hang is identical under both SelectorEventLoop and plain ProactorEventLoop
   - same symptom either way, so event loop choice was never the cause. Also
   ruled out: the app's own middleware (a POST to /metrics, a path the
   rate-limit middleware skips entirely, hangs too) and the ASGI app logic
   itself (the exact same routes succeed reliably via TestClient's in-process
   ASGI transport - only real sockets are affected). curl's own verbose output
   confirms the request body IS delivered to the OS socket layer; nothing ever
   responds afterward. That combination points to something intercepting POST
   traffic to localhost outside the Python process entirely - most likely
   antivirus/firewall real-time inspection on the machine running this, which
   no code change here can address.

Reverted to plain uvicorn.run() (Windows' default ProactorEventLoop) since
SelectorEventLoop demonstrated no benefit for the problem it was meant to
solve. The original ConnectionResetError log flood this file was chasing is
cosmetic (Starlette logging a callback firing after the peer already closed
the connection) - not worth trading for the deprecation warnings and added
complexity of forcing a different loop.

Not used in production (Docker/Linux doesn't have this Windows-specific
event-loop distinction at all - see the Dockerfile's plain `uvicorn app:app`).
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000)
