"""CyberRanger Arena — FastAPI backend + web dashboard server.

Streams the co-evolution arms race (coevolution.py) to the browser via SSE and
serves the built React/shadcn dashboard from web/dist.

Run the demo (single command):
    uv run python server.py            # serves the built UI at http://localhost:8000

Develop the UI with hot reload (two terminals):
    uv run uvicorn server:app          # backend on :8000
    cd web && npm run dev              # Vite on :5173 (proxies /stream to :8000)
"""

import json
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import coevolution

# Seconds between generations so the audience can watch each land. Tweak me.
PACE_SECONDS = 1.0

app = FastAPI(title="CyberRanger Arena")
_DIST = Path(__file__).parent / "web" / "dist"


@app.get("/stream")
def stream():
    """SSE endpoint: run the co-evolution, emit one event per generation.

    Starlette runs this sync generator in a threadpool, so the blocking DVWA
    HTTP calls inside coevolution.run() never stall the event loop.
    """

    def event_source():
        for snapshot in coevolution.run():
            yield f"data: {json.dumps(snapshot)}\n\n"
            if snapshot.get("type") == "generation":
                time.sleep(PACE_SECONDS)
        yield 'data: {"type": "done"}\n\n'

    return StreamingResponse(event_source(), media_type="text/event-stream")


# Serve the built single-page app (assets + client-side entry) if present.
if _DIST.exists():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="app")
else:
    @app.get("/", response_class=HTMLResponse)
    def _needs_build():
        return (
            "<h2 style='font-family:sans-serif'>UI not built yet</h2>"
            "<p>Run <code>cd web && npm install && npm run build</code>, "
            "then restart this server.</p>"
        )


def main():
    import threading
    import webbrowser
    import uvicorn

    url = "http://localhost:8000"
    print(f"\n  CyberRanger Arena  ->  {url}\n")
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


if __name__ == "__main__":
    main()
