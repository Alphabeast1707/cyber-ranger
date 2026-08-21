# SETUP — DVWA target for CyberRanger Arena

The arena attacks a local DVWA instance. Bring it up **before** running the
demo. The arena script never sets up DVWA itself — it just assumes it's here.

## 1. Start the container

```bash
docker compose up -d
```

Wait ~10 seconds, then open http://localhost:8080 in a browser.
Log in with the default credentials:

- **Username:** `admin`
- **Password:** `password`

## 2. One-time database setup

On first login DVWA redirects you to the setup page:

1. Go to http://localhost:8080/setup.php
2. Scroll down and click **"Create / Reset Database"**.
3. You'll be bounced back to the login page — log in again as `admin` / `password`.

## 3. Set security level to Low

1. Go to http://localhost:8080/security.php
2. Set **Security Level** to **Low** and click **Submit**.

That's it. Now run the demo:

```bash
uv run python server.py        # live web dashboard at http://localhost:8000  ← the demo
uv run python coevolution.py   # same arms race, headless in the terminal
```

## Tearing down

```bash
docker compose down
```

> If DVWA isn't running, the demo still works — it falls back to
> **MOCK MODE** and simulates plausible responses so nothing hard-fails.
