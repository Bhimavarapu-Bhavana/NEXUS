## NEXUS Local UI

Start the local dashboard with:

```powershell
python -m app.ui.server
```

Open `http://127.0.0.1:8765/` in a browser.

The UI is local-only and binds to `127.0.0.1`. It presents bounded, redacted
agent evidence, audit history, security state, workspace/Git summaries, and
backend-created approval records. It is not a shell, Python console, arbitrary
tool runner, or cloud service. Existing authorization, risk, approval,
verification, and audit controls remain enforced by the backend.
