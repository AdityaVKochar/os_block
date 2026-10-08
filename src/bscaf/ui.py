"""Minimal dependency-free web dashboard for demonstrating B-SCAF."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any
import webbrowser

from .canonical import canonical_json
from .service import AuditService


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>B-SCAF Audit Dashboard</title>
  <style>
    :root { color-scheme: light; --ink:#000; --paper:#fff; --soft:#f2f2f2; --line:#000; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--paper); color:var(--ink); font-family:Arial,Helvetica,sans-serif; }
    header { border-bottom:3px solid var(--line); padding:18px 28px; display:flex; justify-content:space-between; align-items:end; }
    header h1 { margin:0; font-size:23px; letter-spacing:.04em; }
    header p { margin:4px 0 0; font-size:13px; }
    main { max-width:1180px; margin:0 auto; padding:24px; }
    .toolbar { display:flex; flex-wrap:wrap; gap:10px; margin-bottom:20px; }
    button { appearance:none; background:#000; color:#fff; border:2px solid #000; padding:10px 16px; font-weight:700; cursor:pointer; }
    button.secondary { background:#fff; color:#000; }
    button:hover, button:focus { outline:3px solid #aaa; outline-offset:2px; }
    .status { border:3px solid #000; padding:18px 20px; display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; }
    .status.invalid { background:#000; color:#fff; }
    .status strong { font-size:20px; }
    .status span { font-family:Consolas,monospace; font-size:12px; }
    .cards { display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin-bottom:24px; }
    .card { border:2px solid #000; padding:17px; min-height:100px; }
    .card .label { font-size:12px; text-transform:uppercase; letter-spacing:.12em; }
    .card .value { font-family:Georgia,serif; font-size:34px; margin-top:12px; }
    .flow { display:grid; grid-template-columns:repeat(7,1fr); align-items:center; gap:7px; margin:14px 0 25px; }
    .flow .node { border:2px solid #000; min-height:70px; display:flex; align-items:center; justify-content:center; text-align:center; padding:8px; font-size:12px; font-weight:700; }
    .flow .arrow { text-align:center; font-size:24px; }
    section { margin-top:25px; }
    h2 { font-size:17px; border-bottom:2px solid #000; padding-bottom:8px; margin-bottom:10px; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { border:1px solid #000; padding:9px; text-align:left; vertical-align:top; }
    th { background:var(--soft); }
    code { font-family:Consolas,monospace; overflow-wrap:anywhere; }
    .empty { border:1px dashed #000; padding:16px; }
    .message { min-height:22px; font-size:13px; margin-bottom:10px; }
    .problems li { margin-bottom:7px; }
    footer { margin-top:30px; border-top:1px solid #000; padding-top:12px; font-size:12px; }
    @media(max-width:800px) { .cards{grid-template-columns:1fr}.flow{grid-template-columns:1fr}.flow .arrow{transform:rotate(90deg)} }
  </style>
</head>
<body>
  <header>
    <div><h1>B-SCAF AUDIT DASHBOARD</h1><p>Lightweight permissioned system-call evidence ledger</p></div>
    <div id="clock"></div>
  </header>
  <main>
    <div class="toolbar">
      <button id="demo">Add demo events</button>
      <button id="flush" class="secondary">Flush batch</button>
      <button id="verify" class="secondary">Verify integrity</button>
    </div>
    <div id="message" class="message" aria-live="polite"></div>
    <div id="status" class="status"><strong>Checking...</strong><span></span></div>
    <div class="cards">
      <div class="card"><div class="label">Events checked</div><div id="event-count" class="value">0</div></div>
      <div class="card"><div class="label">Checkpoint blocks</div><div id="checkpoint-count" class="value">0</div></div>
      <div class="card"><div class="label">Integrity problems</div><div id="problem-count" class="value">0</div></div>
    </div>
    <h2>Evidence flow</h2>
    <div class="flow" aria-label="B-SCAF evidence flow">
      <div class="node">System calls</div><div class="arrow">&rarr;</div>
      <div class="node">Policy + hash chain</div><div class="arrow">&rarr;</div>
      <div class="node">Merkle checkpoint</div><div class="arrow">&rarr;</div>
      <div class="node">Verifier / witness</div>
    </div>
    <section><h2>Detected problems</h2><div id="problems" class="empty">No problems detected.</div></section>
    <section><h2>Recent checkpoint blocks</h2><div id="checkpoints"></div></section>
    <section><h2>Recent system-call events</h2><div id="events"></div></section>
    <footer>Local demonstration interface. Raw event records remain in the selected data directory.</footer>
  </main>
  <script>
    const $ = id => document.getElementById(id);
    const shortHash = value => value ? value.slice(0,12) + "..." + value.slice(-8) : "-";
    const text = value => value === null || value === undefined ? "-" : String(value);
    function table(headers, rows) {
      if (!rows.length) return '<div class="empty">No records available.</div>';
      return '<table><thead><tr>' + headers.map(h=>'<th>'+h+'</th>').join('') + '</tr></thead><tbody>' +
        rows.map(row=>'<tr>'+row.map(cell=>'<td>'+cell+'</td>').join('')+'</tr>').join('') + '</tbody></table>';
    }
    function safe(value) { const d=document.createElement('div'); d.textContent=text(value); return d.innerHTML; }
    async function refresh(message='') {
      const response = await fetch('/api/dashboard', {cache:'no-store'});
      if (!response.ok) throw new Error('Dashboard request failed');
      const data = await response.json();
      const report = data.report;
      $('message').textContent = message;
      $('event-count').textContent = report.events_checked;
      $('checkpoint-count').textContent = report.checkpoints_checked;
      $('problem-count').textContent = report.problems.length;
      $('status').className = report.valid ? 'status' : 'status invalid';
      const verdicts = {pass:'INTEGRITY VALID', partial:'PARTIAL EVIDENCE', fail:'INTEGRITY FAILED'};
      $('status').innerHTML = '<strong>'+(verdicts[report.verdict]||'INTEGRITY FAILED')+'</strong><span>'+safe(data.data_dir)+' · policy '+safe(data.policy_version)+'</span>';
      const findings = report.problems.concat(report.warnings||[]);
      $('problems').innerHTML = findings.length
        ? '<ul class="problems">'+findings.map(p=>'<li><strong>'+safe(p.type)+'</strong>: '+safe(p.detail)+'</li>').join('')+'</ul>'
        : 'No problems detected.';
      $('events').innerHTML = table(['Seq.','Time','System call','PID','UID','Process','Hash'], data.events.map(e=>[
        safe(e.sequence),safe(e.timestamp),'<strong>'+safe(e.syscall)+'</strong>',safe(e.pid),safe(e.uid),safe(e.process),'<code>'+safe(shortHash(e.event_hash))+'</code>'
      ]));
      $('checkpoints').innerHTML = table(['Block','Batch','Events','Merkle root','Previous block','Signer'], data.checkpoints.map(c=>[
        safe(c.block_number),safe(c.batch_id),safe(c.event_count),'<code>'+safe(shortHash(c.merkle_root))+'</code>',
        '<code>'+safe(shortHash(c.previous_block_hash))+'</code>',safe(c.signer_id)
      ]));
    }
    async function action(endpoint, label) {
      $('message').textContent = label + '...';
      const response = await fetch(endpoint, {method:'POST'});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || label + ' failed');
      await refresh(result.message || label + ' complete.');
    }
    $('demo').onclick = () => action('/api/demo','Adding demo events').catch(e=>$('message').textContent=e.message);
    $('flush').onclick = () => action('/api/flush','Flushing pending batch').catch(e=>$('message').textContent=e.message);
    $('verify').onclick = () => refresh('Integrity verification complete.').catch(e=>$('message').textContent=e.message);
    $('clock').textContent = new Date().toLocaleString();
    refresh().catch(e=>$('message').textContent=e.message);
  </script>
</body>
</html>"""


class DashboardController:
    def __init__(self, service: AuditService):
        self.service = service
        self.lock = threading.Lock()
        self.service.initialize()

    def dashboard(self) -> dict[str, Any]:
        with self.lock:
            events = [event.to_dict() for event in self.service.events()][-100:]
            checkpoints = [checkpoint.to_dict() for checkpoint in self.service.checkpoints()][-50:]
            return {
                "data_dir": str(self.service.store.root),
                "policy_version": self.service.policy.version,
                "report": self.service.verify(),
                "events": list(reversed(events)),
                "checkpoints": list(reversed(checkpoints)),
            }

    def add_demo_events(self) -> dict[str, Any]:
        with self.lock:
            base = datetime.now(timezone.utc)
            pid = 2000 + len(list(self.service.events()))
            demo = [
                ("execve", "/usr/bin/python3", {"path": "/usr/bin/python3"}, 0),
                ("openat", "/usr/bin/python3", {"path": "/etc/hosts"}, 3),
                ("connect", "/usr/bin/python3", {"destination": "127.0.0.1:443"}, 0),
            ]
            accepted = 0
            for offset, (syscall, process, arguments, result) in enumerate(demo):
                event = {
                    "timestamp": (base + timedelta(milliseconds=offset)).isoformat().replace("+00:00", "Z"),
                    "host_id": "ui-demo-host",
                    "pid": pid,
                    "ppid": 1,
                    "uid": 1000,
                    "syscall": syscall,
                    "process": process,
                    "arguments": arguments,
                    "return_code": result,
                }
                if self.service.ingest(event) is not None:
                    accepted += 1
            self.service.flush()
            return {"message": f"Added {accepted} demo events and committed the batch."}

    def flush(self) -> dict[str, Any]:
        with self.lock:
            checkpoint = self.service.flush()
            return {"message": "No pending events." if checkpoint is None else f"Committed checkpoint block {checkpoint.block_number}."}


def serve_ui(service: AuditService, host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    controller = DashboardController(service)

    class Handler(BaseHTTPRequestHandler):
        def _headers(self, status: HTTPStatus, content_type: str, length: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
            self.end_headers()

        def _json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = canonical_json(payload)
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/":
                body = DASHBOARD_HTML.encode("utf-8")
                self._headers(HTTPStatus.OK, "text/html; charset=utf-8", len(body))
                self.wfile.write(body)
            elif self.path == "/api/dashboard":
                self._json(controller.dashboard())
            elif self.path == "/health":
                self._json({"status": "ok"})
            else:
                self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            try:
                if self.path == "/api/demo":
                    self._json(controller.add_demo_events())
                elif self.path == "/api/flush":
                    self._json(controller.flush())
                elif self.path == "/api/verify":
                    self._json(controller.dashboard()["report"])
                else:
                    self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except (ValueError, OSError) as error:
                self._json({"error": str(error)}, HTTPStatus.BAD_REQUEST)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"B-SCAF dashboard running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
