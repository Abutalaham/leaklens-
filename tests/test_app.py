import io
import logging

from .conftest import rnd


def upload(client, name, data):
    return client.post("/api/scan", data={"file": (io.BytesIO(data), name)}, content_type="multipart/form-data")


def test_full_workflow_text(client, fake, caplog):
    caplog.set_level(logging.DEBUG)
    src = f'DB_PASSWORD = "{fake["pw"]}"\nGH = "{fake["gh"]}"\ncontact = "{fake["email"]}"\n'.encode()
    r = upload(client, "app.py", src)
    assert r.status_code == 200
    j = r.get_json()
    body = r.get_data(as_text=True)
    assert fake["pw"] not in body and fake["gh"] not in body and fake["email"] not in body   # masked in API
    assert j["summary"]["high"] >= 2 and j["masked_text"].count("█") > 20
    ids = [f["id"] for f in j["findings"] if f["status"] == "active"]
    rr = client.post("/api/redact", json={"scan_id": j["scan_id"], "finding_ids": ids, "style": "label"})
    assert rr.status_code == 200 and rr.get_json()["verification"]["active"] == 0
    out = client.get(rr.get_json()["downloads"]["sanitised"])
    assert out.status_code == 200 and fake["pw"].encode() not in out.data and b"[REDACTED:" in out.data
    out.close()
    r_html = client.get(rr.get_json()["downloads"]["report_html"])
    assert r_html.status_code == 200
    r_html.close()
    r_json = client.get(rr.get_json()["downloads"]["report_json"])
    rep = r_json.get_json()
    r_json.close()
    assert rep["action"]["redacted_count"] == len(ids)
    assert fake["pw"] not in str(rep)
    assert not any(fake["pw"] in rec.getMessage() or fake["gh"] in rec.getMessage() for rec in caplog.records)
    assert client.delete(f"/api/scan/{j['scan_id']}").get_json()["deleted"]
    assert client.get(f"/api/download/{j['scan_id']}/sanitised").status_code == 404


def test_partial_redaction_only_selected(client, fake):
    src = f'A_PASSWORD = "{fake["pw"]}"\nGH = "{fake["gh"]}"\n'.encode()
    j = upload(client, "x.py", src).get_json()
    gh = next(f["id"] for f in j["findings"] if f["type"] == "GITHUB_TOKEN")
    rr = client.post("/api/redact", json={"scan_id": j["scan_id"], "finding_ids": [gh]}).get_json()
    out = client.get(rr["downloads"]["sanitised"]).data
    assert fake["gh"].encode() not in out and fake["pw"].encode() in out
    assert rr["verification"]["active"] >= 1


def test_rejections(client):
    assert upload(client, "evil.exe", b"MZ").status_code == 400
    assert upload(client, "fake.pdf", b"hello").status_code == 400
    assert client.post("/api/scan").status_code == 400
    assert client.get("/api/download/../../etc/passwd/sanitised").status_code == 404
    assert client.get("/api/original/" + "0" * 32).status_code == 404
    assert client.post("/api/redact", json={"scan_id": "../x"}).status_code == 404


def test_too_large(client, monkeypatch):
    import app as appmod
    monkeypatch.setitem(appmod.app.config, "MAX_CONTENT_LENGTH", 1000)
    r = upload(client, "big.txt", b"a" * 5000)
    assert r.status_code == 413 and "error" in r.get_json()


def test_pdf_and_pages(client, fake):
    from reportlab.pdfgen import canvas
    buf = io.BytesIO(); c = canvas.Canvas(buf)
    c.drawString(50, 700, "page one"); c.showPage(); c.drawString(50, 700, f"key {fake['gh']}"); c.showPage(); c.save()
    j = upload(client, "d.pdf", buf.getvalue()).get_json()
    gh = next(f for f in j["findings"] if f["type"] == "GITHUB_TOKEN")
    assert gh["page"] == 2 and j["kind"] == "pdf"
    rr = client.post("/api/redact", json={"scan_id": j["scan_id"], "finding_ids": [gh["id"]]}).get_json()
    assert rr["verification"]["active"] == 0
    assert client.get(rr["downloads"]["sanitised"]).data.startswith(b"%PDF")


def test_history_status_evaluation(client, fake):
    assert client.get("/api/history").status_code == 401
    assert client.delete("/api/history").status_code == 401
    client.post("/api/auth/register", json={
        "username": "history_user",
        "email": "history_user@example.com",
        "password": "Password123",
    })
    upload(client, "h.txt", f"pw = \"{fake['pw']}\"".encode())
    h = client.get("/api/history").get_json()
    assert h and h[0]["filename"] == "h.txt" and "pw" not in str(h[0].keys())
    assert client.get("/api/status").get_json()["extensions"]
    ev = client.get("/api/evaluation")
    assert ev.status_code in (200, 404)


def test_history_preview_contains_only_masked_finding_data(client, fake):
    client.post("/api/auth/register", json={
        "username": "history_preview_user",
        "email": "history_preview@example.com",
        "password": "Password123",
    })
    scan = upload(client, "masked.py", f"GH_TOKEN = \"{fake['gh']}\"".encode()).get_json()
    detail = client.get(f"/api/user/history/{scan['scan_id']}")
    assert detail.status_code == 200
    payload = detail.get_json()
    assert payload["findings"]
    assert fake["gh"] not in str(payload)
    assert "findings_json" not in payload and "user_id" not in payload


def test_synthetic_sample_files_are_allowlisted(client):
    from pathlib import Path

    samples = {
        "python": "demo_app.py",
        "pdf": "demo_report.pdf",
        "screenshot": "demo_screenshot.jpg",
        "notes": "demo_notes.txt",
    }
    for sample_id, filename in samples.items():
        response = client.get(f"/api/samples/{sample_id}")
        assert response.status_code == 200
        assert response.data == (Path(__file__).parents[1] / "samples" / filename).read_bytes()
        response.close()
    assert client.get("/api/samples/not-a-sample").status_code == 404


def test_index_and_headers(client):
    r = client.get("/")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and b"LeakLens" in r.data
    assert 'id="view-home" class="view"' in html
    assert 'id="view-scan" class="view scan-page" hidden' in html
    assert 'class="ribbon-stage"' in html and "Tracing<br>the" in html
    assert '/static/tokens.css' in html
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


def test_chamber_frontend_routes(client):
    for route in ("/chamber", "/landing"):
        r = client.get(route)
        html = r.get_data(as_text=True)
        assert r.status_code == 200
        assert "The Digital Inspection Chamber" in html
        assert "https://cdnjs.cloudflare.com" in r.headers["Content-Security-Policy"]
