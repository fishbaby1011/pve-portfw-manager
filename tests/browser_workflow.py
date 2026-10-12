"""Run against scripts/preview.py only. Uses mock APIs, never real host commands."""

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SHOTS = ROOT / ".artifacts" / "browser"


def mock_request(page, path, payload=None):
    return page.evaluate("([path, payload]) => apiJson(path, {method: 'POST', body: JSON.stringify(payload || {})})", [path, payload])


def refresh(page):
    page.evaluate("refreshStatus()")


def fit(page):
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "page overflows horizontally"
    overflow = page.evaluate("""() => [...document.querySelectorAll('button, h1, h2, .metric-card')]
      .filter(e => e.getClientRects().length && e.scrollWidth > e.clientWidth + 2)
      .map(e => e.textContent.trim())""")
    assert not overflow, f"text overflows: {overflow}"


def add_rule(page, name, port, target_port=80):
    page.locator('#view-rules [data-action="add-rule"]').click()
    page.locator('[name="name"]').fill(name)
    page.locator('[name="external_port"]').fill(str(port))
    page.locator('[name="dest_ip"]').fill("10.42.0.120")
    page.locator('[name="dest_port"]').fill(str(target_port))
    page.locator('#rule-form button[type="submit"]').click()


def apply_draft(page, suffix=None):
    page.locator('[data-action="review"]').click()
    expect(page.locator('#review-drawer')).to_have_class("drawer open")
    expect(page.locator('#apply-button')).to_be_disabled()
    expect(page.locator('#dry-run-button')).to_be_enabled()
    fit(page)
    if suffix:
        page.locator('#toast').evaluate("e => e.hidden = true")
        page.screenshot(path=str(SHOTS / f"review-{suffix}.png"))
    page.locator('#dry-run-button').click()
    expect(page.locator('#apply-button')).to_be_enabled()
    page.locator('#apply-button').click()
    expect(page.locator('#apply-banner')).to_be_visible()
    expect(page.locator('#confirm-button')).to_be_enabled()


def workflow(browser, url, width, height, suffix):
    context = browser.new_context(viewport={"width": width, "height": height}, permissions=["clipboard-read", "clipboard-write"], accept_downloads=True)
    config = context.request.get(url.rstrip("/") + "/api/config")
    assert config.ok and config.json().get("previewMode") is True, "Refusing a non-mock application"
    page = context.new_page()
    errors, external = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("response", lambda response: print("API failure:", response.url, response.status, response.text()) if response.status >= 400 else None)
    page.on("request", lambda req: external.append(req.url) if not req.url.startswith(url) and not req.url.startswith("blob:") else None)
    page.on("dialog", lambda dialog: dialog.accept())
    page.goto(url)
    expect(page.locator('#preview-banner')).to_be_visible()
    expect(page.locator('#metric-helper')).to_have_text("已連線")
    mock_request(page, "/__mock__/reset")
    refresh(page)
    expect(page.locator('#metric-active')).to_have_text("2")
    fit(page)
    page.screenshot(path=str(SHOTS / f"dashboard-{suffix}.png"), full_page=True)
    page.locator('[data-view="rules"]').click()
    expect(page.locator('#rules-body tr')).to_have_count(2)
    fit(page)
    page.screenshot(path=str(SHOTS / f"rules-{suffix}.png"), full_page=True)

    # Protected ports and accessible editor.
    page.locator('#view-rules [data-action="add-rule"]').click()
    page.locator('[name="name"]').fill("Protected test")
    page.locator('[name="external_port"]').fill("22")
    page.locator('[name="dest_ip"]').fill("10.42.0.120")
    page.locator('[name="dest_port"]').fill("22")
    page.locator('#rule-form button[type="submit"]').click()
    expect(page.locator('#validation-box')).to_contain_text("受保護")
    page.keyboard.press("Escape")
    add_rule(page, "New service", 9090)
    expect(page.locator('#workflow-phase')).to_contain_text("Unsaved")
    page.locator('[data-action="save"]').click()
    expect(page.locator('#workflow-phase')).to_contain_text("等待套用")
    assert page.evaluate("state.status.activeRuleCount") == 2
    apply_draft(page, suffix)
    # Host automatic rollback; advance only the mock clock.
    mock_request(page, "/__mock__/advance", {"seconds": 121})
    refresh(page)
    expect(page.locator('#apply-banner')).to_be_hidden()
    expect(page.locator('#rules-body tr')).to_have_count(2)
    expect(page.locator('#workflow-phase')).to_contain_text("Rolled Back")

    add_rule(page, "Confirmed service", 9091)
    apply_draft(page)
    page.locator('#confirm-button').click()
    expect(page.locator('#apply-banner')).to_be_hidden()
    expect(page.locator('#workflow-phase')).to_contain_text("Confirmed")
    # Edit and confirm must not change the already applied snapshot.
    page.locator('[data-edit="confirmed-service"]').click()
    page.locator('[name="dest_port"]').fill("8080")
    page.locator('#rule-form button[type="submit"]').click()
    apply_draft(page)
    page.locator('#apply-banner [data-action="rollback"]').click()
    expect(page.locator('#apply-banner')).to_be_hidden()
    assert page.evaluate("state.rules.find(r => r.id === 'confirmed-service').dest_port") == 80

    page.locator('[data-duplicate="web"]').click()
    expect(page.locator('#rules-body tr')).to_have_count(4)
    page.locator('#filter-keyword').fill("Copy")
    expect(page.locator('#rules-body tr')).to_have_count(1)
    page.locator('[data-action="clear-filters"]').click()
    page.locator('[data-toggle="web-copy"]').click()
    page.locator('#filter-status').select_option("disabled")
    expect(page.locator('#rules-body tr')).to_have_count(1)
    page.locator('#filter-proto').select_option("udp")
    expect(page.locator('#rules-body')).to_contain_text("沒有符合")
    page.locator('[data-action="clear-filters"]').click()
    page.locator('[data-delete="web-copy"]').click()
    expect(page.locator('#rules-body tr')).to_have_count(3)

    page.locator('#rules-menu summary').click()
    page.locator('[data-action="copy-rules-json"]').click()
    expect(page.locator('#toast')).to_have_text("rules.json copied")
    copied = json.loads(page.evaluate("navigator.clipboard.readText()"))
    assert len(copied) == 3
    page.locator('#rules-menu summary').click()
    page.locator('#rules-menu [data-action="copy-apply-plan"]').click()
    copied_plan = page.evaluate("navigator.clipboard.readText()")
    assert "validate rules" in copied_plan and "Check protocol" in copied_plan and "120 seconds" in copied_plan
    page.evaluate("() => { navigator.clipboard.writeText = () => Promise.reject(new Error('denied')); }")
    page.locator('#rules-menu summary').click()
    page.locator('[data-action="copy-rules-json"]').click()
    expect(page.locator('#toast')).to_contain_text("複製失敗")

    page.locator('#rules-menu summary').click()
    with page.expect_download() as download:
        page.locator('[data-action="export-json"]').click()
    exported = json.loads(Path(download.value.path()).read_text())
    assert len(exported) == 3
    page.locator('#rules-menu summary').click()
    page.locator('[data-action="import-json"]').click()
    page.locator('#import-json').fill('{"wrong": []}')
    page.locator('#import-form button[type="submit"]').click()
    expect(page.locator('#import-validation')).to_contain_text("現有規則未被覆蓋")
    assert len(page.evaluate("state.rules")) == 3
    invalid = [dict(item) for item in exported]
    invalid[0]["enabled"] = None
    page.locator('#import-json').fill(json.dumps(invalid))
    page.locator('#import-form button[type="submit"]').click()
    expect(page.locator('#import-validation')).to_contain_text("boolean")
    assert len(page.evaluate("state.rules")) == 3
    exported.append({"id": "imported", "name": "Imported UDP", "enabled": True, "proto": "udp", "external_port": 19132, "dest_ip": "10.42.0.120", "dest_port": 19132, "note": ""})
    page.locator('#import-json').fill(json.dumps({"rules": exported}))
    page.locator('#import-form button[type="submit"]').click()
    expect(page.locator('#rules-body tr')).to_have_count(4)
    expect(page.locator('#workflow-phase')).to_contain_text("Unsaved")
    page.locator('[data-action="save"]').click()
    expect(page.locator('[data-action="save"]')).to_be_disabled()
    page.locator('[data-view="nft"]').click()
    expect(page.locator('#nft-safety-checks .safety-check')).to_have_count(5)
    expect(page.locator('#nft-code')).to_contain_text("dport 19132")
    assert "hook output" not in page.locator('#nft-code').inner_text()
    fit(page)
    page.locator('#toast').evaluate("e => e.hidden = true")
    page.screenshot(path=str(SHOTS / f"nft-{suffix}.png"), full_page=True)

    page.locator('[data-view="diagnostics"]').click()
    expect(page.locator('#diagnostic-list')).to_contain_text("Internet → VM/CT")
    expect(page.locator('#diagnostic-list')).to_contain_text("未測試")
    page.locator('#diagnostic-list details summary').first.click()
    expect(page.locator('#diagnostic-list details').first).to_have_js_property("open", True)
    fit(page)
    page.locator('#toast').evaluate("e => e.hidden = true")
    page.screenshot(path=str(SHOTS / f"diagnostics-{suffix}.png"), full_page=True)
    page.locator('#theme-toggle').click()
    expect(page.locator('html')).to_have_attribute("data-theme", "light")
    page.locator('[data-view="dashboard"]').click()
    page.screenshot(path=str(SHOTS / f"dashboard-light-{suffix}.png"), full_page=True)
    fit(page)
    mock_request(page, "/__mock__/offline", {"offline": True})
    refresh(page)
    expect(page.locator('#metric-active')).to_have_text("—")
    expect(page.locator('#metric-helper')).to_have_text("未驗證")
    mock_request(page, "/__mock__/offline", {"offline": False})
    refresh(page)
    expect(page.locator('#metric-helper')).to_have_text("已連線")
    page.locator('[data-view="rules"]').click()
    page.locator('#rules-menu summary').click()
    page.locator('[data-action="disable-all"]').click()
    assert all(not item["enabled"] for item in page.evaluate("state.rules"))
    expect(page.locator('#workflow-phase')).to_contain_text("Unsaved")
    assert page.evaluate("state.status.activeRuleCount") == 3
    assert not errors, errors
    assert not external, external
    assert page.locator('svg').count() > 10
    context.close()
    return {"viewport": f"{width}x{height}", "workflow": "passed", "externalRequests": 0, "javascriptErrors": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8089")
    parser.add_argument("--output-dir", type=Path, default=SHOTS, help="Private, ignored screenshot output directory")
    args = parser.parse_args()
    parsed = urlparse(args.url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("Browser tests require a local HTTP mock preview")
    SHOTS = args.output_dir.resolve()
    SHOTS.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        results = [workflow(browser, args.url, 1440, 960, "desktop"), workflow(browser, args.url, 390, 844, "mobile")]
        page = browser.new_page(viewport={"width": 320, "height": 740})
        page.goto(args.url)
        expect(page.locator('#metric-helper')).to_have_text("已連線")
        for view in ["dashboard", "rules", "nft", "diagnostics"]:
            page.locator('[data-view="' + view + '"]').click()
            fit(page)
        results.append({"viewport": "320x740", "layout": "passed"})
        browser.close()
    print(json.dumps(results, indent=2))
