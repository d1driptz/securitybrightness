"""Browser smoke tests for the standalone website preview.

Requires: pip install playwright && python -m playwright install chromium
Run from repository root: python tools/website_smoke.py

These tests do not start or modify the SecurityBrightness Python core.
"""
from pathlib import Path
import os
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
HOME = (ROOT / "website-preview.html").as_uri()
SCANNER = (ROOT / "scanner.html").as_uri()
SCREENSHOTS = ROOT / "website-review-screenshots"


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            if os.environ.get("WEBSITE_CAPTURE_SCREENSHOTS") == "1":
                SCREENSHOTS.mkdir(exist_ok=True)
                for label, url in (("homepage", HOME), ("scanner", SCANNER)):
                    for width in (390, 1440):
                        shot = browser.new_page(viewport={"width": width, "height": 900},
                                                device_scale_factor=1)
                        shot.goto(url)
                        shot.screenshot(path=str(SCREENSHOTS / f"{label}-{width}px.png"),
                                        full_page=True)
                        shot.close()
            for width in (320, 375, 390, 768, 1024, 1440):
                page = browser.new_page(viewport={"width": width, "height": 850})
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(HOME)
                page.get_by_role("heading", name="Your Security. Your Choice.").wait_for()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
                    f"Homepage horizontal overflow at {width}px"
                )
                page.get_by_role("link", name="Open experimental scanner").click()
                page.get_by_role("button", name="Scan file contents").wait_for()
                overflow = page.evaluate("""() => ({
                    viewport: innerWidth,
                    document: document.documentElement.scrollWidth,
                    offenders: [...document.querySelectorAll('body *')]
                        .filter(el => el.getBoundingClientRect().right > innerWidth + 1)
                        .slice(0, 6)
                        .map(el => ({tag: el.tagName, className: String(el.className).slice(0, 80),
                                     right: Math.round(el.getBoundingClientRect().right)}))
                })""")
                assert overflow["document"] <= overflow["viewport"], (
                    f"Scanner horizontal overflow at {width}px: {overflow}"
                )
                assert not errors, f"JavaScript errors at {width}px: {errors}"
                page.close()

            page = browser.new_page()
            page.goto(SCANNER)
            # No file must show a clear error, not a misleading clean result.
            page.get_by_role("button", name="Scan file contents").click()
            page.get_by_role("heading", name="No file selected").wait_for()

            # Use synthetic, deliberately invalid key-like text, never real credentials.
            page.locator("#fileInput").set_input_files({
                "name": "sample.txt",
                "mimeType": "text/plain",
                "buffer": b"-----BEGIN PRIVATE KEY-----\\nFAKE-TEST-DATA\\n",
            })
            page.get_by_role("button", name="Scan file contents").click()
            page.get_by_text("Private-key header pattern matched.", exact=False).first.wait_for()
            assert "Not a safety verdict" in page.locator("#summaryNote").inner_text()

            # A disallowed file type must be rejected without analysis.
            page.locator("#fileInput").set_input_files({
                "name": "sample.exe",
                "mimeType": "application/octet-stream",
                "buffer": b"not an executable",
            })
            page.get_by_role("button", name="Scan file contents").click()
            assert "Not analyzed" in page.locator("#summaryNote").inner_text()

            # Oversized input must be rejected before parsing.
            page.locator("#fileInput").set_input_files({
                "name": "oversized.txt",
                "mimeType": "text/plain",
                "buffer": b"x" * (1024 * 1024 + 1),
            })
            page.get_by_role("button", name="Scan file contents").click()
            assert "Not analyzed" in page.locator("#summaryNote").inner_text()

            # Benign text must not be reported as proof of safety.
            page.locator("#fileInput").set_input_files({
                "name": "benign.txt",
                "mimeType": "text/plain",
                "buffer": b"Just a normal sentence with no credential patterns.",
            })
            page.get_by_role("button", name="Scan file contents").click()
            page.get_by_text("Not a safety verdict", exact=False).first.wait_for()
            assert "High 0" in page.locator("#summary").inner_text()

            # Untrusted filenames should remain text, not executable markup.
            page.locator("#fileInput").set_input_files({
                "name": "<img src=x onerror=alert(1)>.txt",
                "mimeType": "text/plain",
                "buffer": b"Plain text.",
            })
            page.get_by_role("button", name="Scan file contents").click()
            page.get_by_text("Not a safety verdict", exact=False).first.wait_for()
            assert page.locator("#fileStatus img").count() == 0

            page.get_by_role("link", name="Return to main website").click()
            page.get_by_role("heading", name="Your Security. Your Choice.").wait_for()
            page.close()
            print("Website browser smoke tests passed at 6 viewport widths.")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
