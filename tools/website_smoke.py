"""Browser smoke tests for the standalone website preview.

Requires: pip install playwright && python -m playwright install chromium
Run from repository root: python tools/website_smoke.py

These tests do not start or modify the SecurityBrightness Python core.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
HOME = (ROOT / "website-preview.html").as_uri()
SCANNER = (ROOT / "scanner.html").as_uri()


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
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
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (
                    f"Scanner horizontal overflow at {width}px"
                )
                assert not errors, f"JavaScript errors at {width}px: {errors}"
                page.close()

            page = browser.new_page()
            page.goto(SCANNER)
            page.get_by_role("button", name="Scan file contents").click()
            assert page.locator("#fileStatus").count() == 1
            page.get_by_role("link", name="Back to homepage").click()
            page.get_by_role("heading", name="Your Security. Your Choice.").wait_for()
            page.close()
            print("Website browser smoke tests passed at 6 viewport widths.")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
