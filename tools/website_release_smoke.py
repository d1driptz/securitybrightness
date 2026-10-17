"""Smoke-check only the website files in this release branch. No deployment."""
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
HOME = (ROOT / "index.html").as_uri()
SCANNER = (ROOT / "scanner.html").as_uri()

with sync_playwright() as p:
    browser = p.chromium.launch()
    for width in (375, 390, 768, 1440):
        page = browser.new_page(viewport={"width": width, "height": 900})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(HOME)
        assert page.get_by_text("Your Security. Your Choice.").is_visible()
        assert page.locator("html").get_attribute("lang") == "en"
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), f"Homepage overflow at {width}px"
        page.locator('a[href="./scanner.html"]').first.click()
        assert "scanner.html" in page.url
        assert page.locator('input[type="file"]').count() == 1
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), f"Scanner overflow at {width}px"
        page.locator('a[href="./index.html"]').first.click()
        assert "index.html" in page.url
        assert not errors, errors
        page.close()
    browser.close()
print("Website release branch Chromium smoke tests passed.")
