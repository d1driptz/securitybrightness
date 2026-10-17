# Website redesign — review and release checklist

Branch: `website-redesign-preview`

## Scope
- `website-preview.html`: proposed SecurityBrightness product homepage.
- `scanner.html`: copy of existing experimental browser scanner with navigation back to the preview.
- `index.html`: unchanged on this branch; the current published homepage remains the scanner.

## Completed source review
- Homepage uses the approved headline “Your Security. Your Choice.”
- Homepage describes the Python authorization core and Windows desktop as distinct from the browser scanner.
- Inactive broker work is identified as experimental; no claim of general Windows interception or antivirus protection.
- Scanner link points to `./scanner.html`; scanner back-link points to `./website-preview.html`.
- Both pages include mobile viewport metadata.
- Homepage includes keyboard focus styling and reduced-motion handling.
- Homepage anchor navigation accounts for the sticky header.
- No live product download or unsupported “protected” status is offered.

## Remaining visual, accessibility and release verification
- Visually inspect narrow phone widths (320, 375, 390px) for overlap and clipped controls; automated horizontal-overflow checks passed in Chromium.
- Visually inspect desktop widths (768, 1024, 1440px) for card, navigation and hero readability; automated horizontal-overflow checks passed in Chromium.
- Keyboard navigation order, visible focus and screen reader headings/landmarks.
- Text contrast and zoom at 200%.
- Scanner file-size limit, no-match path and additional match types; no-file, synthetic private-key match and invalid extension paths passed automated Chromium checks.
- Scanner dismissal behaviour and safety of rendered filenames and excerpts.
- Navigation and external documentation links.
- Browser console errors, including mobile Safari.
- GitHub Pages path resolution after final file placement.

## Publishing plan (requires owner approval)
1. Complete browser tests and fix discovered defects.
2. Review final wording and visual appearance with owner.
3. Merge reviewed homepage as `index.html` and keep scanner at `scanner.html` on the GitHub Pages publishing branch.
4. Update the scanner back-link to `./index.html` as part of that publication change.
5. Verify deployed GitHub Pages site and scanner after publication.

Do not merge the entire development branch into the publishing branch merely to release the website; isolate website-only changes. Do not modify authorization core, audit/runtime files or broker code as part of the website release.

## Automated browser smoke-test harness

A website-only Playwright script is available at `tools/website_smoke.py`. On a machine with Python and Chromium Playwright support:

```bash
python -m pip install playwright
python -m playwright install chromium
python tools/website_smoke.py
```

The script opens the preview and scanner directly from the local checkout, checks navigation and horizontal overflow at 320, 375, 390, 768, 1024 and 1440 pixels, and fails on JavaScript page errors. It exercises synthetic browser file uploads for one private-key header match and an invalid extension, but does **not** establish comprehensive scanner correctness, cover Safari, or substitute for visual/accessibility review.

**Status:** GitHub Actions workflow run #3 passed on commit `17b58c7` (as confirmed by the repository owner's GitHub Actions screenshots). The run exercised the smoke-test script version present at that commit, including six Chromium viewport widths, navigation, JavaScript errors, no-file handling, synthetic private-key detection and invalid extension rejection. The later diagnostics-only test-script change was not part of that run. Visual inspection, Safari, deeper scanner checks and owner approval remain pending.
