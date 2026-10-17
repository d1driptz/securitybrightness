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

## Still to verify in an actual browser
- At narrow phone widths (320, 375, 390px), no horizontal overflow, overlap or clipped controls.
- At desktop widths (768, 1024, 1440px), cards, navigation and hero remain readable.
- Keyboard navigation order, visible focus and screen reader headings/landmarks.
- Text contrast and zoom at 200%.
- Scanner select-file, no-file, invalid extension, file size, match and no-match paths.
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
