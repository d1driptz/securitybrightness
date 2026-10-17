# Website-only publication procedure

Status: preparation only — no publication authorized.

## Intended public layout

- `index.html`: reviewed homepage, derived from `website-preview.html`.
- `scanner.html`: separate experimental browser scanner.
- `docs/PRODUCT_VISION.md`: full product vision, not a substitute for current behaviour.
- `docs/CURRENT_BEHAVIOR.md`: current implemented functionality and limitations.

## Release changes to stage together

1. Copy the reviewed `website-preview.html` content to the **publishing branch** `index.html` (replacing its current scanner-first content).
2. Carry over the reviewed `scanner.html` separately; change only its return link from `./website-preview.html` to `./index.html`.
3. Change the homepage's Product Vision GitHub link from `blob/website-redesign-preview/docs/PRODUCT_VISION.md` to the **actual publishing branch's** `blob/<publishing-branch>/docs/PRODUCT_VISION.md` path. Verify that the document exists there.
4. Check other homepage links, especially `CURRENT_BEHAVIOR.md`, against the published branch and intended documentation.
5. Check the configured GitHub Pages publishing source (branch/folder) **before** staging or merging. Never assume `securitybrightness-core` is the Pages source.
6. Stage only the intended website and documentation changes. Do **not** merge the entire `website-redesign-preview` branch, which may carry unrelated ancestry from the development branch.

## Release verification gate

- Confirm homepage loads at `/` and scanner at `/scanner.html` on a local release candidate.
- Verify both directions of navigation and all external links.
- Repeat the six-width Chromium smoke checks against the release-candidate file names, not only the preview file names.
- Verify scanner file handling and size/extension restrictions remain unchanged.
- Manually inspect mobile Safari, keyboard focus, contrast, and 200% zoom.
- Obtain explicit owner approval **before** publishing.
- After publication, verify the public homepage, scanner, and links directly.

## Scope boundaries

The scanner is a browser-based, limited file-pattern review, not an antivirus or malware verdict. Do not raise the 1 MiB limit or expand supported file types as part of this website-only release. The Python authorization core, audit data, Windows broker experiments and Codex's active branch must not be changed.
