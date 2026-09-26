# Bundled fonts — attribution & license

Both typefaces below are licensed under the **SIL Open Font License, Version
1.1** (OFL-1.1), which permits bundling and embedding in documents. They are the
upstream variable-font builds published by the Google Fonts project.

| Family | File | Designer / Foundry | Source |
|---|---|---|---|
| Assistant | `Assistant.ttf` | Ben Nathan | github.com/google/fonts · `ofl/assistant` |
| Heebo | `Heebo.ttf` | Oded Ezer (Hebrew), Christian Robertson (Latin, Roboto) | github.com/google/fonts · `ofl/heebo` |

Each family's full OFL text and copyright notice are carried inside the font
binary's name table. The OFL-1.1 license is available at
<https://openfontlicense.org>.

These two files are embedded at compile time (`include_bytes!`) by
`fingerprint_engine/src/report_studio.rs` and inlined as `data:` URIs into every
generated Report Studio HTML deliverable, so Hebrew renders identically on any
machine without a network fetch. The full variable TTF is embedded as-is (no
instancing or glyph subsetting); the resulting document is fully self-contained.
