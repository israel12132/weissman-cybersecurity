# Bundled fonts — attribution & license

All four typefaces below are licensed under the **SIL Open Font License, Version
1.1** (OFL-1.1), which permits bundling and embedding in documents. They are the
upstream variable-font builds published by the Google Fonts project.

| Family | File | Designer / Foundry | Source |
|---|---|---|---|
| Frank Ruhl Libre | `FrankRuhlLibre.ttf` | Yanek Iontef, Michal Sahar (from Frank-Rühl) | github.com/google/fonts · `ofl/frankruhllibre` |
| Assistant | `Assistant.ttf` | Ben Nathan | github.com/google/fonts · `ofl/assistant` |
| Heebo | `Heebo.ttf` | Oded Ezer (Hebrew), Christian Robertson (Latin, Roboto) | github.com/google/fonts · `ofl/heebo` |
| JetBrains Mono | `JetBrainsMono.ttf` | Philipp Nurullin, Konstantin Bulenkov (JetBrains) | github.com/google/fonts · `ofl/jetbrainsmono` |

Each family's full OFL text and copyright notice are carried inside the font
binary's name table. The OFL-1.1 license is available at
<https://openfontlicense.org>.

These fonts are used only to render the briefing PDFs (`scripts/pdf/render.mjs`);
at build time each used weight is instanced and glyph-subset before embedding.
