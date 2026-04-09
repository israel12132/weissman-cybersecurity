# PDF font for Executive Report (binary PDF)

To generate **binary PDF** reports (instead of HTML), place a Liberation Sans font set here.

1. Download [Liberation Fonts](https://github.com/liberationfonts/liberation-fonts/releases) (e.g. `LiberationSans-Regular.ttf`).
2. Put `LiberationSans-Regular.ttf` in this directory (`fingerprint_engine/fonts/`).
3. Run the server from the project root, or set `WEISSMAN_FONT_DIR` to the path of this directory.

If no font is found, the report endpoint falls back to HTML (download as `.html`).
