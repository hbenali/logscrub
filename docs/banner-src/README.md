# Banner source

`docs/banner.png` (1280x640, also uploaded as the repository's GitHub social preview in Settings -> General) is rendered from
`banner.html` with headless Chrome. The window shows a crop of the real UI, `docs/screenshots/overview.png` (dark theme,
highlighted matches), rendered from `logscrub serve` with headless Chrome at 2x (1180 CSS px wide, a pasted sample log, the
"What was found" tab). To change the crop, edit the `.view img` rule in `banner.html`.

```sh
google-chrome --headless=new --hide-scrollbars --window-size=1280,640 --force-device-scale-factor=1 \
  --virtual-time-budget=9000 --screenshot=docs/banner.png "file://$PWD/docs/banner-src/banner.html"
```

Fonts (Inter and JetBrains Mono) are loaded from Google Fonts while rendering, so rendering needs network access; the
resulting PNG does not.

## Snap Store banner (3:1)

The Snap Store's featured banner must be 3:1, so `docs/banner-store.png` (1440x480) is rendered from `banner-store.html`, the
same design with a more compact layout (no chips, smaller crop of the UI). Same command, different file and size:

```sh
google-chrome --headless=new --hide-scrollbars --window-size=1440,480 --force-device-scale-factor=1 \
  --virtual-time-budget=9000 --screenshot=docs/banner-store.png "file://$PWD/docs/banner-src/banner-store.html"
```
