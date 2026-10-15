#!/bin/sh
# Regenerates the README screenshots from the test fixture (screenshot_test.go).
# No real home is scanned. macOS with Google Chrome; run from anywhere:
#   docs/screenshots.sh
set -eu
cd "$(dirname "$0")/.."

chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

SCREENSHOT_OUT="$work" go test -count=1 -run '^TestScreenshotFixture$' . >/dev/null

# The fixture home lives in a temp dir; its absolute path must never show.
if grep -qE '/Users/|/private/|/var/folders/' "$work/report.html" "$work/summary.txt"; then
	echo "screenshots: an absolute path leaked into the fixture output" >&2
	exit 1
fi

# shot <out.png> <css height> <html>: one viewport-sized capture at 2x, dark
# scheme (preferredColorScheme=0) so the result does not follow the system.
shot() {
	"$chrome" --headless=new --disable-gpu --hide-scrollbars --user-data-dir="$work/chrome" \
		--window-size=960,"$2" --force-device-scale-factor=2 --blink-settings=preferredColorScheme=0 --screenshot="$1" "file://$3" >/dev/null 2>&1
}

shot "$PWD/docs/report-fix-first.png" 1145 "$work/report.html"

# The second picture starts at "Data reach": drop everything above it.
# (Scrolling does not survive a headless capture; it comes out blank.)
sed 's|</body>|<script>let h = [...document.querySelectorAll("h2")].find(h => h.textContent == "Data reach"); while (h.previousSibling) h.previousSibling.remove()</script></body>|' \
	"$work/report.html" >"$work/lower.html"
shot "$PWD/docs/report-reach-prevention.png" 1290 "$work/lower.html"

echo "Updated docs/report-fix-first.png and docs/report-reach-prevention.png"
echo "Terminal summary for the README:"
cat "$work/summary.txt"
