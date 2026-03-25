#!/usr/bin/env bash
set -eu -o pipefail

UI_REPO="$1"
ADMIN_UI_DIST="$2"

clear_dist() {
    mkdir -p "$ADMIN_UI_DIST"
    find "$ADMIN_UI_DIST" -mindepth 1 ! -name .gitkeep -exec rm -rf {} +
}

clear_dist
(cd "$UI_REPO" && vp install && vp build)
cp -R "$UI_REPO/dist/." "$ADMIN_UI_DIST"/
