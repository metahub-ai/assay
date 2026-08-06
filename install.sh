#!/bin/sh
# Install the `assay` CLI.
#
#   curl -fsSL https://raw.githubusercontent.com/metahub-ai/assay/main/install.sh | sh
#
# No domain, no package registry, no sudo. It downloads a release
# tarball straight from GitHub Releases, checks it against the sha256
# published beside it, and unpacks it into ~/.assay.
#
# That is possible because the tool has ZERO runtime dependencies — the
# whole thing is ~240 KB of self-contained JavaScript. Model adapters speak
# their vendor's HTTP API directly, so behavioral runs need a key and
# nothing else. `e2b` and `sigstore` are optional peers, imported lazily
# and only if you use the E2B sandbox or keyless signing.
#
# Read it first if you like — that is why it is short:
#   curl -fsSL .../install.sh | less

set -eu

REPO="${ASSAY_REPO:-metahub-ai/assay}"
BIN_NAME="assay"
ASSAY_HOME="${ASSAY_HOME:-$HOME/.assay}"
INSTALL_DIR="${ASSAY_BIN_DIR:-$ASSAY_HOME/bin}"
LIB_DIR="$ASSAY_HOME/lib"
VERSION="${ASSAY_VERSION:-latest}"
ADD_PATH=0
MIN_NODE_MAJOR=20

for arg in "$@"; do
  case "$arg" in
    --add-path) ADD_PATH=1 ;;
    --version=*) VERSION="${arg#--version=}" ;;
    --dir=*) INSTALL_DIR="${arg#--dir=}" ;;
    -h | --help)
      cat <<EOF
Install the assay CLI from GitHub Releases.

  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh -s -- --add-path

Options
  --add-path        append the PATH line to your shell profile
  --version=<tag>   install a specific release (default: latest)
  --dir=<path>      install the launcher somewhere other than ~/.assay/bin

Environment
  ASSAY_HOME        base directory (default ~/.assay)
  ASSAY_REPO        owner/repo to install from
  GITHUB_TOKEN      used for the API, if the repo is private or you are
                    rate-limited

Uninstall
  rm -rf ~/.assay
EOF
      exit 0
      ;;
  esac
done

say() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

die() {
  err ""
  err "  install failed: $1"
  [ $# -gt 1 ] && err "" && err "  $2"
  err ""
  exit 1
}

# ── preflight ────────────────────────────────────────────────────────

command -v node >/dev/null 2>&1 || die \
  "Node.js is not installed, and assay is a Node program." \
  "Install Node 20 or newer — https://nodejs.org — then run this again."

NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
[ "$NODE_MAJOR" -ge "$MIN_NODE_MAJOR" ] || die \
  "Node $MIN_NODE_MAJOR or newer is required; found $(node -v)." \
  "Upgrade Node, then run this again."

if command -v curl >/dev/null 2>&1; then
  DL="curl -fsSL"
  DL_OUT="curl -fsSL -o"
elif command -v wget >/dev/null 2>&1; then
  DL="wget -qO-"
  DL_OUT="wget -qO"
else
  die "Neither curl nor wget is available." "Install one of them and run this again."
fi

# A token is optional. It is only needed for a private repo, or if you
# have hit the unauthenticated API rate limit.

api() {
  if [ -n "${GITHUB_TOKEN:-}" ] && [ "${DL%% *}" = "curl" ]; then
    curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$1"
  else
    $DL "$1"
  fi
}

# Download a release asset to $2.
#
# Two different URLs, because GitHub serves release assets two ways. The
# browser URL under github.com/.../releases/download works for a public
# repo and 404s for a private one no matter what token you send. Private
# assets come from the API, by numeric asset id, with an Accept header
# asking for the bytes rather than the JSON describing them.
#
# The token used to be applied to the API call that resolves the tag and
# NOT to the download, so on a private repo the installer reported the
# right release and then failed to fetch it.
asset() {
  name="$1"
  dest="$2"
  if [ -n "${GITHUB_TOKEN:-}" ] && [ "${DL%% *}" = "curl" ]; then
    # Pull the asset id that goes with this filename out of the release
    # JSON already fetched into $META.
    id=$(printf '%s' "$META" |
      tr ',' '\n' |
      grep -B40 "\"name\": *\"$name\"" |
      sed -n 's/.*"id": *\([0-9]*\).*/\1/p' |
      tail -1)
    if [ -n "$id" ]; then
      curl -fsSL -o "$dest" \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/octet-stream" \
        "https://api.github.com/repos/$REPO/releases/assets/$id" && return 0
    fi
  fi
  # Public repo, or no token: the plain download URL.
  $DL_OUT "$dest" "https://github.com/$REPO/releases/download/$TAG/$name"
}

# ── resolve the release ──────────────────────────────────────────────

say ""
say "  Installing $BIN_NAME from github.com/$REPO"

if [ "$VERSION" = "latest" ]; then
  API="https://api.github.com/repos/$REPO/releases/latest"
else
  API="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
fi

META=$(api "$API" 2>/dev/null) || META=""
TAG=$(printf '%s' "$META" | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -1)

if [ -z "$TAG" ]; then
  die "no published release found for $REPO ($VERSION)." \
    "If the repository is private, set GITHUB_TOKEN. To build from source instead:
    git clone https://github.com/$REPO.git && cd assay && npm ci && npm run build && npm link"
fi

ARCHIVE="assay-$TAG.tar.gz"

say "  Release   $TAG"
say ""

# ── download and verify ──────────────────────────────────────────────

TMP=$(mktemp -d)
# Clean up on every exit path, including a failed checksum.
trap 'rm -rf "$TMP"' EXIT INT TERM

if ! asset "$ARCHIVE" "$TMP/assay.tar.gz" 2>/dev/null; then
  die "could not download $ARCHIVE from the $TAG release." \
    "If the repository is private, set GITHUB_TOKEN to a token with repo scope."
fi

# Verified, not assumed. This is a tool that fails other people's
# artifacts for shipping unverifiable dependencies; installing itself
# without checking the hash would be difficult to defend.
if asset "checksums.txt" "$TMP/checksums.txt" 2>/dev/null; then
  EXPECTED=$(grep "assay-$TAG.tar.gz" "$TMP/checksums.txt" 2>/dev/null | awk '{print $1}' | head -1)
  if [ -n "$EXPECTED" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      ACTUAL=$(sha256sum "$TMP/assay.tar.gz" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
      ACTUAL=$(shasum -a 256 "$TMP/assay.tar.gz" | awk '{print $1}')
    else
      ACTUAL=""
    fi
    if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$EXPECTED" ]; then
      die "CHECKSUM MISMATCH — refusing to install." \
        "expected $EXPECTED
    got      $ACTUAL"
    fi
    [ -n "$ACTUAL" ] && say "  Checksum  verified (sha256)"
  fi
else
  say "  Checksum  not published for this release — skipping verification"
fi

# ── install ──────────────────────────────────────────────────────────

# Preserve node_modules across the wipe.
#
# `rm -rf "$LIB_DIR"` is right for the shipped files — a stale dist/ from
# an older release must not survive an upgrade. But `assay setup` installs
# the E2B client into this same directory, and deleting it turned every
# upgrade into a silently broken behavioral tier: doctor reported the
# sandbox configured, because the KEY was still in config.json, while the
# client it needs had just been thrown away.
KEEP=""
if [ -d "$LIB_DIR/node_modules" ]; then
  KEEP="$TMP/node_modules"
  mv "$LIB_DIR/node_modules" "$KEEP"
fi

rm -rf "$LIB_DIR"
mkdir -p "$LIB_DIR" "$INSTALL_DIR"
tar -xzf "$TMP/assay.tar.gz" -C "$LIB_DIR" --strip-components=1 2>/dev/null ||
  tar -xzf "$TMP/assay.tar.gz" -C "$LIB_DIR"

if [ -n "$KEEP" ] && [ -d "$KEEP" ]; then
  mv "$KEEP" "$LIB_DIR/node_modules"
  say "  Kept      the sandbox client already installed here"
fi

ENTRY="$LIB_DIR/dist/cli.js"
[ -f "$ENTRY" ] || die "the archive unpacked but $ENTRY is missing"

# A launcher, not a symlink: it pins the node that resolved here and
# survives any restructuring inside lib/.
cat >"$INSTALL_DIR/$BIN_NAME" <<EOF
#!/bin/sh
exec node "$ENTRY" "\$@"
EOF
chmod +x "$INSTALL_DIR/$BIN_NAME"

INSTALLED=$("$INSTALL_DIR/$BIN_NAME" --version 2>/dev/null || echo "$TAG")
say "  Installed assay $INSTALLED"
say ""

# ── PATH ─────────────────────────────────────────────────────────────

PATH_LINE="export PATH=\"$INSTALL_DIR:\$PATH\""

profile_for_shell() {
  case "${SHELL##*/}" in
    zsh) printf '%s' "$HOME/.zshrc" ;;
    bash)
      [ "$(uname -s)" = "Darwin" ] && printf '%s' "$HOME/.bash_profile" ||
        printf '%s' "$HOME/.bashrc"
      ;;
    fish) printf '%s' "$HOME/.config/fish/config.fish" ;;
    *) printf '%s' "" ;;
  esac
}

case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    say "  Ready. Try:"
    say ""
    say "    assay run ."
    say ""
    exit 0
    ;;
esac

PROFILE=$(profile_for_shell)

# The live PATH is not the whole story. An upgrade runs in a shell that
# never sourced the profile — a piped `curl | sh` usually is one — so
# checking only `$PATH` tells a user who configured this months ago to
# configure it again, and hands them a line their profile already has.
if [ -n "$PROFILE" ] && grep -qs "$INSTALL_DIR" "$PROFILE" 2>/dev/null; then
  say "  Already on the PATH in $PROFILE."
  say ""
  say "  Open a new terminal (or: hash -r), then:  assay run ."
  say ""
  exit 0
fi

if [ "$ADD_PATH" = "1" ] && [ -n "$PROFILE" ]; then
  printf '\n# assay\n%s\n' "$PATH_LINE" >>"$PROFILE"
  say "  Added to $PROFILE"
  say ""
  say "  Open a new shell, then:  assay run ."
  say ""
else
  say "  One more step — $INSTALL_DIR is not on your PATH."
  say ""
  say "    $PATH_LINE"
  say ""
  [ -n "$PROFILE" ] && say "  Add that to $PROFILE, or re-run with --add-path." || true
  say ""
  say "  Or run it directly right now:"
  say ""
  say "    $INSTALL_DIR/$BIN_NAME run ."
  say ""
fi
