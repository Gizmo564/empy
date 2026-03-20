#!/bin/bash
# setup_github.sh
# ─────────────────────────────────────────────────────────────────
# One-time script: initialise the local repo, hook it to GitHub,
# and push the first release tag so the Actions workflow fires.
#
# Prerequisites:
#   • Git installed  (https://git-scm.com)
#   • GitHub CLI installed  (https://cli.github.com)  — OR —
#     create the repo manually at https://github.com/new
#   • gh auth login  (if using GitHub CLI)
#
# Usage:
#   chmod +x setup_github.sh
#   ./setup_github.sh
# ─────────────────────────────────────────────────────────────────

set -e

# ── Configurable ──────────────────────────────────────────────────
REPO_NAME="empy"
REPO_DESC="Empyrean Secure Compression — AES-256-GCM encrypted file packaging"
VERSION="v3.2.0"
# Set to "true" to make the repo private (requires GitHub Pro for private Actions minutes)
PRIVATE="false"
# ─────────────────────────────────────────────────────────────────

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   empy — GitHub setup script                 ║"
echo "  ║   Copyright Volvi 2026                       ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Git init ───────────────────────────────────────────────────
if [ ! -d ".git" ]; then
  echo "  [1/5] Initialising git repository..."
  git init -b main
else
  echo "  [1/5] Git repository already initialised."
fi

# ── 2. .gitignore ─────────────────────────────────────────────────
if [ ! -f ".gitignore" ]; then
  echo "  [2/5] Writing .gitignore..."
  cat > .gitignore << 'GITIGNORE'
# Build outputs
dist/
build/
*.empy.build/
*.empy.dist/
*.empy.onefile-build/

# Python
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.egg-info/
.venv/
venv/
env/

# OS
.DS_Store
Thumbs.db
desktop.ini

# Test files
*.empy
*.empy.pub
*.empy.key
GITIGNORE
else
  echo "  [2/5] .gitignore already exists, skipping."
fi

# ── 3. Initial commit ─────────────────────────────────────────────
echo "  [3/5] Staging files..."
git add empy.py build_local.py setup_github.sh .gitignore .github/

git diff --cached --quiet && echo "  Nothing to commit." || {
  echo "  Committing..."
  git commit -m "empy ${VERSION} — Empyrean Secure Compression (Copyright Volvi 2026)"
}

# ── 4. Create GitHub repo ─────────────────────────────────────────
if command -v gh &> /dev/null; then
  echo "  [4/5] Creating GitHub repository with gh CLI..."
  # Check if remote already exists
  if git remote get-url origin &> /dev/null; then
    echo "  Remote 'origin' already set: $(git remote get-url origin)"
  else
    if [ "$PRIVATE" = "true" ]; then
      gh repo create "$REPO_NAME" --private --description "$REPO_DESC" --source=. --remote=origin --push
    else
      gh repo create "$REPO_NAME" --public  --description "$REPO_DESC" --source=. --remote=origin --push
    fi
    echo "  ✅  GitHub repo created and initial commit pushed."
  fi
else
  echo "  [4/5] GitHub CLI (gh) not found."
  echo ""
  echo "  ── Manual step required ──────────────────────────────────"
  echo "  1. Go to https://github.com/new"
  echo "  2. Create a repo named: $REPO_NAME"
  echo "  3. Do NOT initialise with README, .gitignore, or license"
  echo "  4. Copy the SSH or HTTPS remote URL, then run:"
  echo ""
  echo "       git remote add origin <your-repo-url>"
  echo "       git push -u origin main"
  echo ""
  echo "  Press ENTER once you've added the remote and pushed..."
  read -r
fi

# ── 5. Tag and push to trigger the build ──────────────────────────
echo "  [5/5] Creating and pushing release tag ${VERSION}..."
git tag -a "$VERSION" -m "empy ${VERSION} — Empyrean Secure Compression"
git push origin main --tags

echo ""
echo "  ✅  Done!"
echo ""
echo "  The GitHub Actions workflow will now build empy for:"
echo "    • Linux  x64"
echo "    • macOS  x64  (Intel)"
echo "    • macOS  arm64 (Apple Silicon)"
echo "    • Windows x64"
echo ""
echo "  Monitor progress at:"
echo "    https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo '<your-username>/empy')/actions"
echo ""
echo "  When the build finishes, binaries will appear under Releases:"
echo "    https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo '<your-username>/empy')/releases"
echo ""
