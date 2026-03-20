# setup_github.ps1
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
# Usage (run in PowerShell as normal user):
#   .\setup_github.ps1
# ─────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"

$REPO_NAME  = "empy"
$REPO_DESC  = "Empyrean Secure Compression — AES-256-GCM encrypted file packaging"
$VERSION    = "v3.0.0"
$PRIVATE    = $false   # set to $true for a private repo

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════╗"
Write-Host "  ║   empy — GitHub setup script (Windows)       ║"
Write-Host "  ║   Copyright Volvi 2026                       ║"
Write-Host "  ╚══════════════════════════════════════════════╝"
Write-Host ""

# ── 1. Git init ───────────────────────────────────────────────────
if (-Not (Test-Path ".git")) {
    Write-Host "  [1/5] Initialising git repository..."
    git init -b main
} else {
    Write-Host "  [1/5] Git repository already initialised."
}

# ── 2. .gitignore ─────────────────────────────────────────────────
if (-Not (Test-Path ".gitignore")) {
    Write-Host "  [2/5] Writing .gitignore..."
    @"
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

# Test files generated during development
*.empy
*.empy.pub
*.empy.key
"@ | Out-File -FilePath ".gitignore" -Encoding utf8
} else {
    Write-Host "  [2/5] .gitignore already exists, skipping."
}

# ── 3. Initial commit ─────────────────────────────────────────────
Write-Host "  [3/5] Staging files..."
git add empy.py build_local.py setup_github.ps1 .gitignore .github/

$status = git diff --cached --name-only
if ($status) {
    Write-Host "  Committing..."
    git commit -m "empy $VERSION — Empyrean Secure Compression (Copyright Volvi 2026)"
} else {
    Write-Host "  Nothing to commit."
}

# ── 4. Create GitHub repo ─────────────────────────────────────────
$ghExists = Get-Command gh -ErrorAction SilentlyContinue

if ($ghExists) {
    Write-Host "  [4/5] Creating GitHub repository with gh CLI..."
    try {
        $existing = git remote get-url origin 2>&1
        Write-Host "  Remote 'origin' already set: $existing"
    } catch {
        $visibility = if ($PRIVATE) { "--private" } else { "--public" }
        gh repo create $REPO_NAME $visibility --description $REPO_DESC --source=. --remote=origin --push
        Write-Host "  ✅  GitHub repo created and initial commit pushed."
    }
} else {
    Write-Host "  [4/5] GitHub CLI (gh) not found."
    Write-Host ""
    Write-Host "  ── Manual step required ──────────────────────────────────"
    Write-Host "  1. Go to https://github.com/new"
    Write-Host "  2. Create a repo named: $REPO_NAME"
    Write-Host "  3. Do NOT initialise with README, .gitignore, or license"
    Write-Host "  4. Copy the SSH or HTTPS remote URL, then run:"
    Write-Host ""
    Write-Host "       git remote add origin <your-repo-url>"
    Write-Host "       git push -u origin main"
    Write-Host ""
    Write-Host "  Press ENTER once you've added the remote and pushed..."
    Read-Host
}

# ── 5. Tag and push ───────────────────────────────────────────────
Write-Host "  [5/5] Creating and pushing release tag $VERSION..."
git tag -a $VERSION -m "empy $VERSION — Empyrean Secure Compression"
git push origin main --tags

Write-Host ""
Write-Host "  ✅  Done!"
Write-Host ""
Write-Host "  The GitHub Actions workflow will now build empy for:"
Write-Host "    • Linux  x64"
Write-Host "    • macOS  x64  (Intel)"
Write-Host "    • macOS  arm64 (Apple Silicon)"
Write-Host "    • Windows x64"
Write-Host ""
Write-Host "  When the build finishes, download binaries from the Releases page."
Write-Host ""
