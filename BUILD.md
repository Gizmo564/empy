# empy v3 — Build & Distribution Guide

**Empyrean Secure Compression**  
Copyright Volvi 2026

---

## What this produces

Running the build pipeline compiles `empy.py` into **standalone native binaries** using [Nuitka](https://nuitka.net), which translates Python → C → machine code. The output requires no Python installation on the end-user's machine.

| Platform | Output file | Notes |
|---|---|---|
| Linux x64 | `empy-linux-x64` | Tested on Ubuntu 22.04+ / Debian 12+ |
| macOS Intel | `empy-macos-x64` | Tested on macOS 13+ |
| macOS Apple Silicon | `empy-macos-arm64` | Tested on macOS 14+ |
| Windows x64 | `empy-windows-x64.exe` | Tested on Windows 10/11 |

All four binaries are built automatically on GitHub's own runners (no local compiler needed) and attached to a GitHub Release whenever you push a version tag.

---

## Why Nuitka, not PyInstaller?

PyInstaller bundles the `.pyc` bytecode in a ZIP archive that can be trivially unpacked with `pyinstxtractor` and then decompiled back to near-original Python with `uncompyle6`. Nuitka actually **compiles Python to C source code** and then invokes a C compiler, producing a native `.so`/`.dll` object file. The result:

- No Python bytecode in the binary — decompilers have nothing to work with
- Logic is embedded in native machine code, mixed with C runtime
- Strip symbols are applied by default — no function names in the binary
- `--python-flag=no_docstrings` removes all string literals used as docstrings
- Significantly harder to reverse engineer than any bytecode-based approach

No obfuscation technique is perfect against a sufficiently motivated attacker with unlimited time, but Nuitka-compiled binaries provide strong practical protection for commercial software.

---

## Quick start — Automated build via GitHub Actions

This is the recommended path. GitHub builds all four platforms simultaneously in about 10–15 minutes, with no local toolchain required.

### Step 1 — Install prerequisites

You need Git and (optionally) the GitHub CLI. The CLI is the easiest path:

```bash
# macOS
brew install git gh

# Linux (Debian/Ubuntu)
sudo apt-get install git
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [signed-by=...] https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list
sudo apt-get update && sudo apt-get install gh

# Windows — download from https://cli.github.com
# or: winget install GitHub.cli
```

### Step 2 — Authenticate with GitHub

```bash
gh auth login
# Follow the interactive prompts — browser login is easiest
```

### Step 3 — Run the setup script

**macOS / Linux:**
```bash
chmod +x setup_github.sh
./setup_github.sh
```

**Windows (PowerShell):**
```powershell
.\setup_github.ps1
```

The script will:
1. Initialise a local git repo
2. Create a GitHub repository named `empy`
3. Push the code
4. Tag the commit as `v3.0.0` and push the tag

Pushing the tag automatically triggers the GitHub Actions workflow.

### Step 4 — Download the binaries

After 10–15 minutes, go to:
```
https://github.com/<your-username>/empy/releases
```

You will find a release named **empy v3.0.0 — Empyrean Secure Compression** with all four binaries attached, plus a `SHA256SUMS.txt` checksum file.

---

## Releasing future versions

To ship a new version:

```bash
# 1. Edit PROG_VERSION in empy.py (e.g. "3.1.0")
# 2. Commit
git add empy.py
git commit -m "Release v3.1.0"

# 3. Tag and push — this triggers the build workflow
git tag v3.1.0
git push origin main --tags
```

A new GitHub Release with all four binaries will be created automatically.

---

## Local build (optional — test before pushing)

If you want to build and test on your own machine before committing:

```bash
# Install build tools (one-time)
pip install nuitka cryptography zstandard ordered-set

# Build for the current platform
python build_local.py

# Build + skip the smoke test
python build_local.py --skip-test

# Clean previous build and rebuild
python build_local.py --clean
```

Output lands in `dist/empy-<platform>`.

### C compiler requirements for local builds

| Platform | Requirement |
|---|---|
| Linux | `gcc` and `patchelf` — `sudo apt-get install gcc patchelf` |
| macOS | Xcode Command Line Tools — `xcode-select --install` |
| Windows | Visual Studio Build Tools 2019+ — [download](https://visualstudio.microsoft.com/visual-cpp-build-tools/) |

The GitHub Actions runners have all of these pre-installed. You only need them locally if you run `build_local.py`.

---

## macOS Gatekeeper (first run)

macOS will quarantine unsigned binaries downloaded from the internet. Users may see "empy-macos-x64 cannot be opened because the developer cannot be verified."

**Workaround (one-time per machine):**

```bash
# Option A — remove the quarantine attribute
xattr -dr com.apple.quarantine ./empy-macos-x64

# Option B — right-click the binary in Finder → Open → Open (first run only)
```

For a fully seamless experience without this prompt, you would need an Apple Developer certificate and to code-sign the binary. This can be added to the GitHub Actions workflow if needed.

---

## Windows SmartScreen

Windows Defender SmartScreen may show "Windows protected your PC" for the `.exe` on first run. Click "More info" → "Run anyway". This warning disappears once the binary has been run by enough users (reputation-based), or can be eliminated with a code-signing certificate (EV certificate from a CA like DigiCert).

---

## File layout

```
empy/
├── empy.py                        Main application (source)
├── build_local.py                 Local build script
├── setup_github.sh                One-time GitHub setup (macOS/Linux)
├── setup_github.ps1               One-time GitHub setup (Windows)
├── .github/
│   └── workflows/
│       └── release.yml            GitHub Actions CI/CD workflow
└── dist/                          Created by build_local.py (gitignored)
    ├── empy-linux-x64
    ├── empy-macos-x64
    ├── empy-macos-arm64
    └── empy-windows-x64.exe
```

---

## Using the distributed binary

End users receive a single file with no installation required.

**Linux / macOS:**
```bash
chmod +x empy-linux-x64        # make it executable (one-time)
./empy-linux-x64               # opens GUI in browser
./empy-linux-x64 encrypt file.txt   # CLI mode
./empy-linux-x64 --help        # full CLI reference
```

**Windows:**
```
Double-click empy-windows-x64.exe     → opens GUI in browser
empy-windows-x64.exe encrypt file.txt → CLI mode
empy-windows-x64.exe --help           → full CLI reference
```

**Verify download integrity:**
```bash
sha256sum empy-linux-x64
# compare against SHA256SUMS.txt from the release
```
