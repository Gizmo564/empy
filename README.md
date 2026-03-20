# empy v3 — Empyrean Secure Compression
**Copyright Volvi 2026**

AES-256-GCM encrypted file packaging with a browser GUI and full CLI.

---

## Setup

### Prerequisites
- [Git](https://git-scm.com/downloads)
- [GitHub CLI](https://cli.github.com) (`gh`)
- A GitHub account

### Step 1 — Authenticate with GitHub (once)
```bash
gh auth login
```
Choose GitHub.com → HTTPS → Login with a web browser.

---

### Step 2 — Run setup

**macOS / Linux:**
```bash
chmod +x setup_github.sh
./setup_github.sh
```

**Windows (PowerShell):**
```powershell
.\setup_github.ps1
```

This will:
1. Initialise a local git repo
2. Create a public GitHub repo named `empy`
3. Push all files
4. Tag the commit as `v3.0.0` and push the tag

Pushing the tag triggers GitHub Actions to automatically build native binaries for Linux, macOS, and Windows.

---

### Step 3 — Download your binaries

After ~15 minutes, your compiled binaries will be at:
```
https://github.com/<your-username>/empy/releases
```

| File | Platform |
|---|---|
| `empy-linux-x64` | Linux (x64) |
| `empy-macos-arm64` | macOS (Apple Silicon + Intel via Rosetta) |
| `empy-windows-x64.exe` | Windows (x64) |

---

## Using empy

**Open the GUI (double-click or run with no arguments):**
```bash
./empy-linux-x64
```

**CLI:**
```bash
./empy-linux-x64 encrypt photo.jpg
./empy-linux-x64 decrypt photo.jpg.empy
./empy-linux-x64 --help
```

**macOS — first run only:**
```bash
xattr -dr com.apple.quarantine ./empy-macos-arm64
chmod +x ./empy-macos-arm64
```

---

## Releasing a new version

```bash
# Edit PROG_VERSION in empy.py, then:
git add empy.py
git commit -m "Release v3.1.0"
git tag v3.1.0
git push origin main --tags
```

A new GitHub Release with fresh binaries is created automatically.
