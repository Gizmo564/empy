#!/usr/bin/env python3
"""
build_local.py — Local Nuitka build script for empy
====================================================
Run this on your own machine to test the compilation before pushing a tag.

Usage:
    python build_local.py              # build for current platform
    python build_local.py --clean      # remove dist/ first, then build
    python build_local.py --skip-test  # build without running smoke test
"""

import os
import sys
import shutil
import platform
import subprocess
import argparse
from pathlib import Path

# ─── config ────────────────────────────────────────────────────────────────
SOURCE   = Path(__file__).parent / "empy.py"
DIST_DIR = Path(__file__).parent / "dist"
DEPS     = ["cryptography", "nuitka", "zstandard", "ordered-set"]

# ─── platform detection ────────────────────────────────────────────────────
_sys = platform.system()
_arch = platform.machine().lower()
if _sys == "Darwin":
    _plat = f"macos-{'arm64' if 'arm' in _arch else 'x64'}"
elif _sys == "Linux":
    _plat = "linux-x64"
elif _sys == "Windows":
    _plat = "windows-x64"
else:
    _plat = f"{_sys.lower()}-{_arch}"

EXE_NAME = f"empy-{_plat}" + (".exe" if _sys == "Windows" else "")


def step(msg):
    print(f"\n  ── {msg}")


def run(cmd, **kw):
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    subprocess.check_call(cmd, **kw)


def main():
    ap = argparse.ArgumentParser(description="Build empy with Nuitka")
    ap.add_argument("--clean",      action="store_true", help="Remove dist/ before building")
    ap.add_argument("--skip-test",  action="store_true", help="Skip smoke test")
    ap.add_argument("--skip-deps",  action="store_true", help="Skip pip install step")
    args = ap.parse_args()

    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   empy  —  Empyrean Secure Compression       ║")
    print("  ║   Local build script  (Nuitka)               ║")
    print("  ║   Copyright Volvi 2026                       ║")
    print("  ╚══════════════════════════════════════════════╝")
    print(f"\n  Target : {EXE_NAME}")
    print(f"  Source : {SOURCE}")

    # ── 0. Clean ─────────────────────────────────────────────────────────
    if args.clean and DIST_DIR.exists():
        step("Cleaning dist/")
        shutil.rmtree(DIST_DIR)

    DIST_DIR.mkdir(exist_ok=True)

    # ── 1. Install dependencies ──────────────────────────────────────────
    if not args.skip_deps:
        step("Installing build dependencies")
        run([sys.executable, "-m", "pip", "install", "--quiet", "--upgrade"] + DEPS)

    # ── 2. Check Nuitka is available ─────────────────────────────────────
    step("Checking Nuitka")
    result = subprocess.run(
        [sys.executable, "-m", "nuitka", "--version"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("  ❌  Nuitka not found. Run: pip install nuitka")
        sys.exit(1)
    print(f"  {result.stdout.strip()}")

    # ── 3. Compile ───────────────────────────────────────────────────────
    step("Compiling with Nuitka")

    nuitka_cmd = [
        sys.executable, "-m", "nuitka",
        "--onefile",
        "--standalone",
        "--remove-output",
        "--no-pyi-file",
        "--python-flag=no_docstrings",
        "--python-flag=no_annotations",
        f"--output-filename={EXE_NAME}",
        f"--output-dir={DIST_DIR}",
        "--assume-yes-for-downloads",
    ]

    if _sys == "Windows":
        nuitka_cmd.append("--windows-console-mode=attach")

    if _sys == "Darwin":
        # Embed an icon if one exists
        icon = Path(__file__).parent / "assets" / "empy.icns"
        if icon.exists():
            nuitka_cmd.append(f"--macos-app-icon={icon}")

    nuitka_cmd.append(str(SOURCE))
    run(nuitka_cmd)

    exe = DIST_DIR / EXE_NAME
    if not exe.exists():
        print(f"\n  ❌  Expected output not found: {exe}")
        sys.exit(1)

    size = exe.stat().st_size / (1024 * 1024)
    print(f"\n  ✅  Built: {exe}  ({size:.1f} MB)")

    # ── 4. Make executable (Unix) ────────────────────────────────────────
    if _sys != "Windows":
        exe.chmod(0o755)

    # ── 5. Smoke test ────────────────────────────────────────────────────
    if not args.skip_test:
        step("Running smoke test")
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src_file = tmp / "smoke.txt"
            src_file.write_text("Empyrean Secure Compression — smoke test\n" * 50)

            # version
            run([str(exe), "--version"])

            # encrypt
            run([str(exe), "encrypt", str(src_file), "-p", "smokepassword1", "-f"])
            enc = src_file.parent / (src_file.name + ".empy")
            assert enc.exists(), "Encrypted file not created"

            # decrypt
            out_dir = tmp / "out"
            run([str(exe), "decrypt", str(enc), "-p", "smokepassword1",
                 "--outdir", str(out_dir), "-f"])
            dec = out_dir / "smoke.txt"
            assert dec.exists(), "Decrypted file not created"
            assert dec.read_text() == src_file.read_text(), "Content mismatch!"

            print("  ✅  Smoke test PASSED — encrypt / decrypt round-trip verified")

    # ── 6. Done ──────────────────────────────────────────────────────────
    print()
    print(f"  ┌─────────────────────────────────────────────┐")
    print(f"  │  Build complete                             │")
    print(f"  │  Output: dist/{EXE_NAME:<27}  │")
    print(f"  └─────────────────────────────────────────────┘")
    print()
    print("  To release, commit your changes and push a version tag:")
    print("    git add .")
    print('    git commit -m "Release v3.0.0"')
    print("    git tag v3.0.0")
    print("    git push origin main --tags")
    print()


if __name__ == "__main__":
    main()
