#!/usr/bin/env python3
"""
Build script for vt_scanner.exe
Double-click friendly: fixes CWD, pauses on both success and failure.
"""

import os
import sys
import shutil
import subprocess

os.chdir(os.path.dirname(os.path.abspath(__file__)))

SCRIPT   = "vt_scanner.py"
EXE_NAME = "vt_scanner"
ICON     = "icon.ico"

EXCLUDES = [
    # Data science / ML
    "numpy", "pandas", "matplotlib", "matplotlib.backends",
    "scipy", "sklearn", "tensorflow", "torch",
    "torchvision", "torchaudio",
    # Image processing
    "PIL", "cv2",
    # GUI frameworks
    "tkinter", "_tkinter",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "wx",
    # Web frameworks / async
    "flask", "django", "fastapi", "starlette",
    "uvicorn", "aiohttp", "httpx",
    # Database
    "sqlalchemy", "psycopg2", "pymysql",
    # Cloud
    "boto3", "botocore", "s3transfer",
    # Dev / notebook tools
    "pytest", "_pytest", "IPython",
    "jupyter", "notebook", "ipykernel",
    # Misc heavy libs
    "docutils", "pydantic", "grpc",
    "xmlrpc", "email.mime",
    "cryptography", "Crypto",
]

def pause_and_exit(code: int = 0):
    print()
    os.system("pause")
    sys.exit(code)

def check_pyinstaller():
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--version"],
        capture_output=True
    )
    if result.returncode != 0:
        print("ERROR: PyInstaller is not installed.")
        print(f"Fix: {sys.executable} -m pip install pyinstaller")
        pause_and_exit(1)

def clean_old_artifacts():
    print("Cleaning old build artifacts...")
    removed = []

    spec_file = f"{EXE_NAME}.spec"
    if os.path.exists(spec_file):
        os.remove(spec_file)
        removed.append(spec_file)

    for folder in ["build", "dist"]:
        if os.path.isdir(folder):
            shutil.rmtree(folder)
            removed.append(folder + "/")

    if removed:
        print(f"Removed: {', '.join(removed)}")
    else:
        print("Nothing to clean.")
    print()

def main():
    if not os.path.exists(SCRIPT):
        print(f"ERROR: '{SCRIPT}' not found in {os.getcwd()}")
        print("Make sure build_exe.py is in the same folder as vt_scanner.py.")
        pause_and_exit(1)

    check_pyinstaller()
    clean_old_artifacts()

    icon_abs   = os.path.abspath(ICON) if os.path.exists(ICON) else None
    icon_flags = ["--icon", icon_abs] if icon_abs else []

    if not icon_abs:
        print(f"WARNING: '{ICON}' not found - building without an icon.")
        print()

    exclude_flags = []
    for pkg in EXCLUDES:
        exclude_flags += ["--exclude-module", pkg]

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--console",
        "--name", EXE_NAME,
        "--clean",
        "--noconfirm",
        *icon_flags,
        *exclude_flags,
        SCRIPT,
    ]

    print("=" * 50)
    print(f"  Building {EXE_NAME}.exe")
    print("=" * 50)
    print(f"Script  : {os.path.abspath(SCRIPT)}")
    if icon_abs:
        print(f"Icon    : {icon_abs}")
    print(f"Excludes: {len(EXCLUDES)} packages")
    print()

    result = subprocess.run(cmd, check=False)

    print()
    if result.returncode == 0:
        exe_path = os.path.join("dist", f"{EXE_NAME}.exe")
        size_mb  = os.path.getsize(exe_path) / (1024 * 1024) if os.path.exists(exe_path) else 0
        print(f"Build successful!")
        print(f"Output : {os.path.abspath(exe_path)}")
        print(f"Size   : {size_mb:.1f} MB")
        if icon_abs:
            print("Note: if the icon doesn't show yet, press F5 in Explorer to refresh.")
        pause_and_exit(0)
    else:
        print(f"Build FAILED (exit code {result.returncode})")
        print("Scroll up to find the error from PyInstaller.")
        pause_and_exit(result.returncode)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        pause_and_exit(1)
