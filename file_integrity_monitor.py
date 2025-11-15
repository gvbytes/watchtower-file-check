#!/usr/bin/env python3
"""
================================================================================
  FILE INTEGRITY MONITOR (FIM) — Educational Cybersecurity Tool
================================================================================

WHAT IS FILE INTEGRITY MONITORING?
------------------------------------
File Integrity Monitoring (FIM) is a security technique used to detect
unauthorized or unexpected changes to files on a system. It is a cornerstone
of:

  * Digital Forensics — Investigators use FIM to prove that evidence files
    have not been tampered with since they were collected. If a file's hash
    matches the original, it is forensically sound.

  * Malware Detection — Malware often modifies system files (e.g., replacing
    a legitimate DLL with a malicious one). FIM catches these changes even
    after the fact.

  * Incident Response — When a breach is suspected, analysts compare the
    current state of critical files against a "known-good" baseline taken
    before the attack occurred. Any deviation is a red flag.

  * Compliance — Standards like PCI-DSS, HIPAA, and ISO 27001 mandate FIM
    on critical system files and configurations.


WHAT IS A CRYPTOGRAPHIC HASH?
--------------------------------
A cryptographic hash function takes an input (any file, any size) and produces
a fixed-length string of characters called a "digest" or "hash". Key properties:

  1. DETERMINISTIC   -- The same input ALWAYS produces the same output hash.
  2. ONE-WAY         -- You cannot reconstruct the original file from the hash.
  3. AVALANCHE EFFECT-- Changing even ONE bit in the file produces a completely
                        different hash (roughly 50% of bits flip).
  4. COLLISION RESISTANT -- It is computationally infeasible to find two
                            different files with the same hash.

WHY SHA-256?
  * SHA-256 (Secure Hash Algorithm, 256-bit output) is part of the SHA-2 family
    standardized by NIST. It produces a 64-character hexadecimal digest.
  * MD5 and SHA-1 are older and have known collision vulnerabilities -- attackers
    can craft two different files with the same hash. SHA-256 has no known
    practical collision attacks.
  * SHA-256 is fast enough for bulk file scanning while being secure enough
    for forensic use. It is the industry standard for FIM and code signing.

Example SHA-256 behavior:
  "hello"  -> 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
  "Hello"  -> 185f8db32921bd46d35981763b820ce4d316d648c74f41a7c4429e6e0c4d4b0f
  (One capital letter changed -- completely different hash)


THE "KNOWN-GOOD" BASELINE CONCEPT
------------------------------------
Before an attack happens (or right after a clean install), you capture the
state of all important files -- their paths and their hashes. This is your
BASELINE -- a trusted snapshot of what "normal" looks like.

Later, you run the monitor again. It recomputes all hashes and compares them
to the baseline:
  - Hash MATCHES   -> File is unchanged. Safe.
  - Hash DIFFERS   -> File was MODIFIED. Investigate!
  - File is NEW    -> Something was ADDED. Could be malware dropping files.
  - File is GONE   -> Something was DELETED. Could be evidence wiping.

This is exactly how tools like Tripwire, AIDE, and Windows File Integrity
Checking work in the real world.

================================================================================
USAGE:
  Create baseline:   python file_integrity_monitor.py --dir <path> --baseline
  Check for changes: python file_integrity_monitor.py --dir <path> --check
  Custom baseline:   python file_integrity_monitor.py --dir <path> --check --baseline-file my_baseline.json
================================================================================
"""

import os
import sys
import json
import hashlib
import argparse
import datetime


# -----------------------------------------------------------------------------
# ANSI COLOR CODES
# These are special escape sequences that tell the terminal to display text
# in different colors. They work on Linux, macOS, and modern Windows terminals
# (Windows Terminal, VS Code, PowerShell 7+). The format is:
#   \033[<code>m  ->  start color
#   \033[0m       ->  reset to default
# -----------------------------------------------------------------------------

class Colors:
    """ANSI terminal color codes for color-coded output."""
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"   # Bright green  -- unchanged files (safe)
    YELLOW = "\033[93m"   # Bright yellow -- new files (investigate)
    RED    = "\033[91m"   # Bright red    -- modified or deleted (alert!)
    CYAN   = "\033[96m"   # Bright cyan   -- informational headers
    WHITE  = "\033[97m"   # Bright white  -- general text

    @staticmethod
    def supports_color() -> bool:
        """
        Check whether the terminal supports ANSI colors.
        On Windows, legacy cmd.exe does not support them. We detect this so we
        can gracefully fall back to plain text if needed.
        """
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        if sys.platform == "win32":
            # Enable ANSI processing on Windows 10+ via the Windows API
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except Exception:
                return False
        return True


# Global flag -- set once at startup
_USE_COLOR = Colors.supports_color()


def colorize(text: str, color: str) -> str:
    """
    Wrap text in ANSI color codes if the terminal supports it.
    If colors are not supported, return the text unchanged so output
    is still readable when piped to a file or viewed on legacy terminals.
    """
    if _USE_COLOR:
        return f"{color}{text}{Colors.RESET}"
    return text


# -----------------------------------------------------------------------------
# CORE HASHING LOGIC
# -----------------------------------------------------------------------------

def compute_sha256(filepath: str, chunk_size: int = 65536) -> str:
    """
    Compute the SHA-256 hash of a single file and return it as a
    64-character hexadecimal string.

    WHY READ IN CHUNKS?
    -------------------
    Large files (e.g., a 4 GB video file) cannot be loaded into memory all at
    once without risking a MemoryError. Instead, we read the file in small
    chunks (default: 64 KB = 65,536 bytes) and feed each chunk into the
    hash object incrementally. The SHA-256 algorithm maintains internal state
    across updates, so the final digest is identical to hashing the whole file
    at once. This is called "streaming hashing".

    Args:
        filepath  : Absolute or relative path to the file to hash.
        chunk_size: Number of bytes to read per iteration (default 64 KB).

    Returns:
        A 64-character lowercase hexadecimal SHA-256 digest string,
        or None if the file could not be read (permission denied, locked, etc.)
    """
    sha256 = hashlib.sha256()  # Create a fresh SHA-256 hash object

    try:
        # Open in BINARY mode ('rb') -- we need raw bytes, not decoded text.
        # Text mode would apply OS-specific line-ending conversion (e.g., \r\n
        # -> \n on Windows), which would change the hash even though the file
        # content is logically the same. Binary mode gives us the exact bytes
        # that live on disk.
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break              # End of file reached
                sha256.update(chunk)  # Feed this chunk into the hash state

    except (PermissionError, OSError) as e:
        # PermissionError: we don't have read access (common for system files)
        # OSError: file is locked by another process, or is a special device
        print(colorize(f"  [WARN] Cannot read '{filepath}': {e}", Colors.YELLOW))
        return None

    return sha256.hexdigest()  # Returns the final 64-char hex string


def scan_directory(target_dir: str, exclude_paths: set[str] | None = None) -> dict:
    """
    Recursively walk a directory tree, compute SHA-256 hashes for every
    regular file found, and return a dictionary mapping file paths to hashes.

    HOW os.walk() WORKS:
    ---------------------
    os.walk(top) is a generator that yields a 3-tuple for every directory it
    visits:
        (dirpath, dirnames, filenames)
    - dirpath   : Current directory being visited (string)
    - dirnames  : List of subdirectory names in dirpath
    - filenames : List of file names in dirpath (NOT full paths -- just names)

    We construct the full path as: os.path.join(dirpath, filename)

    NORMALIZATION:
    We use os.path.normpath() to normalize the path string (removes redundant
    slashes, resolves '.' and '..'). This ensures consistent dictionary keys
    regardless of how the user typed the path.

    Args:
        target_dir: The root directory to scan.

    Returns:
        A dict of { normalized_file_path: sha256_hex_string }
        Files that could not be read are omitted (None hash is not stored).
    """
    if not os.path.isdir(target_dir):
        print(colorize(f"[ERROR] '{target_dir}' is not a valid directory.", Colors.RED))
        sys.exit(1)

    excluded = {os.path.abspath(path) for path in (exclude_paths or set())}
    file_hashes = {}
    file_count = 0
    skipped_count = 0

    print(colorize(f"\n[*] Scanning directory: {os.path.abspath(target_dir)}", Colors.CYAN))
    print(colorize(    "    (This may take a while for large directories...)\n", Colors.WHITE))

    for dirpath, dirnames, filenames in os.walk(target_dir):
        # Sort dirnames in-place to ensure deterministic traversal order.
        # os.walk visits directories in filesystem order (which can vary by OS
        # and filesystem). Sorting makes our output and baseline reproducible.
        dirnames.sort()

        for filename in sorted(filenames):
            full_path = os.path.normpath(os.path.join(dirpath, filename))
            if os.path.abspath(full_path) in excluded:
                continue
            file_count += 1

            # Progress indicator every 50 files
            if file_count % 50 == 0:
                print(colorize(f"  ... scanned {file_count} files so far ...", Colors.WHITE))

            digest = compute_sha256(full_path)

            if digest is not None:
                file_hashes[full_path] = digest
            else:
                skipped_count += 1

    print(colorize(f"\n[*] Scan complete. {file_count} files found, "
                   f"{skipped_count} skipped (permission/access errors).", Colors.CYAN))
    return file_hashes


# -----------------------------------------------------------------------------
# BASELINE OPERATIONS
# -----------------------------------------------------------------------------

def create_baseline(target_dir: str, baseline_path: str) -> None:
    """
    Scan the target directory and write the resulting hash dictionary to a
    JSON file as the "known-good" baseline.

    WHY JSON?
    ----------
    JSON (JavaScript Object Notation) is a human-readable, language-agnostic
    text format. We use it here because:
      - It is easy to inspect in any text editor (useful for auditing)
      - Python's built-in `json` module handles serialization/deserialization
      - It is easily diff-able with tools like git diff

    The baseline JSON structure:
    {
        "created_at": "2025-06-21T01:22:43",
        "target_directory": "C:\\Users\\...",
        "file_count": 42,
        "hashes": {
            "C:\\path\\to\\file.txt": "abc123...def456",
            ...
        }
    }

    The metadata fields (created_at, target_directory, file_count) provide
    audit context -- in a forensic investigation, you need to know WHEN the
    baseline was taken, not just what the hashes were.

    Args:
        target_dir   : Directory to scan.
        baseline_path: Path where the baseline JSON file will be saved.
    """
    hashes = scan_directory(target_dir, exclude_paths={baseline_path})

    baseline_data = {
        "created_at":       datetime.datetime.now().isoformat(timespec="seconds"),
        "target_directory": os.path.abspath(target_dir),
        "file_count":       len(hashes),
        "hashes":           hashes,
    }

    # Ensure the output directory exists
    baseline_dir = os.path.dirname(os.path.abspath(baseline_path))
    os.makedirs(baseline_dir, exist_ok=True)

    try:
        with open(baseline_path, "w", encoding="utf-8") as f:
            # indent=2 makes the JSON human-readable (pretty-printed)
            # sort_keys=True ensures a consistent, diff-friendly key order
            json.dump(baseline_data, f, indent=2, sort_keys=True)
    except OSError as e:
        print(colorize(f"[ERROR] Could not write baseline file: {e}", Colors.RED))
        sys.exit(1)

    print(colorize(f"\n[+] Baseline created successfully!", Colors.GREEN))
    print(colorize(f"    File  : {os.path.abspath(baseline_path)}", Colors.GREEN))
    print(colorize(f"    Files : {len(hashes)} hashed", Colors.GREEN))
    print(colorize(f"    Time  : {baseline_data['created_at']}", Colors.GREEN))
    print(colorize("\n    TIP: Keep this baseline file in a safe, read-only location.", Colors.YELLOW))
    print(colorize("    If an attacker can modify the baseline, the monitor is useless.", Colors.YELLOW))


def load_baseline(baseline_path: str) -> dict:
    """
    Load and validate a previously saved baseline JSON file.

    Args:
        baseline_path: Path to the baseline JSON file.

    Returns:
        The full baseline data dictionary.
    """
    if not os.path.isfile(baseline_path):
        print(colorize(f"[ERROR] Baseline file not found: '{baseline_path}'", Colors.RED))
        print(colorize(         "        Run with --baseline first to create it.", Colors.YELLOW))
        sys.exit(1)

    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(colorize(f"[ERROR] Baseline file is corrupt or not valid JSON: {e}", Colors.RED))
        sys.exit(1)
    except OSError as e:
        print(colorize(f"[ERROR] Could not read baseline file: {e}", Colors.RED))
        sys.exit(1)

    # Basic structure validation
    required_keys = {"created_at", "target_directory", "file_count", "hashes"}
    if not required_keys.issubset(data.keys()):
        print(colorize("[ERROR] Baseline file is missing required fields. "
                       "It may have been created by an older version or corrupted.", Colors.RED))
        sys.exit(1)

    print(colorize(f"\n[*] Baseline loaded:", Colors.CYAN))
    print(colorize(f"    Created : {data['created_at']}", Colors.WHITE))
    print(colorize(f"    Dir     : {data['target_directory']}", Colors.WHITE))
    print(colorize(f"    Files   : {data['file_count']} (at baseline time)", Colors.WHITE))

    return data


# -----------------------------------------------------------------------------
# INTEGRITY CHECK AND REPORT
# -----------------------------------------------------------------------------

def check_integrity(target_dir: str, baseline_path: str) -> None:
    """
    Compare the current state of the target directory against the saved
    baseline, then print a color-coded report of all changes.

    ALGORITHM:
    -----------
    Given:
        baseline_hashes = { path: hash, ... }  <- from baseline JSON
        current_hashes  = { path: hash, ... }  <- freshly scanned

    We compute three sets:
        baseline_paths = set of all paths in baseline
        current_paths  = set of all paths currently on disk

    1. DELETED files:
       baseline_paths - current_paths
       (were in baseline, now gone)

    2. NEW files:
       current_paths - baseline_paths
       (not in baseline, appeared since then)

    3. COMMON files:
       baseline_paths AND current_paths (intersection)
       For each common path, compare hashes:
         - Same hash   -> UNCHANGED
         - Diff hash   -> MODIFIED

    This set-difference approach is O(n) in the number of files, which is
    efficient even for very large directories.

    Args:
        target_dir   : Directory to re-scan.
        baseline_path: Path to the baseline JSON file.
    """
    baseline_data   = load_baseline(baseline_path)
    baseline_hashes = baseline_data["hashes"]  # { path: hash }

    # Rescan the directory to get current state
    current_hashes = scan_directory(target_dir, exclude_paths={baseline_path})  # { path: hash }

    # Convert to sets for fast set-difference operations
    baseline_paths = set(baseline_hashes.keys())
    current_paths  = set(current_hashes.keys())

    # Categorize results
    deleted_files = sorted(baseline_paths - current_paths)
    new_files     = sorted(current_paths  - baseline_paths)
    common_paths  = sorted(baseline_paths & current_paths)

    unchanged_files = []
    modified_files  = []

    for path in common_paths:
        if current_hashes[path] == baseline_hashes[path]:
            unchanged_files.append(path)
        else:
            modified_files.append(path)

    # Print Report
    divider = "-" * 70

    print(colorize(f"\n{'=' * 70}", Colors.CYAN))
    print(colorize(f"  FILE INTEGRITY MONITOR -- CHECK REPORT", Colors.BOLD))
    print(colorize(f"  Checked at : {datetime.datetime.now().isoformat(timespec='seconds')}", Colors.WHITE))
    print(colorize(f"  Directory  : {os.path.abspath(target_dir)}", Colors.WHITE))
    print(colorize(f"  Baseline   : {os.path.abspath(baseline_path)}", Colors.WHITE))
    print(colorize(f"{'=' * 70}\n", Colors.CYAN))

    # DELETED FILES
    print(colorize(f"  DELETED FILES  ({len(deleted_files)} found)", Colors.RED))
    print(colorize(f"  {divider}", Colors.WHITE))
    if deleted_files:
        for path in deleted_files:
            print(colorize(f"  [-] DELETED   {path}", Colors.RED))
            print(colorize(f"       Expected hash: {baseline_hashes[path]}", Colors.RED))
    else:
        print(colorize("  (none)", Colors.WHITE))

    print()

    # MODIFIED FILES
    print(colorize(f"  MODIFIED FILES  ({len(modified_files)} found)", Colors.RED))
    print(colorize(f"  {divider}", Colors.WHITE))
    if modified_files:
        for path in modified_files:
            print(colorize(f"  [!] MODIFIED  {path}", Colors.RED))
            print(colorize(f"       Baseline hash : {baseline_hashes[path]}", Colors.WHITE))
            print(colorize(f"       Current hash  : {current_hashes[path]}", Colors.RED))
    else:
        print(colorize("  (none)", Colors.WHITE))

    print()

    # NEW FILES
    print(colorize(f"  NEW FILES  ({len(new_files)} found)", Colors.YELLOW))
    print(colorize(f"  {divider}", Colors.WHITE))
    if new_files:
        for path in new_files:
            print(colorize(f"  [+] NEW       {path}", Colors.YELLOW))
            print(colorize(f"       Current hash  : {current_hashes[path]}", Colors.YELLOW))
    else:
        print(colorize("  (none)", Colors.WHITE))

    print()

    # UNCHANGED FILES
    print(colorize(f"  UNCHANGED FILES  ({len(unchanged_files)} found)", Colors.GREEN))
    print(colorize(f"  {divider}", Colors.WHITE))
    if unchanged_files:
        for path in unchanged_files:
            print(colorize(f"  [OK] UNCHANGED  {path}", Colors.GREEN))
    else:
        print(colorize("  (none)", Colors.WHITE))

    # SUMMARY
    total_alerts = len(deleted_files) + len(modified_files) + len(new_files)

    print(colorize(f"\n{'=' * 70}", Colors.CYAN))
    print(colorize(f"  SUMMARY", Colors.BOLD))
    print(colorize(f"  {divider}", Colors.WHITE))
    print(colorize(f"  Unchanged : {len(unchanged_files)}", Colors.GREEN))
    print(colorize(f"  New       : {len(new_files)}",       Colors.YELLOW))
    print(colorize(f"  Modified  : {len(modified_files)}",  Colors.RED))
    print(colorize(f"  Deleted   : {len(deleted_files)}",   Colors.RED))

    if total_alerts == 0:
        print(colorize(f"\n  ALL FILES MATCH BASELINE. No integrity violations detected.", Colors.GREEN))
    else:
        print(colorize(f"\n  WARNING: {total_alerts} INTEGRITY VIOLATION(S) DETECTED. Investigate immediately.", Colors.RED))

    print(colorize(f"{'=' * 70}\n", Colors.CYAN))

    # Exit with a non-zero status code if violations were found.
    # This is important when the tool is called from a script or CI pipeline --
    # the calling script can check the exit code to decide what to do next
    # (e.g., send an alert email, halt a deployment, etc.)
    if total_alerts > 0:
        sys.exit(2)  # Exit code 2 = integrity violations found


# -----------------------------------------------------------------------------
# COMMAND-LINE INTERFACE
# -----------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    """
    Build and return the command-line argument parser.

    WHY argparse?
    --------------
    argparse is Python's built-in module for parsing command-line arguments.
    It automatically generates --help text, validates argument types, and
    handles missing/extra arguments gracefully.
    """
    parser = argparse.ArgumentParser(
        prog="file_integrity_monitor",
        description=(
            "File Integrity Monitor -- Educational Cybersecurity Tool\n"
            "Detects unauthorized modifications, additions, and deletions\n"
            "in a directory by comparing SHA-256 file hashes against a baseline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  Create a baseline:\n"
            "    python file_integrity_monitor.py --dir C:\\important_files --baseline\n\n"
            "  Check for changes:\n"
            "    python file_integrity_monitor.py --dir C:\\important_files --check\n\n"
            "  Use a custom baseline file path:\n"
            "    python file_integrity_monitor.py --dir C:\\logs --baseline --baseline-file C:\\safe\\logs_baseline.json\n"
            "    python file_integrity_monitor.py --dir C:\\logs --check   --baseline-file C:\\safe\\logs_baseline.json\n"
        ),
    )

    # Required: the target directory to scan
    parser.add_argument(
        "--dir",
        required=True,
        metavar="PATH",
        help="Path to the directory to monitor.",
    )

    # Mutually exclusive group: user must choose either --baseline OR --check
    mode_group = parser.add_mutually_exclusive_group(required=True)

    mode_group.add_argument(
        "--baseline",
        action="store_true",
        help="Create (or overwrite) the baseline snapshot for the target directory.",
    )

    mode_group.add_argument(
        "--check",
        action="store_true",
        help="Compare the current directory state against the saved baseline.",
    )

    # Optional: custom path for the baseline JSON file
    parser.add_argument(
        "--baseline-file",
        default="baseline.json",
        metavar="FILE",
        help="Path to the baseline JSON file. Default: 'baseline.json' in the current directory.",
    )

    return parser


def main() -> None:
    """
    Entry point. Parse arguments and dispatch to the appropriate function.
    """
    parser = build_argument_parser()
    args   = parser.parse_args()

    print(colorize("\n" + "=" * 70, Colors.CYAN))
    print(colorize("  FILE INTEGRITY MONITOR -- Educational Cybersecurity Tool", Colors.BOLD))
    print(colorize("  Uses SHA-256 cryptographic hashing to detect file changes", Colors.WHITE))
    print(colorize("=" * 70, Colors.CYAN))

    if args.baseline:
        create_baseline(
            target_dir    = args.dir,
            baseline_path = args.baseline_file,
        )
    elif args.check:
        check_integrity(
            target_dir    = args.dir,
            baseline_path = args.baseline_file,
        )


# -----------------------------------------------------------------------------
# SCRIPT ENTRY POINT
# The `if __name__ == "__main__"` guard ensures that main() is only called when
# this script is run directly (e.g., `python file_integrity_monitor.py`).
# If someone imports this file as a module in another script, main() will NOT
# be called automatically -- which allows the functions to be reused.
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
