import os
import sys
import json
import hashlib
import argparse
import datetime

class Colors:
    RESET = '\x1b[0m'
    BOLD = '\x1b[1m'
    GREEN = '\x1b[92m'
    YELLOW = '\x1b[93m'
    RED = '\x1b[91m'
    CYAN = '\x1b[96m'
    WHITE = '\x1b[97m'

    @staticmethod
    def supports_color() -> bool:
        if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
            return False
        if sys.platform == 'win32':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except Exception:
                return False
        return True
_USE_COLOR = Colors.supports_color()

def colorize(text: str, color: str) -> str:
    if _USE_COLOR:
        return f'{color}{text}{Colors.RESET}'
    return text

def compute_sha256(filepath: str, chunk_size: int=65536) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
    except (PermissionError, OSError) as e:
        print(colorize(f"  [WARN] Cannot read '{filepath}': {e}", Colors.YELLOW))
        return None
    return sha256.hexdigest()

def scan_directory(target_dir: str, exclude_paths: set[str] | None=None) -> dict:
    if not os.path.isdir(target_dir):
        print(colorize(f"[ERROR] '{target_dir}' is not a valid directory.", Colors.RED))
        sys.exit(1)
    excluded = {os.path.abspath(path) for path in exclude_paths or set()}
    file_hashes = {}
    file_count = 0
    skipped_count = 0
    print(colorize(f'\n[*] Scanning directory: {os.path.abspath(target_dir)}', Colors.CYAN))
    print(colorize('    (This may take a while for large directories...)\n', Colors.WHITE))
    for dirpath, dirnames, filenames in os.walk(target_dir):
        dirnames.sort()
        for filename in sorted(filenames):
            full_path = os.path.normpath(os.path.join(dirpath, filename))
            if os.path.abspath(full_path) in excluded:
                continue
            file_count += 1
            if file_count % 50 == 0:
                print(colorize(f'  ... scanned {file_count} files so far ...', Colors.WHITE))
            digest = compute_sha256(full_path)
            if digest is not None:
                file_hashes[full_path] = digest
            else:
                skipped_count += 1
    print(colorize(f'\n[*] Scan complete. {file_count} files found, {skipped_count} skipped (permission/access errors).', Colors.CYAN))
    return file_hashes

def create_baseline(target_dir: str, baseline_path: str) -> None:
    hashes = scan_directory(target_dir, exclude_paths={baseline_path})
    baseline_data = {'created_at': datetime.datetime.now().isoformat(timespec='seconds'), 'target_directory': os.path.abspath(target_dir), 'file_count': len(hashes), 'hashes': hashes}
    baseline_dir = os.path.dirname(os.path.abspath(baseline_path))
    os.makedirs(baseline_dir, exist_ok=True)
    try:
        with open(baseline_path, 'w', encoding='utf-8') as f:
            json.dump(baseline_data, f, indent=2, sort_keys=True)
    except OSError as e:
        print(colorize(f'[ERROR] Could not write baseline file: {e}', Colors.RED))
        sys.exit(1)
    print(colorize(f'\n[+] Baseline created successfully!', Colors.GREEN))
    print(colorize(f'    File  : {os.path.abspath(baseline_path)}', Colors.GREEN))
    print(colorize(f'    Files : {len(hashes)} hashed', Colors.GREEN))
    print(colorize(f"    Time  : {baseline_data['created_at']}", Colors.GREEN))
    print(colorize('\n    TIP: Keep this baseline file in a safe, read-only location.', Colors.YELLOW))
    print(colorize('    If an attacker can modify the baseline, the monitor is useless.', Colors.YELLOW))

def load_baseline(baseline_path: str) -> dict:
    if not os.path.isfile(baseline_path):
        print(colorize(f"[ERROR] Baseline file not found: '{baseline_path}'", Colors.RED))
        print(colorize('        Run with --baseline first to create it.', Colors.YELLOW))
        sys.exit(1)
    try:
        with open(baseline_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(colorize(f'[ERROR] Baseline file is corrupt or not valid JSON: {e}', Colors.RED))
        sys.exit(1)
    except OSError as e:
        print(colorize(f'[ERROR] Could not read baseline file: {e}', Colors.RED))
        sys.exit(1)
    required_keys = {'created_at', 'target_directory', 'file_count', 'hashes'}
    if not required_keys.issubset(data.keys()):
        print(colorize('[ERROR] Baseline file is missing required fields. It may have been created by an older version or corrupted.', Colors.RED))
        sys.exit(1)
    print(colorize(f'\n[*] Baseline loaded:', Colors.CYAN))
    print(colorize(f"    Created : {data['created_at']}", Colors.WHITE))
    print(colorize(f"    Dir     : {data['target_directory']}", Colors.WHITE))
    print(colorize(f"    Files   : {data['file_count']} (at baseline time)", Colors.WHITE))
    return data

def check_integrity(target_dir: str, baseline_path: str) -> None:
    baseline_data = load_baseline(baseline_path)
    baseline_hashes = baseline_data['hashes']
    current_hashes = scan_directory(target_dir, exclude_paths={baseline_path})
    baseline_paths = set(baseline_hashes.keys())
    current_paths = set(current_hashes.keys())
    deleted_files = sorted(baseline_paths - current_paths)
    new_files = sorted(current_paths - baseline_paths)
    common_paths = sorted(baseline_paths & current_paths)
    unchanged_files = []
    modified_files = []
    for path in common_paths:
        if current_hashes[path] == baseline_hashes[path]:
            unchanged_files.append(path)
        else:
            modified_files.append(path)
    divider = '-' * 70
    print(colorize(f"\n{'=' * 70}", Colors.CYAN))
    print(colorize(f'  FILE INTEGRITY MONITOR -- CHECK REPORT', Colors.BOLD))
    print(colorize(f"  Checked at : {datetime.datetime.now().isoformat(timespec='seconds')}", Colors.WHITE))
    print(colorize(f'  Directory  : {os.path.abspath(target_dir)}', Colors.WHITE))
    print(colorize(f'  Baseline   : {os.path.abspath(baseline_path)}', Colors.WHITE))
    print(colorize(f"{'=' * 70}\n", Colors.CYAN))
    print(colorize(f'  DELETED FILES  ({len(deleted_files)} found)', Colors.RED))
    print(colorize(f'  {divider}', Colors.WHITE))
    if deleted_files:
        for path in deleted_files:
            print(colorize(f'  [-] DELETED   {path}', Colors.RED))
            print(colorize(f'       Expected hash: {baseline_hashes[path]}', Colors.RED))
    else:
        print(colorize('  (none)', Colors.WHITE))
    print()
    print(colorize(f'  MODIFIED FILES  ({len(modified_files)} found)', Colors.RED))
    print(colorize(f'  {divider}', Colors.WHITE))
    if modified_files:
        for path in modified_files:
            print(colorize(f'  [!] MODIFIED  {path}', Colors.RED))
            print(colorize(f'       Baseline hash : {baseline_hashes[path]}', Colors.WHITE))
            print(colorize(f'       Current hash  : {current_hashes[path]}', Colors.RED))
    else:
        print(colorize('  (none)', Colors.WHITE))
    print()
    print(colorize(f'  NEW FILES  ({len(new_files)} found)', Colors.YELLOW))
    print(colorize(f'  {divider}', Colors.WHITE))
    if new_files:
        for path in new_files:
            print(colorize(f'  [+] NEW       {path}', Colors.YELLOW))
            print(colorize(f'       Current hash  : {current_hashes[path]}', Colors.YELLOW))
    else:
        print(colorize('  (none)', Colors.WHITE))
    print()
    print(colorize(f'  UNCHANGED FILES  ({len(unchanged_files)} found)', Colors.GREEN))
    print(colorize(f'  {divider}', Colors.WHITE))
    if unchanged_files:
        for path in unchanged_files:
            print(colorize(f'  [OK] UNCHANGED  {path}', Colors.GREEN))
    else:
        print(colorize('  (none)', Colors.WHITE))
    total_alerts = len(deleted_files) + len(modified_files) + len(new_files)
    print(colorize(f"\n{'=' * 70}", Colors.CYAN))
    print(colorize(f'  SUMMARY', Colors.BOLD))
    print(colorize(f'  {divider}', Colors.WHITE))
    print(colorize(f'  Unchanged : {len(unchanged_files)}', Colors.GREEN))
    print(colorize(f'  New       : {len(new_files)}', Colors.YELLOW))
    print(colorize(f'  Modified  : {len(modified_files)}', Colors.RED))
    print(colorize(f'  Deleted   : {len(deleted_files)}', Colors.RED))
    if total_alerts == 0:
        print(colorize(f'\n  ALL FILES MATCH BASELINE. No integrity violations detected.', Colors.GREEN))
    else:
        print(colorize(f'\n  WARNING: {total_alerts} INTEGRITY VIOLATION(S) DETECTED. Investigate immediately.', Colors.RED))
    print(colorize(f"{'=' * 70}\n", Colors.CYAN))
    if total_alerts > 0:
        sys.exit(2)

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='file_integrity_monitor', description='File Integrity Monitor -- Educational Cybersecurity Tool\nDetects unauthorized modifications, additions, and deletions\nin a directory by comparing SHA-256 file hashes against a baseline.', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='Examples:\n  Create a baseline:\n    python file_integrity_monitor.py --dir C:\\important_files --baseline\n\n  Check for changes:\n    python file_integrity_monitor.py --dir C:\\important_files --check\n\n  Use a custom baseline file path:\n    python file_integrity_monitor.py --dir C:\\logs --baseline --baseline-file C:\\safe\\logs_baseline.json\n    python file_integrity_monitor.py --dir C:\\logs --check   --baseline-file C:\\safe\\logs_baseline.json\n')
    parser.add_argument('--dir', required=True, metavar='PATH', help='Path to the directory to monitor.')
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--baseline', action='store_true', help='Create (or overwrite) the baseline snapshot for the target directory.')
    mode_group.add_argument('--check', action='store_true', help='Compare the current directory state against the saved baseline.')
    parser.add_argument('--baseline-file', default='baseline.json', metavar='FILE', help="Path to the baseline JSON file. Default: 'baseline.json' in the current directory.")
    return parser

def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    print(colorize('\n' + '=' * 70, Colors.CYAN))
    print(colorize('  FILE INTEGRITY MONITOR -- Educational Cybersecurity Tool', Colors.BOLD))
    print(colorize('  Uses SHA-256 cryptographic hashing to detect file changes', Colors.WHITE))
    print(colorize('=' * 70, Colors.CYAN))
    if args.baseline:
        create_baseline(target_dir=args.dir, baseline_path=args.baseline_file)
    elif args.check:
        check_integrity(target_dir=args.dir, baseline_path=args.baseline_file)
if __name__ == '__main__':
    main()