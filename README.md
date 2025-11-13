# Watchtower File Check

Watchtower File Check keeps a baseline of file hashes for a folder and reports
what changed later. It is a practical way to learn how integrity monitoring,
hashing, and simple forensic checks fit together.


## What it does

The monitor records SHA-256 hashes for every file in a target folder. Later, it scans the same folder again and compares the current hashes with the saved baseline.

It reports:
  * unchanged files
  * new files
  * modified files
  * deleted files

Tip: If you store `baseline.json` inside the monitored folder, the tool ignores
that baseline file during scans so it does not report its own bookkeeping as a
new file.


## Hashing model

A cryptographic hash function reads a file and produces a fixed-size digest, for example:

  2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

That 64-character value is the file hash. The properties that matter here are:

  PROPERTY 1: DETERMINISTIC
  If you hash the same file twice, you ALWAYS get the exact same hash.

  PROPERTY 2: SMALL CHANGE, DIFFERENT HASH
  If you change even ONE letter in a file (like changing "hello" to "Hello"),
  the hash changes COMPLETELY. Not just a little bit — totally different!

  PROPERTY 3: ONE-WAY
  You can't take a hash and figure out what the original file was.
  It's a one-way street.

  PROPERTY 4: COLLISION RESISTANT
  It's practically impossible for two different files to have the same hash.

The specific hash recipe we use is called SHA-256. It's created by NIST
(a US government science agency) and it's trusted by banks, governments, and
cybersecurity experts worldwide. We don't use older recipes like MD5 or SHA-1
because mathematicians found tricks to "break" them (create fake files with
the same hash). SHA-256 has no known weaknesses like that.


--------------------------------------------------------------------------------
  THE BASELINE — "A PHOTO OF NORMAL"
--------------------------------------------------------------------------------

Think of it like this:

  You take a photo of your bedroom before you leave for school.
  When you come back, you take another photo and compare them.
  If something is different — maybe your little sibling moved your stuff —
  you'll notice right away!

The "baseline" is that first photo. It's a file (called baseline.json) that
stores the hash (digital fingerprint) of every file in your folder at a
specific point in time, along with the exact date and time it was created.

Later, you run the tool in "check" mode. It takes a new set of fingerprints
and compares them to the baseline photo. Any differences stand out clearly.


--------------------------------------------------------------------------------
  WHY DO REAL CYBERSECURITY EXPERTS USE THIS?
--------------------------------------------------------------------------------

1. FINDING MALWARE (Viruses and Bad Programs)
   Malware (bad software) often works by secretly replacing a normal file with
   a dangerous fake version. For example, it might replace "notepad.exe" with
   a version that steals your passwords. An FIM tool would catch this because
   the hash of "notepad.exe" would be different from the baseline!

2. DIGITAL FORENSICS (Computer Crime Investigation)
   When police investigate a computer crime, they need to prove that the
   evidence hasn't been tampered with. Before they analyze files, they hash
   them. After analysis, they hash them again. If the hashes match, the files
   are "forensically sound" — proven untouched.

3. INCIDENT RESPONSE (Cleaning Up After a Hack)
   If a company gets hacked, security analysts run FIM to find out EXACTLY
   which files the attacker changed or added. This tells them what happened
   and what to fix.

4. COMPLIANCE (Following the Rules)
   Many industries (banking, hospitals, etc.) are REQUIRED BY LAW to use
   file integrity monitoring. Standards like PCI-DSS, HIPAA, and ISO 27001
   all mandate it for critical files.

Real-world FIM tools you might have heard of include Tripwire, AIDE, and
Windows System File Checker (sfc /scannow) — all use the same core idea!


--------------------------------------------------------------------------------
  HOW TO RUN THE TOOL
--------------------------------------------------------------------------------

You need Python 3.6 or newer installed. That's it — no extra packages needed!

STEP 1: Open your terminal / PowerShell / Command Prompt

STEP 2: Navigate to the folder where the script is saved:
  cd C:\Users\Jay Prakash Verma\.gemini\antigravity\scratch\cyber_tools\file_integrity_monitor

STEP 3: CREATE A BASELINE (the "before" photo)
  This scans a folder and saves all file fingerprints.

  python file_integrity_monitor.py --dir "C:\path\to\your\folder" --baseline

  Example (scan a folder called "test_files"):
  python file_integrity_monitor.py --dir "C:\Users\Jay Prakash Verma\Desktop\test_files" --baseline

  This creates a file called "baseline.json" in your current directory.

STEP 4: Make some changes to files in that folder (to test the tool!)
  - Edit a file
  - Add a new file
  - Delete a file

STEP 5: CHECK FOR CHANGES (the "after" photo comparison)
  python file_integrity_monitor.py --dir "C:\path\to\your\folder" --check

  The tool will show you exactly what changed, in color!


--------------------------------------------------------------------------------
  OPTIONAL: USE A CUSTOM LOCATION FOR THE BASELINE FILE
--------------------------------------------------------------------------------

By default, baseline.json is saved in whatever folder you're currently in.
You can choose a different location with --baseline-file:

  Create baseline at a specific location:
  python file_integrity_monitor.py --dir "C:\important" --baseline --baseline-file "C:\safe\my_baseline.json"

  Check against that same baseline:
  python file_integrity_monitor.py --dir "C:\important" --check --baseline-file "C:\safe\my_baseline.json"

  PRO TIP: Store the baseline somewhere DIFFERENT from the folder you're
  monitoring. If an attacker changes your files, you don't want them to be
  able to update the baseline too!


--------------------------------------------------------------------------------
  UNDERSTANDING THE COLOR-CODED OUTPUT
--------------------------------------------------------------------------------

  [GREEN]  [OK] UNCHANGED  C:\files\document.txt
             The file is exactly the same as in the baseline. Safe!

  [YELLOW] [+]  NEW        C:\files\suspicious_file.exe
             This file didn't exist when the baseline was created.
             Could be normal (you added something), or could be malware dropping files.

  [RED]    [!]  MODIFIED   C:\files\config.ini
                Baseline hash : abc123...
                Current hash  : xyz789...
             The file was changed! The hashes don't match.

  [RED]    [-]  DELETED    C:\files\important.txt
             This file was in the baseline but is gone now.
             Could be normal deletion, or could be evidence wiping.


--------------------------------------------------------------------------------
  EXIT CODES (FOR ADVANCED USERS)
--------------------------------------------------------------------------------

When you run the tool in --check mode:

  Exit code 0  = Everything matches the baseline. All clear!
  Exit code 1  = The tool itself had a problem (bad arguments, file errors).
  Exit code 2  = Integrity violations were found! Something changed.

This means you can use this tool in automated scripts, like:

  python file_integrity_monitor.py --dir C:\server --check
  if %errorlevel% == 2 (
      echo ALERT: Files have been tampered with!
  )


--------------------------------------------------------------------------------
  THE baseline.json FILE (WHAT'S INSIDE?)
--------------------------------------------------------------------------------

The baseline.json file is a plain text file you can open in Notepad. It looks
something like this:

  {
    "created_at": "2025-06-21T01:22:43",
    "file_count": 5,
    "hashes": {
      "C:\\test_files\\config.txt": "2cf24dba5fb0a30e26e83b2ac5b9e29...",
      "C:\\test_files\\readme.txt": "b94f6f125c79e3a5ffaa826f584c1...",
      ...
    },
    "target_directory": "C:\\test_files"
  }

  "created_at"       : The exact date and time the baseline was made
  "file_count"       : How many files were scanned
  "hashes"           : The big dictionary of file paths and their SHA-256 hashes
  "target_directory" : The folder that was scanned


--------------------------------------------------------------------------------
  REQUIREMENTS
--------------------------------------------------------------------------------

  * Python 3.6 or newer (download from https://www.python.org/)
  * NO extra packages needed — everything used is built into Python!
  * Works on Windows, macOS, and Linux


--------------------------------------------------------------------------------
  LIMITATIONS (THINGS TO KNOW)
--------------------------------------------------------------------------------

  * The tool compares file CONTENT (via hash), not file metadata like dates
    and permissions. A real enterprise FIM tool would track those too.

  * Files you don't have permission to read will be skipped with a warning.

  * The baseline.json itself is NOT monitored (to avoid false alarms).
    Always store your baseline somewhere safe and separate from what you monitor.

  * This is an educational tool. For protecting real servers, look into
    professional tools like Tripwire, OSSEC, Wazuh, or Windows File Integrity.


--------------------------------------------------------------------------------
  FUN EXPERIMENT TO TRY
--------------------------------------------------------------------------------

1. Create a folder called "test_fim" on your Desktop and put a few text files
   in it with some content.

2. Run: python file_integrity_monitor.py --dir "C:\Users\YourName\Desktop\test_fim" --baseline

3. Open one of the text files and change a word. Save it.
   Add a new text file.
   Delete one of the original text files.

4. Run: python file_integrity_monitor.py --dir "C:\Users\YourName\Desktop\test_fim" --check

5. See how the tool catches EVERY change you made — modified, new, and deleted!

That's exactly what security software does on real computers every day.


================================================================================
  Happy learning! You're now thinking like a cybersecurity analyst.
================================================================================


