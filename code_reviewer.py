"""AI CODE REVIEW AGENT - CLI / Tkinter Entry Point.

Backward-compatible entry point enhanced with the CodeReviewAgent 2.0 modular engine,
static analyzers, risk scoring, and persistent scan storage.
"""

import os
import sys
from dotenv import load_dotenv

# Load environment
load_dotenv()

from codereview.models import Severity
from codereview.providers.groq_provider import GroqAIProvider
from codereview.providers.mock_provider import MockAIProvider
from codereview.scanners.engine import ReviewEngine
from codereview.storage.db import ScanStorage

api_key = os.environ.get("GROQ_API_KEY")

print("======================================")
print("       AI CODE REVIEW AGENT")
print("======================================")
print()

# Determine target file either from argument or Tkinter file dialog
file_path = None
if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
    file_path = sys.argv[1]
else:
    try:
        from tkinter import Tk, filedialog
        root = Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename(
            title="Select Python File",
            filetypes=[
                ("Python files", "*.py"),
                ("All files", "*.*")
            ]
        )
    except Exception as e:
        print(f"File dialog unavailable: {e}")
        file_path = input("Enter path to Python file to review: ").strip()

# Check if a file was selected
if not file_path:
    print("No file selected.")
    sys.exit(0)

# Get file name
file_name = os.path.basename(file_path)
print("Selected file:", file_name)
print()

# Read the selected Python file
try:
    with open(file_path, "r", encoding="utf-8") as file:
        code = file.read()
except Exception as e:
    print("Error reading the file:")
    print(e)
    sys.exit(1)

# Check if the file is empty
if not code.strip():
    print("The selected file is empty.")
    sys.exit(0)

print("Reviewing your code...")
print("Running static analyzers and AI review...")
print("Please wait...")
print()

# Initialize AI provider
ai_provider = None
if api_key:
    try:
        ai_provider = GroqAIProvider(api_key=api_key)
    except Exception as e:
        print(f"Warning: Could not initialize Groq provider ({e}). Falling back to static review.")
else:
    print("Note: GROQ_API_KEY not found. Running in static analysis mode.")

# Run review engine
engine = ReviewEngine(ai_provider=ai_provider)
scan_result = engine.review_file(
    filename=file_path,
    code=code,
    use_ai=(ai_provider is not None),
    target_type="local_file",
    target_identifier=file_name,
)

# Persist scan to database
try:
    storage = ScanStorage()
    storage.save_scan(scan_result)
except Exception as db_err:
    print(f"Warning: Could not persist scan to database: {db_err}")

# Display review
print("======================================")
print("           CODE REVIEW")
print("======================================")
print()
print("File:", file_name)
print(f"Risk Score: {scan_result.metadata.risk_score}/100 ({scan_result.metadata.risk_level})")
print(f"Total Findings: {len(scan_result.findings)}")
print()

if not scan_result.findings:
    print("No bugs, security issues, or code quality problems found. Excellent work!")
else:
    # Organize output into standard sections
    bugs = [f for f in scan_result.findings if f.category.value == "BUG"]
    quality = [f for f in scan_result.findings if f.category.value == "CODE_QUALITY"]
    security = [f for f in scan_result.findings if f.category.value == "SECURITY"]
    performance = [f for f in scan_result.findings if f.category.value == "PERFORMANCE"]

    print("1. BUGS")
    if bugs:
        for b in bugs:
            print(f"- [Line {b.line_number}] {b.rule_id}: {b.message}")
            if b.explanation:
                print(f"  Explanation: {b.explanation}")
    else:
        print("No actual bugs detected.")
    print()

    print("2. CODE QUALITY")
    if quality:
        for q in quality:
            print(f"- [Line {q.line_number}] {q.rule_id}: {q.message}")
            if q.explanation:
                print(f"  Explanation: {q.explanation}")
    else:
        print("Code structure and maintainability look good.")
    print()

    print("3. SECURITY")
    if security:
        for s in security:
            print(f"- [{s.severity.value}] [Line {s.line_number}] {s.rule_id}: {s.message}")
            if s.explanation:
                print(f"  Explanation: {s.explanation}")
    else:
        print("No obvious security problems detected.")
    print()

    print("4. PERFORMANCE")
    if performance:
        for p in performance:
            print(f"- [Line {p.line_number}] {p.rule_id}: {p.message}")
    else:
        print("No obvious performance bottlenecks detected.")
    print()

    print("5. SUGGESTIONS")
    suggestions = [f.suggestion for f in scan_result.findings if f.suggestion]
    if suggestions:
        for s in suggestions[:5]:
            print(f"- {s}")
    else:
        print("Continue following PEP 8 conventions and writing unit tests.")
    print()

    print("6. SUMMARY & SCAN ID")
    print(f"Scan ID: {scan_result.metadata.scan_id}")
    print("View and compare full results in the web dashboard by running: streamlit run app.py")

print()
print("======================================")