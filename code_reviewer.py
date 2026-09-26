import os
from tkinter import Tk, filedialog
from dotenv import load_dotenv
from groq import Groq


# Load API key from .env file
load_dotenv()

api_key = os.environ.get("GROQ_API_KEY")

if not api_key:
    print("ERROR: GROQ_API_KEY was not found.")
    print("Please check your .env file.")
    exit()


# Create Groq client
client = Groq(api_key=api_key)


print("======================================")
print("       AI CODE REVIEW AGENT")
print("======================================")
print()


# Open file selection window
root = Tk()
root.withdraw()

file_path = filedialog.askopenfilename(
    title="Select Python File",
    filetypes=[
        ("Python files", "*.py"),
        ("All files", "*.*")
    ]
)

# Check if a file was selected
if not file_path:
    print("No file selected.")
    exit()


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
    exit()


# Check if the file is empty
if not code.strip():
    print("The selected file is empty.")
    exit()


print("Reviewing your code...")
print("Please wait...")
print()


# Ask Groq to review the code
try:
    response = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[
            {
                "role": "system",
                "content": """
You are an AI Code Review Agent.

Your job is to carefully review the provided source code.

Give a clear and beginner-friendly review.

Organize your response using exactly these sections:

1. BUGS
Identify actual bugs or incorrect behavior.

2. CODE QUALITY
Identify problems related to readability, structure, naming,
unnecessary code, documentation, and maintainability.

3. SECURITY
Identify possible security problems.
If there are no obvious security problems, say so.

4. PERFORMANCE
Identify possible performance problems.
If there are no obvious performance problems, say so.

5. SUGGESTIONS
Give practical suggestions for improving the code.

6. CORRECTED CODE
Provide a corrected version of the code when changes are necessary.
If no correction is necessary, explain why.

Important:
- Do not invent bugs that are not present.
- Clearly distinguish actual bugs from optional improvements.
- Explain important problems in simple language.
- Focus on the code provided.
"""
            },
            {
                "role": "user",
                "content": f"""
Review this Python file.

File name:
{file_name}

Code:

{code}
"""
            }
        ]
    )

    review = response.choices[0].message.content

except Exception as e:
    print("Error while communicating with Groq:")
    print(e)
    exit()


# Display review
print("======================================")
print("           CODE REVIEW")
print("======================================")
print()

print("File:", file_name)
print()
print(review)

print()
print("======================================")