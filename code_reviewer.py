from tkinter import Tk, filedialog
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

print("===== AI CODE REVIEW AGENT =====")
root = Tk()
root.withdraw()

file_path = filedialog.askopenfilename(
    title="Select Python File",
    filetypes=[("Python files", "*.py")]
)

if file_path:
    with open(file_path, "r") as file:
        code = file.read()
else:
    print("No file selected.")
    exit()
response = client.chat.completions.create(
    model="openai/gpt-oss-120b",
    messages=[
        {
            "role": "user",
            "content": f"""
You are a Python code review agent.

Review the following Python code.

Identify:
1. Bugs
2. Errors or problems
3. Suggestions for improvement
4. A corrected version if necessary

Explain everything in a beginner-friendly way.

Python code:

{code}
"""
        }
    ]
)

print("\n===== CODE REVIEW =====")
print(response.choices[0].message.content)
print("=======================")