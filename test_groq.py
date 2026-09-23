import os
from groq import Groq

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

code = """
def add(a, b):
    print(a)
    return a - b
"""

response = client.chat.completions.create(
    model="openai/gpt-oss-120b",
    messages=[
        {
            "role": "user",
            "content": f"Review this Python code and tell me what is wrong with it:\n\n{code}"
        }
    ]
)

print(response.choices[0].message.content)