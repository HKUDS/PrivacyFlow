from openai import OpenAI


client = OpenAI(base_url="http://localhost:8765/v1", api_key="apg-local")

response = client.chat.completions.create(
    model="gpt-4.1-mini",
    messages=[
        {"role": "user", "content": "My email is alice@example.test and my key is sk-example-abcdefghijklmnopqrstuvwxyz123456."}
    ],
)

print(response.choices[0].message.content)
