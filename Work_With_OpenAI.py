# Introduction to the OpenAI API

from openai import OpenAI

# Create the OpenAI client
client = OpenAI(api_key="<OPENAI_API_TOKEN>")

# Create a request to the Chat Completions endpoint
response = client.chat.completions.create(
  model="gpt-4o-mini",
  messages=[
    {"role": "user", 
     "content": "Write a polite reply accepting an AI Engineer job offer."}]
)

print(response)
print(response.choices[0].message.content)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Prompting OpenAI Models
"""Text Editing with OpenAI API"""

client = OpenAI(api_key="<OPENAI_API_TOKEN>")

prompt="""Replace car with plane and adjust phrase:
A car is a vehicle that is typically powered by an internal combustion engine or an electric motor. It has four wheels, and is designed to carry passengers and/or cargo on roads or highways. Cars have become a ubiquitous part of modern society, and are used for a wide variety of purposes, such as commuting, travel, and transportation of goods. Cars are often associated with freedom, independence, and mobility."""

# Create a request to the Chat Completions endpoint
response = client.chat.completions.create(
  model="gpt-4o-mini",
  messages=[{"role": "user", "content": prompt}],
  max_completion_tokens=100
)

# Extract and print the response text
print(response.choices[0].message.content)



"""Text Summarization with OpenAI API"""

client = OpenAI(api_key="<OPENAI_API_TOKEN>")
finance_text = """The global financial markets have experienced significant volatility in recent months, driven by a combination of geopolitical tensions, economic uncertainty, and shifts in investor sentiment. Central banks around the world have been adjusting interest rates in response to inflationary pressures, while governments have implemented various fiscal policies to stimulate growth. Investors are closely monitoring corporate earnings reports, as well as macroeconomic indicators such as employment data and consumer spending trends, to gauge the health of the economy and make informed investment decisions."""
# Use an f-string to format the prompt
prompt = f"""Summarize the following text into two concise bullet points:
{finance_text}"""

# Create a request to the Chat Completions endpoint
response = client.chat.completions.create(
  model="gpt-4o-mini",
  messages=[{"role": "user", "content": prompt}],
  max_completion_tokens=400
)

print(response.choices[0].message.content)

# Tokens are units of text that help the AI understand and interpret the input. The number of tokens in a prompt can affect the cost and performance of the API call.
"""Token Counting and Cost Estimation with OpenAI API"""

client = OpenAI(api_key="<OPENAI_API_TOKEN>")
max_completion_tokens = 100
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": prompt}],
    max_completion_tokens=max_completion_tokens
)

input_token_price = 0.15 / 1_000_000
output_token_price = 0.6 / 1_000_000

# Extract token usage
input_tokens = response.usage.prompt_tokens
output_tokens = max_completion_tokens
# Calculate cost
cost = (input_tokens * input_token_price + output_tokens * output_token_price)
print(f"Estimated cost: ${cost}")
