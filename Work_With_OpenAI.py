"""OpenAI API learning exercises.

This file is organized into small, readable examples. Each example shows a different
OpenAI use case and can be run independently.

Before running the examples, set your API key in the environment:
    export OPENAI_API_KEY="your-api-key"

or replace the placeholder in get_client().
"""

import os

from openai import OpenAI


def get_client() -> OpenAI:
    """Create and return an OpenAI client using the environment variable."""
    api_key = os.getenv("OPENAI_API_KEY") or "<OPENAI_API_TOKEN>"
    return OpenAI(api_key=api_key)


def print_text(response) -> None:
    """Print the model's text response clearly."""
    print(response.choices[0].message.content)


# ---------------------------------------------------------------------------
# 1. Introduction
# ---------------------------------------------------------------------------

def intro_example() -> None:
    """Basic Chat Completions request."""
    client = get_client()

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "user",
                "content": "Write a polite reply accepting an AI Engineer job offer.",
            }
        ],
    )

    print("--- Intro Example ---")
    print_text(response)


# ---------------------------------------------------------------------------
# 2. Prompting and text transformation
# ---------------------------------------------------------------------------

def text_editing_example() -> None:
    """Rewrite a paragraph by replacing terms and adjusting wording."""
    client = get_client()

    prompt = """Replace car with plane and adjust phrase:
A car is a vehicle that is typically powered by an internal combustion engine or an electric motor. It has four wheels, and is designed to carry passengers and/or cargo on roads or highways. Cars have become a ubiquitous part of modern society, and are used for a wide variety of purposes, such as commuting, travel, and transportation of goods. Cars are often associated with freedom, independence, and mobility."""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_completion_tokens=100,
    )

    print("--- Text Editing Example ---")
    print_text(response)


def text_summarization_example() -> None:
    """Summarize a finance paragraph into two concise bullet points."""
    client = get_client()

    finance_text = """The global financial markets have experienced significant volatility in recent months, driven by a combination of geopolitical tensions, economic uncertainty, and shifts in investor sentiment. Central banks around the world have been adjusting interest rates in response to inflationary pressures, while governments have implemented various fiscal policies to stimulate growth. Investors are closely monitoring corporate earnings reports, as well as macroeconomic indicators such as employment data and consumer spending trends, to gauge the health of the economy and make informed investment decisions."""

    prompt = f"""Summarize the following text into two concise bullet points:
{finance_text}"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_completion_tokens=400,
    )

    print("--- Text Summarization Example ---")
    print_text(response)


def cost_estimation_example() -> None:
    """Estimate API cost using token usage from a response."""
    client = get_client()

    prompt = """Summarize the following text into two concise bullet points:
The global financial markets have experienced significant volatility in recent months, driven by a combination of geopolitical tensions, economic uncertainty, and shifts in investor sentiment."""

    max_completion_tokens = 100
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_completion_tokens=max_completion_tokens,
    )

    input_token_price = 0.15 / 1_000_000
    output_token_price = 0.6 / 1_000_000

    input_tokens = response.usage.prompt_tokens
    output_tokens = response.usage.completion_tokens
    cost = (input_tokens * input_token_price) + (output_tokens * output_token_price)

    print("--- Cost Estimation Example ---")
    print(f"Estimated cost: ${cost:.8f}")


def prompt_creation_example() -> None:
    """Generate a product description prompt for a headphone product."""
    client = get_client()

    prompt = """
Create a detailed prompt to generate a product description for SonicPro headphones, including:
- Active noise cancellation (ANC)
- 40-hour battery life
- Foldable design
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_completion_tokens=400,
        temperature=0,
    )

    print("--- Prompt Creation Example ---")
    print_text(response)


def few_shot_prompting_example() -> None:
    """Use a few-shot example to classify sentiment with a pattern."""
    client = get_client()

    prompt = """Classify sentiment as 1-5 (negative to positive):
1. Comfortable, but not very pretty = 2
2. Love these! = 5
3. Unbelievably good! = 
4. Shoes fell apart on the second use. = 
5. The shoes look nice, but they aren't very comfortable. = 
6. Can't wait to show them off! = """

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        max_completion_tokens=100,
    )

    print("--- Few-Shot Prompting Example ---")
    print_text(response)


# ---------------------------------------------------------------------------
# 3. Conversations and system messages
# ---------------------------------------------------------------------------

def system_message_example() -> None:
    """Use a system prompt to keep the model within a behavior guardrail."""
    client = get_client()

    system_message = """You are a study planning assistant that creates plans for learning new skills.

If the skill is not related to languages, return this exact message:
'Apologies, to focus on languages, we no longer create learning plans on other topics.'
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": "Help me learn Chinese."},
        ],
    )

    print("--- System Message Example ---")
    print_text(response)


def assistant_memory_example() -> None:
    """Add assistant messages to provide in-context examples."""
    client = get_client()

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a helpful Geography tutor that generates concise summaries for different countries.",
            },
            {"role": "user", "content": "Give me a quick summary of Portugal."},
            {
                "role": "assistant",
                "content": "Portugal is a country in Europe that borders Spain. The capital city is Lisboa.",
            },
            {"role": "user", "content": "Give me a quick summary of Greece."},
        ],
    )

    print("--- Assistant Memory Example ---")
    print_text(response)


def multi_turn_conversation_example() -> None:
    """Create a short multi-turn conversation that keeps context across messages."""
    client = get_client()

    messages = [{"role": "system", "content": "You are a helpful math tutor that speaks concisely."}]
    user_msgs = ["Explain what pi is.", "Summarize this in two bullet points."]

    for question in user_msgs:
        print(f"User: {question}")
        messages.append({"role": "user", "content": question})

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_completion_tokens=100,
        )

        answer = response.choices[0].message.content
        messages.append({"role": "assistant", "content": answer})
        print(f"Assistant: {answer}\n")


# ---------------------------------------------------------------------------
# Run the examples
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Uncomment the examples you want to run.
    intro_example()
    text_editing_example()
    text_summarization_example()
    cost_estimation_example()
    prompt_creation_example()
    few_shot_prompting_example()
    system_message_example()
    assistant_memory_example()
    multi_turn_conversation_example()










