import json
import os
import requests
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise ValueError("Missing GROQ_API_KEY. Please set it in your .env file.")

client = Groq(api_key=api_key)

# 1. Live Weather Function (Open-Meteo - 100% Free, No Key Needed)
def get_current_weather(location: str):
    try:
        # Step A: Convert city name to latitude & longitude
        geo_url = f"https://geocoding-api.open-meteo.com/v1/search?name={location}&count=1&language=en&format=json"
        geo_res = requests.get(geo_url, timeout=5).json()

        if not geo_res.get("results"):
            return json.dumps({"error": f"Could not find coordinates for '{location}'."})

        place = geo_res["results"][0]
        lat, lon = place["latitude"], place["longitude"]
        city_name = place["name"]
        country = place.get("country", "")

        # Step B: Fetch real-time weather
        weather_url = (
            f"https://api.open-meteo.com/v1/forecast?"
            f"latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,wind_speed_10m"
        )
        weather_res = requests.get(weather_url, timeout=5).json()
        current = weather_res.get("current", {})

        return json.dumps({
            "location": f"{city_name}, {country}",
            "temperature_celsius": current.get("temperature_2m"),
            "apparent_temp_celsius": current.get("apparent_temperature"),
            "humidity_percent": current.get("relative_humidity_2m"),
            "wind_speed_kmh": current.get("wind_speed_10m"),
            "precipitation_mm": current.get("precipitation"),
        })
    except Exception as e:
        return json.dumps({"error": f"Failed to retrieve weather data: {str(e)}"})


# 2. Tool Definition for the LLM
tools = [
    {
        "type": "function",
        "function": {
            "name": "get_current_weather",
            "description": "Fetch real-time current weather metrics for any given city or country.",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "The city and country name, e.g., 'Singapore', 'London', 'Tokyo'.",
                    }
                },
                "required": ["location"],
            },
        },
    }
]

# Map available tools
available_functions = {
    "get_current_weather": get_current_weather
}

# 3. Main Chat Loop
conversation_history = [
    {
        "role": "system",
        "content": "You are a helpful assistant. When asked about current conditions or weather, use the get_current_weather tool to fetch live data."
    }
]

print("--- AI Chatbot with Live Weather Ready! (Type 'quit' to exit) ---\n")

while True:
    try:
        user_input = input("You: ").strip()
        if not user_input:
            continue
        if user_input.lower() in ["exit", "quit", "q"]:
            print("Chatbot: Goodbye!")
            break

        conversation_history.append({"role": "user", "content": user_input})

        # Ask model (checks if it wants to call a tool)
        response = client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=conversation_history,
            tools=tools,
            tool_choice="auto",
            temperature=0.3,
        )

        response_message = response.choices[0].message

        # Check if the model called a function
        if response_message.tool_calls:
            # Append model's tool call intent to context
            conversation_history.append(response_message)

            for tool_call in response_message.tool_calls:
                func_name = tool_call.function.name
                func_args = json.loads(tool_call.function.arguments)

                print(f"[Calling weather tool for: {func_args.get('location')}...]")
                
                func_to_call = available_functions[func_name]
                tool_output = func_to_call(location=func_args.get("location"))

                # Provide tool output back to the model
                conversation_history.append({
                    "tool_call_id": tool_call.id,
                    "role": "tool",
                    "name": func_name,
                    "content": tool_output,
                })

            # Get final answer incorporating the tool output
            second_response = client.chat.completions.create(
                model="openai/gpt-oss-20b",
                messages=conversation_history,
                temperature=0.5,
            )
            final_reply = second_response.choices[0].message.content
            print(f"AI: {final_reply}\n")
            conversation_history.append({"role": "assistant", "content": final_reply})

        else:
            # Standard conversational reply
            reply = response_message.content
            print(f"AI: {reply}\n")
            conversation_history.append({"role": "assistant", "content": reply})

    except KeyboardInterrupt:
        print("\nExiting...")
        break
    except Exception as e:
        print(f"\n[Error]: {e}\n")