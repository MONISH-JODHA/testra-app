import google.generativeai as genai
import os
from dotenv import load_dotenv # Import

load_dotenv() # Load variables from .env file

# Configure API Key (same as in your app)
api_key = os.getenv('GOOGLE_API_KEY') # Now it should find it
if api_key:
    genai.configure(api_key=api_key)
    print("Available Models:")
    try: # Add try/except for listing models too
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                print(f"- {m.name} (Supports generateContent)")
    except Exception as e:
        print(f"Error listing models: {e}")
else:
    print("API Key not found (checked environment variables after attempting to load .env).")