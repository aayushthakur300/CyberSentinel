import os
import google.generativeai as genai

# Setup API Key
api_key = os.environ.get("GEMINI_API_KEY")
if not api_key:
    print("❌ Error: GEMINI_API_KEY is not set.")
    exit()

genai.configure(api_key=api_key)

print("Checking available models for your API key...\n")

try:
    count = 0
    for m in genai.list_models():
        # We only care about models that support content generation
        if 'generateContent' in m.supported_generation_methods:
            print(f"✅ AVAILABLE: {m.name}")
            count += 1
    
    if count == 0:
        print("\n⚠️ No generative models found! Check if the 'Generative Language API' is enabled in your Google Cloud Console.")
        
except Exception as e:
    print(f"\n❌ Error listing models: {e}")
    print("Try updating your library: pip install --upgrade google-generativeai")