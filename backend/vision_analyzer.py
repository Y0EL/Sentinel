import google.generativeai as genai
import os
from PIL import Image
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

class VisionAnalyzer:
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-1.5-pro')

    def analyze_image(self, image_path, prompt):
        if not os.path.exists(image_path):
            return {"error": "Image file not found"}
        
        try:
            img = Image.open(image_path)
            response = self.model.generate_content([prompt, img])
            return {
                "analysis": response.text,
                "status": "success"
            }
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    # analyst = VisionAnalyzer()
    # print(analyst.analyze_image("path/to/image.png", "Extract IP addresses and describe the activity."))
    pass
