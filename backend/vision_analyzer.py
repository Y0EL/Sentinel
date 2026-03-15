import openai
import os
import base64
from dotenv import load_dotenv

load_dotenv()

# Configure OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

class VisionAnalyzer:
    def __init__(self):
        self.model = "gpt-4.1-nano"  # Latest OpenAI vision model

    def analyze_image(self, image_path, prompt):
        if not os.path.exists(image_path):
            return {"error": "Image file not found"}
        
        try:
            # Read and encode image
            with open(image_path, "rb") as image_file:
                base64_image = base64.b64encode(image_file.read()).decode('utf-8')
            
            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{base64_image}"
                                }
                            }
                        ]
                    }
                ],
                max_tokens=1000
            )
            
            return {
                "analysis": response.choices[0].message.content,
                "status": "success"
            }
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    # analyst = VisionAnalyzer()
    # print(analyst.analyze_image("path/to/image.png", "Extract IP addresses and describe the activity."))
    pass
