import requests
import json
url = "https://gpt-api.hkust-gz.edu.cn/v1/chat/completions"
headers = { 
    "Content-Type": "application/json", 
    "Authorization": "Bearer 9b6ba9d51c3e49de96ca191ea549b13088a3c18d194d4268af25a084f5255a38" #Please change your KEY. If your key is XXX, the Authorization is "Authorization": "Bearer XXX"
}
data = { 
    "model": "DeepSeek-R1-671B", # # "gpt-3.5-turbo" version in gpt-4o-mini, "gpt-4" version in gpt-4o-2024-08-06
    "messages": [{"role": "user", "content": "This is a test."}], 
    "temperature": 0.7 
}
response = requests.post(url, headers=headers, data=json.dumps(data))
print(response.json())