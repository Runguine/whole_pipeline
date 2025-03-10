from openai import OpenAI
import config


APIKEY = config.APIKEY
BASEURL = config.BASEURL

client = OpenAI(
  base_url = "https://openrouter.ai/api/v1",
  api_key = "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",
)

PROMPT = "You are an expert in the field of blockchain and have a basic understanding of some well-known smart contract codes. You are skilled at analyzing the overall functionality of contracts through decompiled smart contract and providing code comments. You can also independently think about these codes and review whether there may be any bugs in them. Next, I will provide you with some decompiled Contract. Please derive the functions of this contract based on the content of these contracts, and help me annotate the code and explain the overall functionality."
decompile = ""


completion = client.chat.completions.create(
    model="deepseek/deepseek-r1-distill-llama-8b",,
    messages=[
      {
        "role": "system",
        "content": PROMPT+decompile
      }
    ]
)
print(completion.choices[0].message.content)

