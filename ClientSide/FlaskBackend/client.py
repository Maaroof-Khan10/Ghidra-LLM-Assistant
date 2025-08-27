import socket
import json
from flask import Flask
from flask_cors import CORS
from google import genai
from pydantic import BaseModel

HOST, PORT = '127.0.0.1', 42069
app = Flask(__name__)
CORS(app)

# Try connecting to ghidra
try:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
except:
    print("Unable to connect to ghidra, make sure the server is running")
    print("\nAfter running ghidra server, go to /reconnect to connect to it\n")

genClient = genai.Client()
model = "gemini-2.5-flash"

# Base models for structured output through gemini

class DecompFuncAnalysis(BaseModel):
    current_name: str
    potential_new_name: str
    functionality: str
    analysis_priority: int
    interesting_calls: list[str]


# Tools
def get_function_decompiled_tool(func_name):
    data = json.dumps({
        'toCall': "get_function_decompiled",
        "params": [str(func_name)]
    })
    client.sendall(data.encode("utf-8"))
    response = client.recv(65536).decode("utf-8")
    return json.loads(response)

# Endpoints

@app.route("/quit")
def quit_server():
    data = json.dumps({
        'toCall': "quit",
        'params': []
    })
    client.sendall(data.encode("utf-8"))
    response = client.recv(65536).decode("utf-8")
    return json.loads(response)

@app.route("/reconnect")
def reconnect():
    global client # Use global client to reconnect
    try:
        if client:
            client.close()
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, PORT))
        return {"message": "Reconnected successfully"}
    except:
        return {"message": "Unable to connect to ghidra or already connected, make sure the server is running"}

@app.route('/list_functions')
def list_functions():
    data = json.dumps({
        'toCall': "list_functions",
        'params': []
    })
    client.sendall(data.encode("utf-8"))
    response = client.recv(65536).decode("utf-8")
    return json.loads(response)

@app.route('/get_function_decompiled/<func_name>')
def get_function_decompiled(func_name):
    response = get_function_decompiled_tool(func_name)
    return response

@app.route('/analyze_function/<func_name>')
def analyze_function(func_name):
    data = get_function_decompiled_tool(func_name)
    prompt = f'''
        You are a expert reverse engineering assistant, the following function has been decompiled using ghidra into C:

        {data}
        Input format (JSON):
            current_name - The name of the function
            decompiled - The C code

        Output format (JSON):
            current_name - The current name as it is
            potential_new_name - New name based on the functionality of the function (If the function is "main", just return "main")
            functionality - A short one paragraph summary of what the function actually does
            analysis_priority - Give a score from 1 to 10 (Rating should be based on if the function contains the killswitch of a malware, API calls or other valuable information). Don't give a false high priority, make sure it deserves that number
            interesting_calls - A list of functions that the current function calls which might be interesting in finding (Killswitches, API calls, or other valuable information to analyse malware)
    '''
    response = genClient.models.generate_content(
        model=model,
        contents=prompt,
        config={
            'response_mime_type': "application/json",
            'response_schema': list[DecompFuncAnalysis]
        }
    )

    json_res = json.loads(response.text)

    return json_res[0]

if __name__ == '__main__':
    app.run()