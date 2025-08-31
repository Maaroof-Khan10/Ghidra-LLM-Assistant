import socket
import json
import os
from flask import Flask, request
from flask_cors import CORS
from google import genai
from pydantic import BaseModel

HOST, PORT = '127.0.0.1', 42069
app = Flask(__name__)
CORS(app)

analysis_storage = "analyzed.json" # The path where file it to be stored

# CRUD operations to store the analysis file

def load_data():
    if analysis_storage != "":
        if not os.path.exists(analysis_storage):
            with open(analysis_storage, "w") as file:
                json.dump([], file)
        with open(analysis_storage, "r") as file:
            return json.load(file)
        
def save_data(data):
    with open(analysis_storage, "w") as file:
        json.dump(data, file, indent=4)

def create(analysis_data):
    data = load_data()
    data.append(analysis_data)
    save_data(data)

def read_all():
    return load_data()

def read_by_entry(entry):
    data = load_data()
    return next((item for item in data if item.get("entry") == str(entry)), None)

def update_by_entry(entry, new_data):
    data = load_data()
    for i, item in enumerate(data):
        if item.get("entry") == str(entry):
            data[i].update(new_data)
            save_data(data)
            return True
    return False

def delete_by_entry(entry):
    data = load_data()
    new_data = [item for item in data if item.get("entry") != str(entry)]
    if len(new_data) != len(data):
        save_data(new_data)
        return True
    return False

def rename_json_function(entry, new_name):
    return update_by_entry(entry, {"current_name": new_name})



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
    entry: str
    current_name: str
    potential_new_name: str
    functionality: str
    analysis_priority: int
    interesting_calls: list[str]


# Tools

def get_function_decompiled_tool(addr):
    data = json.dumps({
        'toCall': "get_function_decompiled",
        "params": [str(addr)]
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

@app.route('/get_function_decompiled/<addr>')
def get_function_decompiled(addr):
    response = get_function_decompiled_tool(addr)
    return response

@app.route('/rename_function', methods=['POST'])
def rename_function():
    if request.method == "POST":
        json_data = request.get_json()
        addr = json_data.get("addr")
        new_name = json_data.get("new_name")
        data = json.dumps({
            'toCall': "rename_function",
            "params": [str(addr), str(new_name)]
        })
        client.sendall(data.encode('utf_8'))
        response = json.loads(client.recv(65536).decode("utf-8"))
        if response.get("message") == "Rename successful":
            print(rename_json_function(addr, new_name))
        return response
        

@app.route('/analyze_function', methods=['POST'])
def analyze_function():
    if request.method == "POST":
        data = request.get_json()
        addr = data.get("addr")
        additional_prompts = data.get("addPrompts")
        pre_analyzed = read_by_entry(addr)

        if pre_analyzed:
            return pre_analyzed
        else:

            if not addr or not additional_prompts:
                return {"error": "Missing funcName or addPrompts"}, 400
            
            decomp_data = get_function_decompiled_tool(addr)
            prompt = f'''
                You are a expert reverse engineering assistant, the following function has been decompiled using ghidra into C:

                {decomp_data}

                Input format (JSON):
                    entry - The address of the function in ghidra
                    current_name - The name of the function
                    decompiled - The C code

                Output format (JSON):
                    entry - The entry as it is exactly
                    current_name - The current name as it is
                    potential_new_name - New name based on the functionality of the function (If the function is "main", just return "main")
                    functionality - A short one paragraph summary of what the function actually does
                    analysis_priority - Give a score from 1 to 10 (Rating should be based on if the function contains the killswitch of a malware, API calls or other valuable information). Don't give a false high priority, make sure it deserves that number
                    interesting_calls - A list of functions that the current function calls which might be interesting in finding (Killswitches, API calls, or other valuable information to analyse malware)
                
                Additional Information:

                {additional_prompts}
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
            create(json_res[0])

            return json_res[0]

if __name__ == '__main__':
    app.run()