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

app.config["ANALYSIS_STORAGE"] = "analyzed.json" # The path where file it to be stored

# CRUD operations to store the analysis file

def load_data():
    analysis_storage = app.config["ANALYSIS_STORAGE"]
    if analysis_storage != "":
        if not os.path.exists(analysis_storage):
            with open(analysis_storage, "w") as file:
                json.dump([], file)
        with open(analysis_storage, "r") as file:
            return json.load(file)
        
def save_data(data):
    analysis_storage = storage = app.config["ANALYSIS_STORAGE"]
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

@app.route("/set_path", methods=["POST"])
def set_path():
    if request.method == 'POST':
        json_data = request.get_json()
        path = json_data.get("path")
        if not os.path.isdir(path):
            return {"message": "Path is invalid or does not exist"}, 400
        analysis_storage = os.path.join(path, "analyzed.json")
        app.config["ANALYSIS_STORAGE"] = analysis_storage
        return {"message": f"Path set successfully. Saved at {analysis_storage}"}

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
    response = json.loads(client.recv(65536).decode("utf-8"))
    for item in response: # If the function is already analyzed assign the priority
        check_exist = read_by_entry(item.get("entry"))
        if check_exist and "analysis_priority" in check_exist:
            item["analysis_priority"] = check_exist["analysis_priority"]
    return response

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

        if pre_analyzed and additional_prompts == "None":
            return pre_analyzed
        else:

            if not addr or not additional_prompts:
                return {"error": "Missing funcName or addPrompts"}, 400
            
            decomp_data = get_function_decompiled_tool(addr)
            prompt = f'''
            You are an expert reverse-engineering assistant. The following function was
            decompiled with Ghidra into C:

            {decomp_data}

            Input (JSON):
            entry         - address of the function in Ghidra
            current_name  - function name
            decompiled    - the C code

            Output (JSON):
            entry
            current_name
            potential_new_name - new name based on functionality (return "main" if main)
            functionality       - one short paragraph summary
            analysis_priority   - integer 0-10 (see Priority rules)
            interesting_calls   - ordered list of called functions (most → least important)

            Priority rules (0–10):
            +2  if main or central to program
            +1  if function calls other functions
            +1  if it calls any "interesting" function (killswitch/API/etc.)
            +1  if function contains strings or URLs (plain or obfuscated)
            +1  if function returns a value
            +1  if intentionally obfuscated
            +3  if function can act as a killswitch or makes an API call

            Additional information:
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
            if additional_prompts != "None" and pre_analyzed:
                update_by_entry(addr, json_res[0])
            else:
                create(json_res[0])

            return json_res[0]

if __name__ == '__main__':
    app.run()