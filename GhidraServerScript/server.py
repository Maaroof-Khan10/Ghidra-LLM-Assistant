# A server to integrate ghidra tools with external tools
# @category Python 3

import socket
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

HOST, PORT = '127.0.0.1', 42069 # To create socket
program = currentProgram()
fm = program.getFunctionManager() # Function manager is the bridge that allows all our tools (List, Decompile, Rename)
symbolTable = program.getSymbolTable() # To lookup function names and addresses
decompiler = DecompInterface()
decompiler.openProgram(program)

# Tools go here
def list_functions():
    # Gets every function in the program
    funcs = []
    for func in fm.getFunctions(True):
        funcs.append({
            "name": func.getName(),
            "entry": str(func.getEntryPoint()), # The address needs to be string
            "analysis_priority": 0 # By default the priority will be zero before it gets analyzed
        })
    return funcs

def get_function_decompiled(func_name):
    # Returns decompiled code for a specific functions
    symbols = symbolTable.getSymbols(func_name) # Get the function from the symbol table
    # Set to none
    output = None
    func = None

    if symbols is None:
        output = {"message": "The function does not exist"}
    else:
        for symbol in symbols:
            print(f"Symbol: {symbol}, Type: {symbol.getSymbolType().toString()} to decompile")
            if symbol.getSymbolType().toString() == "Function":
                func = fm.getFunctionAt(symbol.getAddress())
                break
        if func is not None:
            decompFun = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor()) # Decompile the function with a 60 second timeout
            if decompFun.decompileCompleted():
                c_code = decompFun.getDecompiledFunction().getC()
                output = {
                    "current_name": func_name,
                    "decompiled": c_code
                }
            else:
                output = {"message": "Decompilation failed", "error": decompFun.getErrorMessage()}
        else:
            output = {"message": "The function does not exist"}

    return output

functionMap = {
    "list_functions": list_functions,
    "get_function_decompiled": get_function_decompiled
}

# Creating and binding server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Server started listening.....")

# Connection handling
while True:
    conn, addr = server.accept()
    print(f"{addr} is connnected")
    with conn:
        while True: # To keep persistant connection
            data = conn.recv(4096).decode("utf-8").strip()
            if not data:
                break
            data = json.loads(data)
            toCall = data["toCall"]
            params = data["params"]
            if toCall == "quit":
                conn.sendall(json.dumps({"message": "Server shutdown"}).encode("utf-8"))
                print("Shutting down server")
                conn.close()
                server.close()
                exit()
            if toCall in functionMap:
                output = functionMap[toCall](*params)
            else:
                output = {"message": "Function does not exist"}
            conn.sendall(json.dumps(output).encode("utf-8"))