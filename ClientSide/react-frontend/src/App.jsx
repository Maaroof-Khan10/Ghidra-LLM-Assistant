import React, {useRef, useState, useEffect} from 'react';
import axios from 'axios';
import {Prism as SyntaxHighlighter} from "react-syntax-highlighter";
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

const api = axios.create({
  baseURL: "http://localhost:5000/"
})

function App() {
  const [path, setPath] = useState("");
  const [funcList, setFuncList] = useState([]);
  const [decomp, setDecomp] = useState({});
  const [loadedDecomp, setLoadingDecomp] = useState(false);
  const [addPrompts, setAddPrompts] = useState("");
  const [loadedAnalysis, setLoadedAnalysis] = useState(false);
  const [analysisData, setAnalysisData] = useState({});
  const [newName, setNewName] = useState("");

  const getList = async () => {
    try {
      let res = await api.get("/list_functions");

      const sorted = res.data.sort(
        (a, b) => b.analysis_priority - a.analysis_priority
      );

      setFuncList(sorted);
    } catch (err) {
      console.error("Error fetching functions, make sure flask server is running:", err);
    }
  }

  useEffect(() => {
    // Keeping the path persistant using localStorage
    try {
      const savedPath = localStorage.getItem("analysisPath");
      if (savedPath) {
        setPath(savedPath);
      }
    } catch (err) {
      console.error("Error reading path from local storage:", err);
    }
    // Fetching functions
    getList();
  }, [])
  
  // Keeping the path persistant using localStorage
  useEffect(() => {
    try {
      if (path) {
        localStorage.setItem("analysisPath", path);
      }
    } catch (err) {
      console.error("Error saving path to localStorage:", err);
    }
  }, [path])

  const set_path = async () => {
    try {
      if (path !== "") {
        let data = {
          path: path
        }
        let res = await api.post("/set_path", data)
        console.log(res.data);
        getList();
      }
    } catch (err) {
      console.error("Error setting path:", err);
    }
  }

  const getDecomp = async (addr) => {
    try {
      let res = await api.get("/get_function_decompiled/" + addr)
      setDecomp(res.data);
      setLoadingDecomp(true);
      setLoadedAnalysis(false);
      setAnalysisData({})
      setNewName("")
    } catch (err) {
      console.error("Error in decompiling, make sure flask and ghidra servers are running:", err);
    }
  }

  const analyzeDecomp = async () => {
    try {
        let data = {
        addr: decomp.entry,
        addPrompts: "None"
      }
      if (addPrompts !== "") {
        data.addPrompts = addPrompts
      }
      let res = await api.post('/analyze_function', data);
      getList();
      setAnalysisData(res.data);
      setNewName(res.data.potential_new_name)
      setLoadedAnalysis(true);
    } catch (err) {
      console.error("Error in analysis, make sure the flask server, ghidra server are running and API key + Path are proper:", err);
    }
  }

  const quitConn = async () => {
    try {
      let res = await api.get("/quit")
      console.log(res.data);
    } catch (err) {
      console.error("Error quitting, make sure the flask server and ghidra server are running:", err);
    }
  }

  const reconnect = async () => {
    try {
      let res = await api.get("/reconnect")
      console.log(res.data);
    } catch (err) {
      console.error("Error reconnecting, make sure the flask server and ghidra server are running:", err);
    }
  }

  const rename = async () => {
    try {
      let data = {
        addr: analysisData.entry,
        new_name: newName
      }
      if (newName === "") {
        data.new_name = analysisData.potential_new_name;
      }
      let res = await api.post('/rename_function', data);
      console.log(res.data);
      let newDecomp = decomp.decompiled.replaceAll(decomp.current_name, newName);
      setDecomp(prevData => ({
        ...prevData,
        current_name: data.new_name,
        decompiled: newDecomp
      }))
      setAnalysisData(prevData => ({
        ...prevData,
        current_name: data.new_name
      }))
      getList();
    } catch (err) {
      console.error("Error renaming function, make sure the flask server and ghidra server are running:", err);
    }
  }

  return (
    <div className="flex flex-col">
      <nav className='flex h-15 bg-gray-900 text-white px-5 py-3 justify-between sticky top-0'>
        <div className='flex items-center text-xl'>
          <span className='font-semibold'>DragonAttack</span>
        </div>
        <div className='flex items-center gap-x-5 w-1/2'>
          <input 
          placeholder='Enter the path to store the analysis data' 
          value={path} 
          onChange={(e) => {setPath(e.target.value)}}
          className='w-full h-10 bg-amber-50 text-gray-900 rounded-lg px-2'
          />
        </div>
        <div className="flex justify-center gap-5">
          <button onClick={() => {set_path()}}>Set Path</button>
          <button onClick={() => {reconnect()}}>Reconnect</button>
          <button onClick={() => {quitConn()}}>Quit</button>
        </div>
      </nav>
      <div className='flex'>
        <div className="w-80 h-[calc(100vh-50px)] bg-gray-800 text-white px-4 py-2 overflow-y-scroll scrollbar">
          <div className='my-2 mb-4'>
            <h1 className='text-2xl font-bold'>Functions available</h1>
          </div>
          <hr />
          <ul className='mt-3 font-bold text-balance'>
            {funcList.map((func) => (
              <li 
              key={func.entry} 
              onClick={() => {getDecomp(func.entry)}}
              className='mb-2 rounded hover:shadow hover:bg-blue-400 py-2 px-3 text-wrap overflow-x-clip'
              >
                {func.name} - {func.entry} - {func.analysis_priority}
              </li>
            ))}
          </ul>
        </div>
        <div className='flex flex-col mx-2 my-5 gap-y-10 w-full overflow-y-scroll h-[calc(100vh-90px)] scrollbar'>
            {loadedDecomp && decomp.current_name && (
              <div className='flex flex-col p-5 py-8 bg-gray-800 rounded-lg'>
                <div className='flex justify-between items-center mb-3'>
                  <h1 className='text-3xl'>{decomp.current_name}</h1>
                  <p className='text-2xl'>Ghidra Address: {decomp.entry}</p>
                  <button onClick={() => {analyzeDecomp()}} className='text-xl bg-blue-500 w-1/6 p-3 rounded-lg hover:shadow-xl/20 hover:bg-blue-400'>Analyze</button>
                </div>
                <div>
                  <SyntaxHighlighter
                    language="c"
                    style={vscDarkPlus}
                    customStyle={{
                      backgroundColor: "#101828",
                      borderRadius: "0.5rem",
                      padding: "1rem",
                      fontSize: "0.875rem"
                    }}
                  >
                    {decomp.decompiled}
                  </SyntaxHighlighter>
                </div>
                <div className='flex flex-col my-2'>
                  <h1 className='text-xl my-1'>Additional Prompts:</h1>
                  <textarea className='bg-gray-900 outline-blue-900 rounded-md p-2' value={addPrompts} onChange={e => {setAddPrompts(e.target.value)}}></textarea>
                </div>
              </div>
            )}
            {loadedAnalysis && (
              <div className='flex flex-col p-5 py-8 bg-gray-800 rounded-lg'>
                <h1 className='text-2xl'>Gemini Analysis</h1>
                <hr className='my-2'/>
                <div className='flex'>
                  <h2 className='text-xl'>Priority: {analysisData.analysis_priority}</h2>
                </div>
                <div className='flex justify-between'>
                  <h3 className='text-xl w-1/2'>Potential new name:</h3>
                  <div className='flex justify-around w-1/2'>
                    <input className='bg-gray-900 outline-blue-900 rounded-md p-1.5 w-3/4' placeholder="Any name you like" value={newName} onChange={e => {setNewName(e.target.value)}}></input>
                    <button className='bg-blue-500 w-1/5 p-1.5 rounded-lg hover:shadow-xl/20 hover:bg-blue-400' onClick={() => rename()}>Rename</button>
                  </div>
                </div>
                <div className='flex flex-col my-2 gap-y-2'>
                  <h3 className='text-xl'>Functionality</h3>
                  <p className='bg-gray-900 p-2 rounded-lg'>{analysisData.functionality}</p>
                </div>
                <div className='flex flex-col my-2 gap-y-2'>
                  <h3 className='text-xl'>Interesting function calls</h3>
                  <div className='bg-gray-900 p-2 px-5 rounded-lg '>
                    <ul className='list-disc list-inside'>
                      {analysisData.interesting_calls.map((func) => (
                        <li className='text-balance' key={func}>{func}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}
        </div>
      </div>
    </div>
  );
}

export default App;
