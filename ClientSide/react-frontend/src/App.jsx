import React, {useRef, useState, useEffect} from 'react';
import axios from 'axios';

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
    <div className="App">
      <div className='nav'>
        <input placeholder='Enter the path to store the analysis data' value={path} onChange={(e) => {setPath(e.target.value)}}></input>
        <button onClick={() => {set_path()}}>Set Path</button>
        <button onClick={() => {reconnect()}}>Reconnect</button>
        <button onClick={() => {quitConn()}}>Quit</button>
      </div>
      <div className="sidebar">
        <ul>
          {funcList.map((func) => (
            <li key={func.entry} onClick={() => {getDecomp(func.entry)}}>{func.name} - {func.entry} - {func.analysis_priority}</li>
          ))}
        </ul>
        
      </div>
      {loadedDecomp && decomp.current_name && (
        <div className='panel'>
          <div className='panel_header'>
            <h1>{decomp.current_name}</h1>
            <p>Ghidra Address: {decomp.entry}</p>
            <button onClick={() => {analyzeDecomp()}}>Analyze</button>
          </div>
          <div className='panel_content'>
            <p>{decomp.decompiled}</p>
            <textarea value={addPrompts} onChange={e => {setAddPrompts(e.target.value)}}></textarea>
          </div>
          {loadedAnalysis && (
            <div className='panel_ai_analysis'>
              <h3>Current name: {analysisData.current_name}</h3>
              <p>Address in Ghidra: {analysisData.entry}</p>
              <h3>Potential new name: {analysisData.potential_new_name}</h3>
              <input placeholder="Any name you like" value={newName} onChange={e => {setNewName(e.target.value)}}></input>
              <button onClick={() => rename()}>Rename</button>
              <h4>Priority: {analysisData.analysis_priority}</h4>
              <p>{analysisData.functionality}</p>
              <ul>
                {analysisData.interesting_calls.map((func) => (
                  <li key={func}>{func}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
