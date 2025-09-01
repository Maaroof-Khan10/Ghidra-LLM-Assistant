import React, {useState, useEffect} from 'react';
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
    let res = await api.get("/list_functions");

    const sorted = res.data.sort(
      (a, b) => b.analysis_priority - a.analysis_priority
    );

    setFuncList(sorted);
  }

  useEffect(() => {
    getList();
  }, [])

  const set_path = async () => {
    if (path !== "") {
      let data = {
        path: path
      }
      let res = await api.post("/set_path", data)
      console.log(res.data);
    }
  }

  const getDecomp = async (addr) => {
    let res = await api.get("/get_function_decompiled/" + addr)
    setDecomp(res.data);
    setLoadingDecomp(true);
    setLoadedAnalysis(false);
    setAnalysisData({})
    setNewName("")
  }

  const analyzeDecomp = async () => {
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
  }

  const quitConn = async () => {
    let res = await api.get("/quit")
    console.log(res.data);
  }

  const reconnect = async () => {
    let res = await api.get("/reconnect")
    console.log(res.data);
  }

  const rename = async () => {
    let data = {
      addr: analysisData.entry,
      new_name: newName
    }
    if (newName === "") {
      data.new_name = analysisData.potential_new_name;
    }
    let res = await api.post('/rename_function', data);
    console.log(res.data);
    setDecomp(prevData => ({
      ...prevData,
      current_name: data.new_name
    }))
    setAnalysisData(prevData => ({
      ...prevData,
      current_name: data.new_name
    }))
    getList();
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
