import React, {useState, useEffect} from 'react';
import axios from 'axios';

const api = axios.create({
  baseURL: "http://localhost:5000/"
})

function App() {
  const [funcList, setFuncList] = useState([]);
  const [decomp, setDecomp] = useState({});
  const [loadedDecomp, setLoadingDecomp] = useState(false);
  const [addPrompts, setAddPrompts] = useState("");
  const [loadedAnalysis, setLoadedAnalysis] = useState(false);
  const [analysisData, setAnalysisData] = useState({});

  useEffect(() => {
    const getList = async () => {
      let res = await api.get("/list_functions");
      setFuncList(res.data);
    }

    getList();
  }, [])

  const getDecomp = async (addr) => {
    let res = await api.get("/get_function_decompiled/" + addr)
    setDecomp(res.data);
    setLoadingDecomp(true);
    setLoadedAnalysis(false);
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
    setAnalysisData(res.data);
    setLoadedAnalysis(true);
  }

  return (
    <div className="App">
      <div className="sidebar">
        <ul>
          {funcList.map((func) => (
            <li key={func.entry} onClick={() => {getDecomp(func.entry)}}>{func.name} - {func.entry}</li>
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
