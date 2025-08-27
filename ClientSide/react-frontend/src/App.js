import React, {useState, useEffect} from 'react';
import axios from 'axios';

const api = axios.create({
  baseURL: "http://localhost:5000/"
})

function App() {
  const [funcList, setFuncList] = useState([]);
  const [decomp, setDecomp] = useState({});
  const [loadedDecomp, setLoadingDecomp] = useState(false);

  useEffect(() => {
    const getList = async () => {
      let res = await api.get("/list_functions");
      setFuncList(res.data);
    }

    getList();
  }, [])

  const getDecomp = async (funcName) => {
    let res = await api.get("/get_function_decompiled/" + funcName)
    setDecomp(res.data);
    setLoadingDecomp(true);
  }

  return (
    <div className="App">
      <div className="sidebar">
        <ul>
          {funcList.map((func) => (
            <li key={func.entry} onClick={() => {getDecomp(func.name)}}>{func.name} - {func.entry}</li>
          ))}
        </ul>
        
      </div>
      {loadedDecomp && (
        <div className='panel'>
          <h1>{decomp.current_name}</h1>
          <p>{decomp.decompiled}</p>
        </div>
      )}
    </div>
  );
}

export default App;
