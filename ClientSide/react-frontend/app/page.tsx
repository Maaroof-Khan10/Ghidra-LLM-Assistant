"use client";

import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Loader2, AlertTriangle, Send, Settings, Power, RefreshCw, ServerCrash } from 'lucide-react';

// Import the types we defined
import { FunctionItem, DecompData, AnalysisData } from './types';

// API instance configured for the Flask backend
const api = axios.create({
  baseURL: "http://localhost:5000/"
});

// --- Re-usable Components with Prop Types ---

interface NavBarProps {
  path: string;
  setPath: React.Dispatch<React.SetStateAction<string>>;
  onSetPath: () => void;
  onReconnect: () => void;
  onQuit: () => void;
}

function NavBar({ path, setPath, onSetPath, onReconnect, onQuit }: NavBarProps) {
  return (
    <nav className='flex flex-wrap gap-4 items-center h-auto md:h-15 bg-gray-900 text-white px-5 py-3 justify-between sticky top-0 border-b border-gray-700 shadow-md z-10'>
      <div className='flex items-center text-xl'>
        <span className='font-semibold text-blue-400'>DragonAttack</span>
      </div>
      <div className='flex items-center gap-x-3 w-full md:w-1/2'>
        <input
          placeholder='Enter path to store analysis data (e.g., /path/to/folder)'
          value={path}
          onChange={(e) => { setPath(e.target.value) }}
          className='flex-grow h-10 bg-gray-800 border border-gray-700 text-white rounded-lg px-3 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500'
        />
        <button
          onClick={onSetPath}
          title="Set Path"
          className='p-2 bg-blue-600 rounded-lg hover:bg-blue-500 transition-colors flex-shrink-0'
        >
          <Settings size={20} />
        </button>
      </div>
      <div className="flex justify-center gap-3">
        <button 
          onClick={onReconnect} 
          title="Reconnect to Ghidra"
          className='p-2 bg-green-600 rounded-lg hover:bg-green-500 transition-colors'
        >
          <RefreshCw size={20} />
        </button>
        <button 
          onClick={onQuit} 
          title="Shutdown Ghidra Connection"
          className='p-2 bg-red-600 rounded-lg hover:bg-red-500 transition-colors'
        >
          <Power size={20} />
        </button>
      </div>
    </nav>
  );
}

interface FunctionListProps {
  funcList: FunctionItem[];
  onSelectFunction: (addr: string) => void;
  selectedAddr: string | null;
}

function FunctionList({ funcList, onSelectFunction, selectedAddr }: FunctionListProps) {
  return (
    <div className="w-full md:w-80 h-[40vh] md:h-[calc(100vh-68px)] bg-gray-800 text-white p-4 overflow-y-auto scrollbar border-r border-gray-700">
      <div className='my-2 mb-4'>
        <h1 className='text-2xl font-bold'>Functions</h1>
      </div>
      <hr className='border-gray-600' />
      <ul className='mt-3 font-medium text-sm'>
        {funcList.map((func: FunctionItem) => ( // Add type to 'func'
          <li
            key={func.entry}
            onClick={() => { onSelectFunction(func.entry) }}
            className={`mb-2 rounded hover:bg-blue-600 py-2 px-3 text-wrap overflow-x-hidden cursor-pointer transition-colors ${selectedAddr === func.entry ? 'bg-blue-700' : 'hover:bg-blue-700'}`}
          >
            <span className='font-mono block truncate'>{func.name}</span>
            <span className='text-xs text-gray-400 block'>{func.entry} - Priority: {func.analysis_priority}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

interface DecompilerViewProps {
  decomp: DecompData;
  addPrompts: string;
  setAddPrompts: React.Dispatch<React.SetStateAction<string>>;
  onAnalyze: () => void;
  isLoadingAnalysis: boolean;
}

function DecompilerView({ decomp, addPrompts, setAddPrompts, onAnalyze, isLoadingAnalysis }: DecompilerViewProps) {
  return (
    <div className='flex flex-col p-5 bg-gray-800 rounded-lg shadow-lg border border-gray-700'>
      <div className='flex flex-wrap justify-between items-center mb-4 gap-4'>
        <h1 className='text-3xl font-semibold font-mono break-all'>{decomp.current_name}</h1>
        <p className='text-lg font-mono text-gray-400'>{decomp.entry}</p>
      </div>
      <div className="bg-gray-900 rounded-lg overflow-hidden border border-gray-700">
        <pre
          className="p-4 text-sm max-h-[500px] overflow-auto scrollbar"
          style={{ fontFamily: '"Fira Code", monospace', backgroundColor: "#0d1117", whiteSpace: "pre-wrap", color: "#c9d1d9" }}
        >
          {decomp.decompiled}
        </pre>
      </div>
      <div className='flex flex-col mt-4'>
        <label htmlFor="addPrompts" className='text-lg mb-2 text-gray-300'>Additional Prompts:</label>
        <textarea
          id="addPrompts"
          className='bg-gray-900 border border-gray-700 rounded-md p-2 w-full h-24 focus:outline-none focus:ring-2 focus:ring-blue-500'
          value={addPrompts}
          onChange={e => { setAddPrompts(e.target.value) }}
        ></textarea>
      </div>
      <button 
        onClick={onAnalyze} 
        disabled={isLoadingAnalysis}
        className='mt-4 text-lg bg-blue-600 w-full md:w-1/4 p-3 rounded-lg hover:bg-blue-500 transition-all flex items-center justify-center gap-2 disabled:bg-gray-600'
      >
        {isLoadingAnalysis ? <Loader2 className='animate-spin' size={24} /> : 'Analyze'}
        {!isLoadingAnalysis && <Send size={20} />}
      </button>
    </div>
  );
}

interface AnalysisViewProps {
  analysisData: AnalysisData;
  newName: string;
  setNewName: React.Dispatch<React.SetStateAction<string>>;
  onRename: () => void;
  isLoadingRename: boolean;
}

function AnalysisView({ analysisData, newName, setNewName, onRename, isLoadingRename }: AnalysisViewProps) {
  return (
    <div className='flex flex-col p-5 bg-gray-800 rounded-lg shadow-lg border border-gray-700'>
      <h1 className='text-2xl font-semibold mb-3'>Gemini Analysis</h1>
      <hr className='my-2 border-gray-600' />
      
      <div className='my-2'>
        <h2 className='text-xl text-gray-300'>Priority: <span className='font-bold text-blue-400'>{analysisData.analysis_priority}</span></h2>
      </div>

      <div className='flex flex-col md:flex-row justify-between md:items-center gap-3 my-2'>
        <h3 className='text-xl text-gray-300 w-full md:w-1/3'>Potential new name:</h3>
        <div className='flex gap-2 w-full md:w-2/3'>
          <input 
            className='bg-gray-900 border border-gray-700 rounded-md p-2 w-full focus:outline-none focus:ring-2 focus:ring-blue-500' 
            placeholder="Enter new name..." 
            value={newName} 
            onChange={e => { setNewName(e.target.value) }}
          />
          <button 
            className='bg-blue-600 p-2 rounded-lg hover:bg-blue-500 transition-colors flex-shrink-0 disabled:bg-gray-600' 
            onClick={onRename}
            disabled={isLoadingRename}
          >
            {isLoadingRename ? <Loader2 className='animate-spin' size={24} /> : 'Rename'}
          </button>
        </div>
      </div>

      <div className='flex flex-col my-2 gap-y-2'>
        <h3 className='text-xl text-gray-300'>Functionality</h3>
        <p className='bg-gray-900 p-3 rounded-lg border border-gray-700 text-gray-200'>{analysisData.functionality}</p>
      </div>

      <div className='flex flex-col my-2 gap-y-2'>
        <h3 className='text-xl text-gray-300'>Interesting Function Calls</h3>
        <div className='bg-gray-900 p-3 px-5 rounded-lg border border-gray-700 text-gray-200'>
          <ul className='list-disc list-inside'>
            {analysisData.interesting_calls.map((func: string) => ( // Add type to 'func'
              <li className='text-balance' key={func}>{func}</li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

interface ErrorDisplayProps {
  message: string | null;
  onClear: () => void;
}

function ErrorDisplay({ message, onClear }: ErrorDisplayProps) {
  if (!message) return null;
  return (
    <div className='fixed top-24 left-1/2 -translate-x-1/2 z-50 w-11/12 md:w-1/3 bg-red-800 border border-red-600 text-white p-4 rounded-lg shadow-lg flex items-center justify-between'>
      <div className='flex items-center gap-3'>
        <AlertTriangle size={24} />
        <div>
          <h4 className='font-bold'>Error</h4>
          <p className='text-sm'>{message}</p>
        </div>
      </div>
      <button onClick={onClear} className='text-xl'>&times;</button>
    </div>
  );
}

// --- Main App Component ---

export default function Home() {
  // State with explicit types
  const [path, setPath] = useState("");
  const [funcList, setFuncList] = useState<FunctionItem[]>([]);
  const [decomp, setDecomp] = useState<DecompData | null>(null);
  const [addPrompts, setAddPrompts] = useState("");
  const [analysisData, setAnalysisData] = useState<AnalysisData | null>(null);
  const [newName, setNewName] = useState("");
  const [selectedAddr, setSelectedAddr] = useState<string | null>(null);

  // Loading & Error State with explicit types
  const [isLoadingList, setIsLoadingList] = useState(false);
  const [isLoadingDecomp, setIsLoadingDecomp] = useState(false);
  const [isLoadingAnalysis, setIsLoadingAnalysis] = useState(false);
  const [isLoadingRename, setIsLoadingRename] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // --- API Functions ---

  const getList = async () => {
    setError(null);
    setIsLoadingList(true);
    try {
      // Add type to response
      let res = await api.get<FunctionItem[]>("/list_functions");
      const sorted = res.data.sort(
        (a, b) => b.analysis_priority - a.analysis_priority
      );
      setFuncList(sorted);
    } catch (err) {
      console.error("Error fetching functions:", err);
      setError("Error fetching functions. Make sure Flask & Ghidra servers are running.");
    } finally {
      setIsLoadingList(false);
    }
  };

  const getDecomp = async (addr: string) => { // Add type to addr
    if (isLoadingDecomp) return;
    setError(null);
    setIsLoadingDecomp(true);
    setDecomp(null);
    setAnalysisData(null);
    setNewName("");
    setAddPrompts("");
    setSelectedAddr(addr);
    try {
      // Add type to response
      let res = await api.get<DecompData>("/get_function_decompiled/" + addr);
      setDecomp(res.data);
    } catch (err) {
      console.error("Error in decompiling:", err);
      setError("Error decompiling function. Make sure Ghidra server is running.");
      setSelectedAddr(null);
    } finally {
      setIsLoadingDecomp(false);
    }
  };

  const analyzeDecomp = async () => {
    if (!decomp) return;
    setError(null);
    setIsLoadingAnalysis(true);
    try {
      let data = {
        addr: decomp.entry,
        addPrompts: addPrompts || "None"
      };
      // Add type to response
      let res = await api.post<AnalysisData>('/analyze_function', data);
      setAnalysisData(res.data);
      setNewName(res.data.potential_new_name);
      await getList(); // Refresh list to update priority
    } catch (err) {
      console.error("Error in analysis:", err);
      setError("Error analyzing function. Check API key and server status.");
    } finally {
      setIsLoadingAnalysis(false);
    }
  };

  const rename = async () => {
    if (!analysisData) return;
    setError(null);
    setIsLoadingRename(true);
    try {
      let data = {
        addr: analysisData.entry,
        new_name: newName || analysisData.potential_new_name
      };
      await api.post('/rename_function', data);
      
      // Optimistically update UI
      setDecomp(prev => {
        if (!prev) return null; // Type guard
        return {
          ...prev,
          current_name: data.new_name,
          decompiled: prev.decompiled.replaceAll(prev.current_name, data.new_name)
        }
      });
      setAnalysisData(prev => {
         if (!prev) return null; // Type guard
        return {
          ...prev,
          current_name: data.new_name
        }
      });
      await getList(); // Refresh list to show new name
    } catch (err) {
      console.error("Error renaming function:", err);
      setError("Error renaming function. Check server status.");
    } finally {
      setIsLoadingRename(false);
    }
  };

  const set_path = async () => {
    setError(null);
    try {
      if (path !== "") {
        await api.post("/set_path", { path: path });
        await getList(); // Get list after setting path
      }
    } catch (err) {
      console.error("Error setting path:", err);
      setError("Error setting path. Make sure path is a valid directory.");
    }
  };

  const quitConn = async () => {
    if (window.confirm("Are you sure you want to shut down the Ghidra server connection?")) {
      setError(null);
      try {
        await api.get("/quit");
        setFuncList([]);
        setDecomp(null);
        setAnalysisData(null);
      } catch (err) {
        console.error("Error quitting:", err);
        setError("Error quitting connection. Check Flask server.");
      }
    }
  };

  const reconnect = async () => {
    setError(null);
    try {
      await api.get("/reconnect");
      await getList();
    } catch (err) {
      console.error("Error reconnecting:", err);
      setError("Error reconnecting. Make sure Ghidra server is running.");
    }
  };

  // --- Effects ---

  useEffect(() => {
    // Load path from localStorage on initial render
    try {
      const savedPath = localStorage.getItem("analysisPath");
      if (savedPath) {
        setPath(savedPath);
      }
    } catch (err) {
      console.error("Error reading path from local storage:", err);
    }
    // Don't auto-fetch list, wait for user to set path
  }, []);

  useEffect(() => {
    // Save path to localStorage whenever it changes
    try {
      if (path) {
        localStorage.setItem("analysisPath", path);
      }
    } catch (err) {
      console.error("Error saving path to localStorage:", err);
    }
  }, [path]);

  // --- Render ---

  return (
    <div className="flex flex-col h-screen bg-gray-900 text-white">
      <ErrorDisplay message={error} onClear={() => setError(null)} />
      
      <NavBar
        path={path}
        setPath={setPath}
        onSetPath={set_path}
        onReconnect={reconnect}
        onQuit={quitConn}
      />

      <div className='flex flex-col md:flex-row flex-1 overflow-hidden'>
        <FunctionList
          funcList={funcList}
          onSelectFunction={getDecomp}
          selectedAddr={selectedAddr}
        />
        
        <main className='flex-1 mx-2 my-5 gap-y-10 overflow-y-auto scrollbar'>
          {isLoadingDecomp && (
            <div className='flex justify-center items-center h-full'>
              <Loader2 className='animate-spin' size={48} />
            </div>
          )}
          
          {!isLoadingDecomp && !decomp && (
             <div className='flex flex-col justify-center items-center h-full text-gray-500'>
              <ServerCrash size={64} />
              <p className='text-xl mt-4'>Select a function to decompile</p>
              <p className='text-sm'>Make sure your path is set and servers are running.</p>
            </div>
          )}

          {decomp && (
            <DecompilerView
              decomp={decomp}
              addPrompts={addPrompts}
              setAddPrompts={setAddPrompts}
              onAnalyze={analyzeDecomp}
              isLoadingAnalysis={isLoadingAnalysis}
            />
          )}

          {analysisData && (
            <div className='mt-10'>
              <AnalysisView
                analysisData={analysisData}
                newName={newName}
                setNewName={setNewName}
                onRename={rename}
                isLoadingRename={isLoadingRename}
              />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
