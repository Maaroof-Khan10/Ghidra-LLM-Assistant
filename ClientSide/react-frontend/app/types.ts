// We can define the shapes of your data here
// based on your server.py and client.py files.

export interface FunctionItem {
  name: string;
  entry: string;
  analysis_priority: number;
}

export interface DecompData {
  entry: string;
  current_name: string;
  decompiled: string;
}

export interface AnalysisData {
  entry: string;
  current_name: string;
  potential_new_name: string;
  functionality: string;
  analysis_priority: number;
  interesting_calls: string[];
}
