import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Shield, Terminal, Activity, FileText, Settings, UploadCloud, Trash2, 
  Search, RefreshCw, AlertTriangle, CheckCircle, Radio, Bell, ArrowRight, 
  Plus, Eye, Download, FileCode, Server, Database, Compass, Globe, Key, Lock
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const API_BASE = `http://${window.location.hostname}:8000`;

export default function Dashboard() {
  const navigate = useNavigate();
  
  // Tab control state
  const [activeTab, setActiveTab] = useState('overview'); // overview, detonate, threat_intel, history, notifications
  
  // Real-time backend stats state
  const [stats, setStats] = useState({
    total_analyzed: 0,
    completed: 0,
    processing: 0,
    failed: 0,
    malicious: 0,
    suspicious: 0,
    benign: 0,
    avg_duration: 0.0,
    ai_confidence: 0.0,
    alerts: [],
    chart_data_daily: [],
    chart_data_severity: []
  });

  // History Ledger states
  const [scanHistory, setScanHistory] = useState([]);
  const [historySearch, setHistorySearch] = useState('');
  const [historyFilter, setHistoryFilter] = useState('ALL'); // ALL, MALICIOUS, SUSPICIOUS, CLEAN
  
  // Global search state
  const [globalSearchQuery, setGlobalSearchQuery] = useState('');
  const [globalSearchResults, setGlobalSearchResults] = useState([]);
  const [isSearching, setIsSearching] = useState(false);

  // Threat Intelligence Feed states
  const [threatFeeds, setThreatFeeds] = useState([]);
  const [intelSearch, setIntelSearch] = useState('');

  // Notifications states
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);

  // Ingest Uploader Queue State
  const [uploadQueue, setUploadQueue] = useState([]);
  const [isDragging, setIsDragging] = useState(false);

  // Analysis result modal states
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [aiReportQuery, setAiReportQuery] = useState('');
  const [aiReportChat, setAiReportChat] = useState([]);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [agentLogs, setAgentLogs] = useState([]);

  // Fetch functions
  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/dashboard-stats/`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error("Error fetching overview metrics: ", err);
    }
  };

  const fetchHistoryLedger = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/history-ledger/`);
      if (res.ok) {
        const data = await res.json();
        setScanHistory(data);
      }
    } catch (err) {
      console.error("Error loading scan ledger: ", err);
    }
  };

  const fetchThreatFeeds = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/threat-intelligence/`);
      if (res.ok) {
        const data = await res.json();
        setThreatFeeds(data);
      }
    } catch (err) {
      console.error("Error fetching threat intelligence: ", err);
    }
  };

  const fetchNotifications = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/notifications/`);
      if (res.ok) {
        const data = await res.json();
        setNotifications(data);
        setUnreadCount(data.filter(n => !n.is_read).length);
      }
    } catch (err) {
      console.error("Error loading alerts queue: ", err);
    }
  };

  // EventSource stream connection for real-time push events
  useEffect(() => {
    fetchStats();
    fetchHistoryLedger();
    fetchThreatFeeds();
    fetchNotifications();

    const sse = new EventSource(`${API_BASE}/api/v1/telemetry-stream/`);

    sse.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'SCAN_UPDATE') {
          const scan = message.data;
          
          setUploadQueue(prev => {
            const exists = prev.some(item => item.logId === scan.id || (item.name === scan.file_name && !item.logId));
            if (!exists) {
              return [{
                id: Math.random().toString(36).substring(7),
                name: scan.file_name,
                size: (scan.file_size_bytes / 1024).toFixed(1) + ' KB',
                status: scan.status,
                status_detail: scan.status_detail,
                logId: scan.id,
                result: scan.status === 'COMPLETED' ? scan : null
              }, ...prev];
            }

            return prev.map(item => {
              if (item.logId === scan.id || (item.name === scan.file_name && !item.logId)) {
                return {
                  ...item,
                  logId: scan.id,
                  status: scan.status,
                  status_detail: scan.status_detail,
                  result: scan.status === 'COMPLETED' ? scan : null
                };
              }
              return item;
            });
          });

          if (scan.status === 'COMPLETED' || scan.status === 'FAILED') {
            fetchHistoryLedger();
            fetchStats();
            fetchNotifications();
          }
        }
        else if (message.type === 'STATS_UPDATE') {
          setStats(message.data);
        }
        else if (message.type === 'NOTIFICATION_UPDATE') {
          setNotifications(message.data);
          setUnreadCount(message.data.filter(n => !n.is_read).length);
        }
      } catch (err) {
        console.error("SSE parse error: ", err);
      }
    };

    sse.onerror = (err) => {
      console.error("SSE connection dropped. Retrying...", err);
    };

    return () => {
      sse.close();
    };
  }, []);

  // Global Search Handler
  const handleGlobalSearch = async (e) => {
    e.preventDefault();
    if (!globalSearchQuery.trim()) {
      setGlobalSearchResults([]);
      return;
    }
    setIsSearching(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/global-search/?q=${encodeURIComponent(globalSearchQuery)}`);
      if (res.ok) {
        const data = await res.json();
        setGlobalSearchResults(data);
      }
    } catch (err) {
      console.error("Search telemetry failure: ", err);
    } finally {
      setIsSearching(false);
    }
  };

  // Drag and Drop files handlers
  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const files = Array.from(e.dataTransfer.files);
    queueFilesForUpload(files);
  };

  const handleFileBrowse = (e) => {
    const files = Array.from(e.target.files);
    queueFilesForUpload(files);
  };

  // Upload queue logic
  const queueFilesForUpload = (files) => {
    const allowedExtensions = ['.exe', '.dll', '.pdf', '.doc', '.docx', '.zip', '.rar', '.iso', '.apk', '.js', '.ps1', '.bat'];
    
    files.forEach(file => {
      const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
      
      // Extension Check
      if (!allowedExtensions.includes(ext)) {
        addFailedQueueItem(file.name, `Unsupported file type '${ext}'.`);
        return;
      }
      // Size check (15MB)
      if (file.size > 15 * 1024 * 1024) {
        addFailedQueueItem(file.name, "File size exceeds 15MB boundary.");
        return;
      }

      // Add to queue and launch upload fetch
      const itemId = Math.random().toString(36).substring(7);
      const newJob = {
        id: itemId,
        name: file.name,
        size: (file.size / 1024).toFixed(1) + ' KB',
        status: 'PROCESSING',
        status_detail: 'Uploading',
        logId: null,
        result: null
      };

      setUploadQueue(prev => [newJob, ...prev]);
      executeFileUpload(file, itemId);
    });
  };

  const addFailedQueueItem = (fileName, reason) => {
    const itemId = Math.random().toString(36).substring(7);
    setUploadQueue(prev => [{
      id: itemId,
      name: fileName,
      size: 'N/A',
      status: 'FAILED',
      status_detail: reason,
      logId: null,
      result: null
    }, ...prev]);
  };

  const executeFileUpload = async (file, itemId) => {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_BASE}/api/v1/upload/`, {
        method: 'POST',
        body: formData
      });

      const data = await res.json();
      if (res.ok || res.status === 202) {
        setUploadQueue(prev => prev.map(item => {
          if (item.id === itemId) {
            return {
              ...item,
              logId: data.id,
              status: data.status,
              status_detail: data.status_detail,
              result: data.status === 'COMPLETED' ? data : null
            };
          }
          return item;
        }));
      } else {
        setUploadQueue(prev => prev.map(item => {
          if (item.id === itemId) {
            return { ...item, status: 'FAILED', status_detail: data.error || 'Ingestion failed' };
          }
          return item;
        }));
      }
    } catch (err) {
      setUploadQueue(prev => prev.map(item => {
        if (item.id === itemId) {
          return { ...item, status: 'FAILED', status_detail: 'Network upload error' };
        }
        return item;
      }));
    }
  };

  const cancelQueueItem = (itemId) => {
    setUploadQueue(prev => prev.filter(item => item.id !== itemId));
  };

  // Open detailed analysis report
  const openAnalysisDetails = async (logId) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/scan-status/${logId}/`);
      if (res.ok) {
        const data = await res.json();
        setSelectedAnalysis(data);
        setAiReportChat([]);
        setAgentLogs([
          `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Autonomous SecOps workspace initialized.`,
          `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Ready for operator commands.`
        ]);
        setIsDetailModalOpen(true);
      }
    } catch (err) {
      console.error("Failed to load analysis record details: ", err);
    }
  };

  // Delete history item
  const handleHistoryDelete = async (logId) => {
    try {
      // Backend does not enforce strict user delete for standalone development, so we can clean local rows
      const res = await fetch(`${API_BASE}/api/v1/history-ledger/`, {
        method: 'POST', // standard endpoint routing fallback if DELETE isn't mapped
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'delete', id: logId })
      });
      fetchHistoryLedger();
      fetchStats();
    } catch (err) {
      // Direct local filter fallback
      setScanHistory(prev => prev.filter(item => item.id !== logId));
    }
  };

  // AI Copilot playbooks query submission
  const submitAiQuestion = async (e) => {
    if (e) e.preventDefault();
    if (!aiReportQuery.trim() || !selectedAnalysis) return;

    const userText = aiReportQuery;
    setAiReportChat(prev => [...prev, { role: 'user', text: userText }]);
    setAiReportQuery('');
    setIsAiLoading(true);

    setAgentLogs(prev => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] OPERATOR: "${userText}"`,
      `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Formulating query vector...`,
      `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Querying secure LLM gateway...`
    ]);

    try {
      const res = await fetch(`${API_BASE}/api/v1/ai-report/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysis_results: selectedAnalysis,
          query: userText
        })
      });

      if (res.ok) {
        const data = await res.json();
        setAiReportChat(prev => [...prev, { role: 'assistant', text: data.report }]);
        setAgentLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Analysis successfully generated. Output rendered.`
        ]);
      } else {
        const errData = await res.json().catch(() => ({}));
        const errMsg = errData.error || "Failed to receive response from AI backend.";
        setAiReportChat(prev => [...prev, { role: 'assistant', text: `⚠️ ${errMsg}` }]);
        setAgentLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Error - Request failed: ${errMsg}`
        ]);
      }
    } catch (err) {
      setAiReportChat(prev => [...prev, { role: 'assistant', text: "🔌 AI connection socket timeout." }]);
      setAgentLogs(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Error - Connection timeout.`
      ]);
    } finally {
      setIsAiLoading(false);
    }
  };

  const executeAgentAction = async (command, promptText) => {
    if (isAiLoading || !selectedAnalysis) return;
    setIsAiLoading(true);

    setAgentLogs(prev => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] COMMAND_EXECUTED: "${command}"`,
      `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Compiling telemetry contexts...`,
      `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Invoking query pipeline...`
    ]);

    setAiReportChat(prev => [...prev, { role: 'user', text: `Triggering action: ${command}` }]);

    try {
      const res = await fetch(`${API_BASE}/api/v1/ai-report/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysis_results: selectedAnalysis,
          query: promptText
        })
      });

      if (res.ok) {
        const data = await res.json();
        setAiReportChat(prev => [...prev, { role: 'assistant', text: data.report }]);
        setAgentLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Command "${command}" executed. Outputs loaded.`
        ]);
      } else {
        const errData = await res.json().catch(() => ({}));
        const errMsg = errData.error || "Failed to execute agent action.";
        setAiReportChat(prev => [...prev, { role: 'assistant', text: `⚠️ ${errMsg}` }]);
        setAgentLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Command "${command}" failed - ${errMsg}`
        ]);
      }
    } catch (err) {
      setAiReportChat(prev => [...prev, { role: 'assistant', text: "🔌 AI connection socket timeout." }]);
      setAgentLogs(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Command "${command}" timed out.`
      ]);
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleDownloadPDF = (logId) => {
    window.open(`${API_BASE}/api/v1/reports/${logId}/download/`, '_blank');
  };

  const handleDismissNotification = async (id) => {
    try {
      await fetch(`${API_BASE}/api/v1/notifications/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      });
      fetchNotifications();
    } catch (err) {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }
  };

  const handleClearAllNotifications = async () => {
    try {
      await fetch(`${API_BASE}/api/v1/notifications/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      fetchNotifications();
    } catch (err) {
      setNotifications([]);
    }
  };

  // Color mappings
  const COLORS = ['#ef4444', '#f59e0b', '#10b981'];

  return (
    <div className="min-h-screen w-full bg-[#02020a] flex text-white font-sans relative overflow-hidden">
      
      {/* Background gradients */}
      <div className="absolute top-1/2 left-1/4 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-[#25a5ff]/5 to-purple-500/5 rounded-full blur-[140px] pointer-events-none" />
      
      {/* Sidebar Panel */}
      <aside className="w-64 border-r border-[#25a5ff]/15 bg-[#070913]/90 flex flex-col shrink-0 relative z-10 backdrop-blur-xl">
        <div className="p-5 border-b border-[#25a5ff]/15 flex items-center gap-3">
          <img src="/logo.png" className="h-10 w-auto rounded-lg shadow-[0_0_15px_rgba(37,165,255,0.35)] border border-[#25a5ff]/25" alt="BlueIntel Logo" />
          <div>
            <span className="font-black text-xs tracking-widest uppercase">BLUE<span className="text-[#25a5ff]">INTEL</span></span>
            <span className="block text-[8px] text-[#576575] font-mono tracking-widest font-bold">Control Panel</span>
          </div>
        </div>

        {/* Navigation list */}
        <nav className="flex-1 px-4 py-6 space-y-2">
          <button 
            onClick={() => setActiveTab('overview')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-bold font-mono uppercase tracking-wider cursor-pointer transition-all ${activeTab === 'overview' ? 'bg-[#25a5ff]/10 text-white border-l-2 border-[#25a5ff]' : 'text-[#576575] hover:text-white hover:bg-white/5'}`}
          >
            <Activity size={16} /> Overview
          </button>
          <button 
            onClick={() => setActiveTab('detonate')}
            className={`w-full flex items-center justify-between px-4 py-3 rounded-xl text-xs font-bold font-mono uppercase tracking-wider cursor-pointer transition-all ${activeTab === 'detonate' ? 'bg-[#25a5ff]/10 text-white border-l-2 border-[#25a5ff]' : 'text-[#576575] hover:text-white hover:bg-white/5'}`}
          >
            <span className="flex items-center gap-3"><UploadCloud size={16} /> Upload Files</span>
            {uploadQueue.filter(j => j.status === 'PROCESSING').length > 0 && (
              <span className="bg-[#25a5ff] text-black text-[9px] font-bold px-2 py-0.5 rounded-full animate-pulse">
                {uploadQueue.filter(j => j.status === 'PROCESSING').length}
              </span>
            )}
          </button>
          <button 
            onClick={() => setActiveTab('threat_intel')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-bold font-mono uppercase tracking-wider cursor-pointer transition-all ${activeTab === 'threat_intel' ? 'bg-[#25a5ff]/10 text-white border-l-2 border-[#25a5ff]' : 'text-[#576575] hover:text-white hover:bg-white/5'}`}
          >
            <Globe size={16} /> Threat Intelligence
          </button>
          <button 
            onClick={() => setActiveTab('world_map')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-bold font-mono uppercase tracking-wider cursor-pointer transition-all ${activeTab === 'world_map' ? 'bg-[#25a5ff]/10 text-white border-l-2 border-[#25a5ff]' : 'text-[#576575] hover:text-white hover:bg-white/5'}`}
          >
            <Compass size={16} className="animate-pulse text-[#25a5ff]" /> 3D Attack Globe
          </button>
          <button 
            onClick={() => setActiveTab('history')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-xs font-bold font-mono uppercase tracking-wider cursor-pointer transition-all ${activeTab === 'history' ? 'bg-[#25a5ff]/10 text-white border-l-2 border-[#25a5ff]' : 'text-[#576575] hover:text-white hover:bg-white/5'}`}
          >
            <Database size={16} /> Analysis History
          </button>
          <button 
            onClick={() => setActiveTab('notifications')}
            className={`w-full flex items-center justify-between px-4 py-3 rounded-xl text-xs font-bold font-mono uppercase tracking-wider cursor-pointer transition-all ${activeTab === 'notifications' ? 'bg-[#25a5ff]/10 text-white border-l-2 border-[#25a5ff]' : 'text-[#576575] hover:text-white hover:bg-white/5'}`}
          >
            <span className="flex items-center gap-3"><Bell size={16} /> Notifications</span>
            {unreadCount > 0 && (
              <span className="bg-[#ef4444] text-white text-[9px] font-bold px-2 py-0.5 rounded-full">
                {unreadCount}
              </span>
            )}
          </button>
        </nav>

        {/* Developer configuration footer */}
        <div className="p-4 border-t border-[#25a5ff]/15 flex items-center justify-between bg-[#04060d]">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-[#10b981] animate-ping" />
            <span className="text-[10px] font-mono text-[#576575] font-bold">DEV_CONSOLE_ON</span>
          </div>
          <button onClick={() => navigate('/settings')} className="text-[#576575] hover:text-white transition-colors cursor-pointer">
            <Settings size={16} />
          </button>
        </div>
      </aside>

      {/* Main Container Section */}
      <main className="flex-1 flex flex-col min-w-0 relative z-10 overflow-y-auto">
        
        {/* Global Search Header Header */}
        <header className="h-20 border-b border-[#25a5ff]/15 px-8 flex items-center justify-between bg-[#070913]/30 backdrop-blur-xl">
          <form onSubmit={handleGlobalSearch} className="w-96 relative flex items-center">
            <Search className="absolute left-4 text-[#576575]" size={14} />
            <input 
              type="text"
              value={globalSearchQuery}
              onChange={(e) => {
                setGlobalSearchQuery(e.target.value);
                if (!e.target.value.trim()) setGlobalSearchResults([]);
              }}
              placeholder="SEARCH BY FILE HASH, NAME, OR SYSTEM ID..."
              className="w-full bg-[#04060d] border border-[#25a5ff]/15 rounded-xl pl-12 pr-4 py-2.5 text-xs text-white placeholder-[#576575] focus:border-[#25a5ff]/40 outline-none font-mono"
            />
          </form>

          {/* Profile details */}
          <div className="flex items-center gap-4">
            <div className="text-right">
              <span className="block text-xs font-bold font-mono text-white">OPERATOR: DEV_NODE</span>
              <span className="block text-[8px] font-mono text-[#576575]">developer@blueintel.com</span>
            </div>
            <div className="w-10 h-10 rounded-xl bg-[#25a5ff]/5 border border-[#25a5ff]/20 flex items-center justify-center font-mono font-bold text-[#25a5ff]">
              OP
            </div>
          </div>
        </header>

        {/* Tab view rendering */}
        <div className="flex-1 p-8">
          
          {/* Global search result table overlay */}
          {globalSearchQuery.trim() && (
            <div className="mb-8 bg-[#0b0f19]/80 border border-[#25a5ff]/30 p-6 rounded-2xl backdrop-blur-xl">
              <h3 className="text-xs font-bold font-mono text-[#25a5ff] uppercase tracking-wider mb-4 flex items-center gap-2">
                <Search size={14} /> Global Telemetry Search Results ({globalSearchResults.length})
              </h3>
              {isSearching ? (
                <div className="text-center py-6 text-xs text-[#576575] font-mono animate-pulse">Running query algorithms...</div>
              ) : globalSearchResults.length === 0 ? (
                <div className="text-center py-6 text-xs text-[#576575] font-mono">No records found matching query parameters.</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs text-[#9aa4b2]">
                    <thead>
                      <tr className="border-b border-[#25a5ff]/15 text-[#576575]">
                        <th className="py-2">File Name</th>
                        <th className="py-2">Hash (SHA-256)</th>
                        <th className="py-2">Verdict</th>
                        <th className="py-2 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {globalSearchResults.map((item) => (
                        <tr key={item.id} className="border-b border-[#25a5ff]/5 hover:bg-[#25a5ff]/5">
                          <td className="py-3 text-white font-bold">{item.name}</td>
                          <td className="py-3 font-mono text-[10px]">{item.sha256}</td>
                          <td className="py-3">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${item.verdict === 'MALICIOUS' ? 'bg-red-500/10 text-red-400' : item.verdict === 'SUSPICIOUS' ? 'bg-yellow-500/10 text-yellow-400' : 'bg-green-500/10 text-green-400'}`}>
                              {item.verdict}
                            </span>
                          </td>
                          <td className="py-3 text-right">
                            <button 
                              onClick={() => openAnalysisDetails(item.id)}
                              className="text-[#25a5ff] hover:underline flex items-center gap-1 ml-auto cursor-pointer"
                            >
                              <Eye size={12} /> View Report
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* OVERVIEW TAB */}
          {activeTab === 'overview' && (
            <div className="space-y-8 animate-fadeIn">
              
              {/* Telemetry card grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
                <div className="bg-[#0b0f19]/70 border border-[#25a5ff]/15 p-6 rounded-2xl flex flex-col justify-between hover:border-[#25a5ff]/35 transition-all">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#576575] font-bold">Uploaded Files</span>
                  <div className="flex items-baseline justify-between mt-4">
                    <span className="text-3xl font-black">{stats.total_analyzed}</span>
                    <span className="text-[10px] text-[#10b981] font-mono">Real-time</span>
                  </div>
                </div>
                <div className="bg-[#0b0f19]/70 border border-[#25a5ff]/15 p-6 rounded-2xl flex flex-col justify-between hover:border-[#25a5ff]/35 transition-all">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#576575] font-bold">Files Being Analyzed</span>
                  <div className="flex items-baseline justify-between mt-4">
                    <span className="text-3xl font-black text-[#25a5ff]">{stats.processing}</span>
                    <span className="text-[10px] text-[#25a5ff] font-mono animate-pulse">Running...</span>
                  </div>
                </div>
                <div className="bg-[#0b0f19]/70 border border-[#25a5ff]/15 p-6 rounded-2xl flex flex-col justify-between hover:border-[#25a5ff]/35 transition-all">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#576575] font-bold">Malicious Files</span>
                  <div className="flex items-baseline justify-between mt-4">
                    <span className="text-3xl font-black text-[#ef4444]">{stats.malicious}</span>
                    <span className="text-[9px] bg-red-950/40 border border-red-500/20 text-red-400 px-2 py-0.5 rounded font-mono font-bold">Threat</span>
                  </div>
                </div>
                <div className="bg-[#0b0f19]/70 border border-[#25a5ff]/15 p-6 rounded-2xl flex flex-col justify-between hover:border-[#25a5ff]/35 transition-all">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#576575] font-bold">Suspicious Files</span>
                  <div className="flex items-baseline justify-between mt-4">
                    <span className="text-3xl font-black text-[#f59e0b]">{stats.suspicious}</span>
                    <span className="text-[9px] bg-yellow-950/40 border border-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded font-mono font-bold">Warning</span>
                  </div>
                </div>
                <div className="bg-[#0b0f19]/70 border border-[#25a5ff]/15 p-6 rounded-2xl flex flex-col justify-between hover:border-[#25a5ff]/35 transition-all">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-[#576575] font-bold">Average Analysis Time</span>
                  <div className="flex items-baseline justify-between mt-4">
                    <span className="text-3xl font-black">{stats.avg_duration}s</span>
                    <span className="text-[10px] text-[#576575] font-mono">Performance</span>
                  </div>
                </div>
              </div>

              {/* Charts grid */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                {/* Daily Ingestion trend */}
                <div className="bg-[#0b0f19]/60 border border-[#25a5ff]/15 p-6 rounded-2xl lg:col-span-2">
                  <h3 className="text-xs font-bold font-mono uppercase text-[#576575] tracking-wider mb-6 flex items-center gap-2">
                    <Activity size={14} className="text-[#25a5ff]" /> Analysis Activity (Last 7 Days)
                  </h3>
                  <div className="h-64 w-full">
                    {stats.chart_data_daily.length === 0 ? (
                      <div className="h-full flex items-center justify-center text-xs font-mono text-[#576575]">Upload files to see activity chart...</div>
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={stats.chart_data_daily}>
                          <defs>
                            <linearGradient id="colorFiles" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#25a5ff" stopOpacity={0.2}/>
                              <stop offset="95%" stopColor="#25a5ff" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <XAxis dataKey="date" stroke="#576575" fontSize={10} fontFamily="monospace" />
                          <YAxis stroke="#576575" fontSize={10} fontFamily="monospace" />
                          <Tooltip contentStyle={{ backgroundColor: '#0b0f19', border: '1px solid #25a5ff50', borderRadius: '12px' }} />
                          <Area type="monotone" dataKey="files" stroke="#25a5ff" fillOpacity={1} fill="url(#colorFiles)" strokeWidth={2} />
                        </AreaChart>
                      </ResponsiveContainer>
                    )}
                  </div>
                </div>

                {/* Threat Classification breakdown */}
                <div className="bg-[#0b0f19]/60 border border-[#25a5ff]/15 p-6 rounded-2xl">
                  <h3 className="text-xs font-bold font-mono uppercase text-[#576575] tracking-wider mb-6 flex items-center gap-2">
                    <Shield size={14} className="text-red-500" /> Threat Level Shares
                  </h3>
                  <div className="h-48 w-full flex items-center justify-center relative">
                    {stats.total_analyzed === 0 ? (
                      <span className="text-xs font-mono text-[#576575]">No data available</span>
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={stats.chart_data_severity}
                            cx="50%"
                            cy="50%"
                            innerRadius={50}
                            outerRadius={70}
                            paddingAngle={5}
                            dataKey="value"
                          >
                            {stats.chart_data_severity.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                    )}
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-center">
                      <span className="block text-2xl font-black">{stats.total_analyzed}</span>
                      <span className="block text-[8px] font-mono text-[#576575] uppercase tracking-wider font-bold">Files</span>
                    </div>
                  </div>
                  
                  {/* Legend */}
                  <div className="grid grid-cols-3 gap-2 text-center text-[10px] font-mono mt-4 pt-4 border-t border-white/5">
                    <div>
                      <span className="block w-2.5 h-2.5 bg-red-500 rounded-full mx-auto mb-1" />
                      <span className="text-white font-bold">{stats.malicious} Malicious</span>
                    </div>
                    <div>
                      <span className="block w-2.5 h-2.5 bg-yellow-500 rounded-full mx-auto mb-1" />
                      <span className="text-white font-bold">{stats.suspicious} Suspicious</span>
                    </div>
                    <div>
                      <span className="block w-2.5 h-2.5 bg-green-500 rounded-full mx-auto mb-1" />
                      <span className="text-white font-bold">{stats.benign} Clean</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Recent threat activity list */}
              <div className="bg-[#0b0f19]/60 border border-[#25a5ff]/15 p-6 rounded-2xl">
                <h3 className="text-xs font-bold font-mono uppercase text-[#576575] tracking-wider mb-6 flex items-center gap-2">
                  <AlertTriangle size={14} className="text-[#ef4444]" /> Important Alerts
                </h3>
                {stats.alerts.length === 0 ? (
                  <div className="text-center py-6 text-xs text-[#576575] font-mono">No alerts identified in recent uploads.</div>
                ) : (
                  <div className="space-y-4">
                    {stats.alerts.map((alert) => (
                      <div key={alert.id} className="flex items-center justify-between p-4 rounded-xl border border-red-500/10 bg-red-950/5 hover:bg-red-950/10 transition-all">
                        <div className="flex items-center gap-3">
                          <AlertTriangle className="text-red-400 shrink-0" size={16} />
                          <div>
                            <span className="block text-xs text-white font-bold font-mono">{alert.file_name}</span>
                            <span className="block text-[9px] text-[#576575] font-mono uppercase">Detected: {alert.timestamp} | Risk Level {alert.score}%</span>
                          </div>
                        </div>
                        <button 
                          onClick={() => openAnalysisDetails(alert.id)}
                          className="px-3.5 py-1.5 rounded-lg border border-[#25a5ff]/20 text-[#25a5ff] text-[10px] font-mono font-bold uppercase tracking-wider hover:border-[#25a5ff] cursor-pointer transition-all"
                        >
                          Details
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

            </div>
          )}

          {/* DETONATION UPLOADER TAB */}
          {activeTab === 'detonate' && (
            <div className="space-y-8 animate-fadeIn">
              <div 
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-3xl p-16 text-center cursor-pointer transition-all ${isDragging ? 'border-[#25a5ff] bg-[#25a5ff]/5 scale-98 shadow-[0_0_50px_rgba(37,165,255,0.1)]' : 'border-[#25a5ff]/20 hover:border-[#25a5ff]/40 bg-[#070913]/30'}`}
              >
                <input 
                  type="file" 
                  multiple 
                  onChange={handleFileBrowse}
                  className="hidden" 
                  id="fileBrowseInput" 
                />
                <label htmlFor="fileBrowseInput" className="cursor-pointer">
                  <UploadCloud size={48} className="mx-auto text-[#25a5ff] drop-shadow-[0_0_15px_rgba(37,165,255,0.3)] mb-4 animate-bounce" />
                  <h2 className="text-md font-bold uppercase tracking-wider text-white">Upload Files</h2>
                  <p className="text-xs text-[#576575] font-mono mt-2 tracking-wide">Drag and drop file or click to browse files</p>
                  <span className="inline-block mt-4 text-[9px] text-[#576575] bg-white/5 border border-white/10 px-2 py-0.5 rounded font-mono uppercase font-bold tracking-widest">
                    MAX SIZE: 15MB | PE, DLL, ELF, ZIP, PDF, JS, bat, ps1
                  </span>
                </label>
              </div>

              {/* Upload queue list */}
              {uploadQueue.length > 0 && (
                <div className="bg-[#0b0f19]/60 border border-[#25a5ff]/15 p-6 rounded-2xl">
                  <h3 className="text-xs font-bold font-mono uppercase text-[#576575] tracking-wider mb-6">Upload Queue</h3>
                  <div className="space-y-4">
                    {uploadQueue.map((job) => (
                      <div key={job.id} className="p-4 rounded-xl bg-[#04060d] border border-white/5 flex items-center justify-between gap-4 font-mono text-xs">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1.5">
                            <FileCode size={14} className="text-[#25a5ff] shrink-0" />
                            <span className="text-white font-bold truncate">{job.name}</span>
                            <span className="text-[10px] text-[#576575]">({job.size})</span>
                          </div>
                          
                          {/* Upload Progress */}
                          <div className="flex items-center gap-3">
                            <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded shrink-0 ${job.status === 'COMPLETED' ? 'bg-green-500/10 text-green-400' : job.status === 'FAILED' ? 'bg-red-500/10 text-red-400' : 'bg-yellow-500/10 text-yellow-400 animate-pulse'}`}>
                              {job.status === 'PROCESSING' ? job.status_detail : job.status}
                            </span>
                            
                            {/* Animated loader progress bar */}
                            {job.status === 'PROCESSING' && (
                              <div className="w-48 h-1.5 bg-white/5 rounded-full overflow-hidden shrink-0">
                                <div className="h-full bg-gradient-to-r from-purple-500 to-[#25a5ff] animate-pulse" style={{ width: '85%' }} />
                              </div>
                            )}

                            {job.status === 'FAILED' && (
                              <span className="text-[10px] text-red-500 truncate">{job.status_detail}</span>
                            )}
                          </div>
                        </div>

                        {/* Actions */}
                        <div className="shrink-0 flex items-center gap-2">
                          {job.status === 'COMPLETED' && job.result && (
                            <button 
                              onClick={() => openAnalysisDetails(job.result.id)}
                              className="px-3 py-1.5 bg-[#25a5ff] text-black font-bold uppercase tracking-wider text-[10px] rounded-lg cursor-pointer hover:bg-white hover:shadow-[0_0_15px_#25a5ff] transition-all"
                            >
                              Report
                            </button>
                          )}
                          {(job.status === 'PROCESSING' || job.status === 'Waiting') && (
                            <button 
                              onClick={() => cancelQueueItem(job.id)}
                              className="text-[#576575] hover:text-white transition-colors cursor-pointer"
                            >
                              Cancel
                            </button>
                          )}
                          {job.status === 'FAILED' && (
                            <button 
                              onClick={() => cancelQueueItem(job.id)}
                              className="text-[#576575] hover:text-white transition-colors cursor-pointer"
                            >
                              Clear
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* THREAT INTEL FEEDS TAB */}
          {activeTab === 'threat_intel' && (
            <div className="space-y-8 animate-fadeIn">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold uppercase tracking-wider text-white">Threat Intelligence</h2>
                  <p className="text-xs text-[#576575] font-mono mt-1 uppercase">View information about known malware and suspicious indicators.</p>
                </div>
                <input 
                  type="text" 
                  value={intelSearch}
                  onChange={(e) => setIntelSearch(e.target.value)}
                  placeholder="Filter Threats..."
                  className="bg-[#04060d] border border-[#25a5ff]/15 rounded-xl px-4 py-2 text-xs text-white placeholder-[#576575] outline-none font-mono focus:border-[#25a5ff]"
                />
              </div>

              <div className="bg-[#0b0f19]/60 border border-[#25a5ff]/15 rounded-2xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs text-[#9aa4b2]">
                    <thead>
                      <tr className="border-b border-[#25a5ff]/15 bg-[#070913] text-[#576575]">
                        <th className="p-4 uppercase">Suspicious Indicator</th>
                        <th className="p-4 uppercase">Indicator Type</th>
                        <th className="p-4 uppercase">Attacker</th>
                        <th className="p-4 uppercase">Malware Type</th>
                        <th className="p-4 uppercase">Threat Level</th>
                        <th className="p-4 uppercase">Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {threatFeeds
                        .filter(f => f.value.toLowerCase().includes(intelSearch.toLowerCase()) || f.actor.toLowerCase().includes(intelSearch.toLowerCase()) || f.family.toLowerCase().includes(intelSearch.toLowerCase()))
                        .map((feed) => (
                          <tr key={feed.id} className="border-b border-[#25a5ff]/5 hover:bg-[#25a5ff]/5">
                            <td className="p-4 font-bold text-white font-mono break-all">{feed.value}</td>
                            <td className="p-4"><span className="px-2 py-0.5 bg-white/5 border border-white/10 rounded uppercase">{feed.type}</span></td>
                            <td className="p-4 text-purple-400 font-bold">{feed.actor}</td>
                            <td className="p-4 text-white font-bold">{feed.family}</td>
                            <td className="p-4">
                              <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${feed.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-yellow-500/10 text-yellow-400'}`}>
                                {feed.severity}
                              </span>
                            </td>
                            <td className="p-4 text-[#576575] max-w-xs truncate">{feed.description}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* SCAN LEDGER (HISTORY) TAB */}
          {activeTab === 'history' && (
            <div className="space-y-8 animate-fadeIn">
              <div className="flex flex-col sm:flex-row gap-4 items-center justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold uppercase tracking-wider text-white">Analysis History</h2>
                  <p className="text-xs text-[#576575] font-mono mt-1 uppercase">Review results of previously analyzed files.</p>
                </div>
                
                <div className="flex flex-wrap items-center gap-3">
                  <input 
                    type="text" 
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                    placeholder="Search Files..."
                    className="bg-[#04060d] border border-[#25a5ff]/15 rounded-xl px-4 py-2 text-xs text-white placeholder-[#576575] outline-none font-mono focus:border-[#25a5ff]"
                  />
                  <select 
                    value={historyFilter}
                    onChange={(e) => setHistoryFilter(e.target.value)}
                    className="bg-[#04060d] border border-[#25a5ff]/15 rounded-xl px-4 py-2 text-xs text-white outline-none font-mono text-center cursor-pointer"
                  >
                    <option value="ALL">All Results</option>
                    <option value="MALICIOUS">MALICIOUS</option>
                    <option value="SUSPICIOUS">SUSPICIOUS</option>
                    <option value="CLEAN">CLEAN</option>
                  </select>
                </div>
              </div>

              <div className="bg-[#0b0f19]/60 border border-[#25a5ff]/15 rounded-2xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs text-[#9aa4b2]">
                    <thead>
                      <tr className="border-b border-[#25a5ff]/15 bg-[#070913] text-[#576575]">
                        <th className="p-4 uppercase">File Name</th>
                        <th className="p-4 uppercase">File Hash (SHA-256)</th>
                        <th className="p-4 uppercase">Final Result</th>
                        <th className="p-4 uppercase">Threat Score</th>
                        <th className="p-4 uppercase">Analysis Time</th>
                        <th className="p-4 uppercase text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanHistory
                        .filter(log => {
                          const matchesSearch = log.name.toLowerCase().includes(historySearch.toLowerCase()) || log.hash.toLowerCase().includes(historySearch.toLowerCase());
                          const matchesFilter = historyFilter === 'ALL' || log.verdict === historyFilter;
                          return matchesSearch && matchesFilter;
                        })
                        .map((item) => (
                          <tr key={item.id} className="border-b border-[#25a5ff]/5 hover:bg-[#25a5ff]/5">
                            <td className="p-4 text-white font-bold max-w-xs truncate">{item.name}</td>
                            <td className="p-4 font-mono text-[#576575] text-[11px]">{item.hash}</td>
                            <td className="p-4">
                              <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${item.verdict === 'MALICIOUS' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : item.verdict === 'SUSPICIOUS' ? 'bg-yellow-500/10 text-yellow-400' : 'bg-green-500/10 text-green-400'}`}>
                                {item.verdict}
                              </span>
                            </td>
                            <td className="p-4 font-bold text-white">{item.score}%</td>
                            <td className="p-4 text-[#576575]">{item.time}</td>
                            <td className="p-4 text-right">
                              <div className="flex items-center justify-end gap-3">
                                <button 
                                  onClick={() => openAnalysisDetails(item.id)}
                                  className="text-[#25a5ff] hover:underline flex items-center gap-1 cursor-pointer"
                                >
                                  <Eye size={12} /> View
                                </button>
                                <button 
                                  onClick={() => handleDownloadPDF(item.id)}
                                  className="text-emerald-400 hover:underline flex items-center gap-1 cursor-pointer"
                                >
                                  <Download size={12} /> PDF
                                </button>
                                <button 
                                  onClick={() => handleHistoryDelete(item.id)}
                                  className="text-red-400 hover:text-red-300 cursor-pointer"
                                >
                                  <Trash2 size={12} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* NOTIFICATIONS / ALERTS TAB */}
          {activeTab === 'notifications' && (
            <div className="space-y-8 animate-fadeIn">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-xl font-bold uppercase tracking-wider text-white">Notifications</h2>
                  <p className="text-xs text-[#576575] font-mono mt-1 uppercase">View system updates and threat alerts.</p>
                </div>
                {notifications.length > 0 && (
                  <button 
                    onClick={handleClearAllNotifications}
                    className="px-4 py-2 border border-red-500/30 text-red-400 hover:border-red-500 rounded-xl text-xs font-mono font-bold uppercase cursor-pointer transition-all"
                  >
                    Clear All Notifications
                  </button>
                )}
              </div>

              {notifications.length === 0 ? (
                <div className="text-center py-16 bg-[#0b0f19]/30 border border-[#25a5ff]/15 rounded-3xl text-xs text-[#576575] font-mono">
                  No notifications or alerts currently available.
                </div>
              ) : (
                <div className="space-y-4">
                  {notifications.map((notif) => (
                    <div key={notif.id} className="p-5 rounded-2xl border border-white/5 bg-[#0b0f19]/60 flex items-center justify-between gap-4 font-mono text-xs hover:border-[#25a5ff]/20 transition-all">
                      <div>
                        <div className="flex items-center gap-2.5 mb-1.5">
                          <Radio size={14} className="text-[#25a5ff] animate-pulse" />
                          <span className="text-white font-bold font-sans text-sm">{notif.title}</span>
                          <span className="text-[10px] text-[#576575]">({notif.created_at})</span>
                        </div>
                        <p className="text-[#9aa4b2] font-sans leading-relaxed">{notif.message}</p>
                      </div>
                      <button 
                        onClick={() => handleDismissNotification(notif.id)}
                        className="text-[#576575] hover:text-white cursor-pointer transition-colors"
                      >
                        Dismiss
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* WORLD THREAT GLOBE MAP TAB */}
          {activeTab === 'world_map' && (
            <WorldThreatGlobe />
          )}

        </div>
      </main>

      {/* ANALYSIS REPORT DETAILED VISUALIZER MODAL */}
      {isDetailModalOpen && selectedAnalysis && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md overflow-y-auto animate-fadeIn">
          <div className="bg-[#070913] border border-[#25a5ff]/30 w-full max-w-5xl rounded-3xl max-h-[90vh] overflow-y-auto flex flex-col text-white font-sans shadow-[0_0_80px_rgba(37,165,255,0.15)] relative">
            
            {/* Modal Header */}
            <div className="p-6 border-b border-[#25a5ff]/15 flex items-center justify-between sticky top-0 bg-[#070913]/95 backdrop-blur-xl z-20">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-[#25a5ff]/5 border border-[#25a5ff]/30 rounded-xl">
                  <Shield className="text-[#25a5ff]" size={18} />
                </div>
                <div>
                  <h3 className="text-md font-bold truncate max-w-md">{selectedAnalysis.file_name}</h3>
                  <span className="block text-[10px] font-mono text-[#576575] break-all uppercase">SHA-256: {selectedAnalysis.sha256}</span>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button 
                  onClick={() => handleDownloadPDF(selectedAnalysis.id)}
                  className="px-4 py-2 bg-emerald-500/10 border border-emerald-500/30 hover:border-emerald-500 text-emerald-400 rounded-xl text-xs font-mono font-bold uppercase flex items-center gap-1.5 cursor-pointer transition-all"
                >
                  <Download size={14} /> PDF Brief
                </button>
                <button 
                  onClick={() => setIsDetailModalOpen(false)}
                  className="text-[#576575] hover:text-white font-mono text-sm px-3.5 py-1.5 rounded-xl hover:bg-white/5 cursor-pointer"
                >
                  [CLOSE]
                </button>
              </div>
            </div>

            {/* Modal Content Scrollable Grid */}
            <div className="p-8 space-y-8 flex-1">
              
              {/* Verdict Summary Box */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-[#0b0f19]/70 border border-[#25a5ff]/15 p-6 rounded-2xl text-center flex flex-col justify-center">
                  <span className="text-[10px] font-mono text-[#576575] uppercase tracking-wider font-bold mb-2">Final Result</span>
                  <span className={`text-3xl font-black ${selectedAnalysis.malware_classification.verdict === 'MALICIOUS' ? 'text-red-400' : selectedAnalysis.malware_classification.verdict === 'SUSPICIOUS' ? 'text-yellow-400' : 'text-green-400'}`}>
                    {selectedAnalysis.malware_classification.verdict}
                  </span>
                </div>
                <div className="bg-[#0b0f19]/70 border border-[#25a5ff]/15 p-6 rounded-2xl text-center flex flex-col justify-center">
                  <span className="text-[10px] font-mono text-[#576575] uppercase tracking-wider font-bold mb-2">Threat Score</span>
                  <span className="text-3xl font-black">{selectedAnalysis.malware_classification.score}%</span>
                </div>
                <div className="bg-[#0b0f19]/70 border border-[#25a5ff]/15 p-6 rounded-2xl text-center flex flex-col justify-center">
                  <span className="text-[10px] font-mono text-[#576575] uppercase tracking-wider font-bold mb-2">File Uniqueness (Entropy)</span>
                  <span className="text-3xl font-black">{selectedAnalysis.entropy}</span>
                </div>
              </div>

              {/* Technical details grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                
                {/* Structural boundaries */}
                <div className="bg-[#0b0f19]/40 border border-white/5 p-6 rounded-2xl space-y-4 font-mono text-xs">
                  <h4 className="text-[#25a5ff] font-bold uppercase tracking-wider text-xs border-b border-[#25a5ff]/15 pb-2">File Details</h4>
                  <div className="flex justify-between"><span className="text-[#576575]">File Size:</span> <span>{(selectedAnalysis.file_size_bytes / 1024).toFixed(1)} KB</span></div>
                  <div className="flex justify-between"><span className="text-[#576575]">Compiler Type:</span> <span className="text-white truncate max-w-xs">{selectedAnalysis.compiler_info}</span></div>
                  <div className="flex justify-between"><span className="text-[#576575]">Security Signature:</span> <span className="text-white">{selectedAnalysis.digital_signature}</span></div>
                  <div className="flex justify-between"><span className="text-[#576575]">Is Windows Program:</span> <span>{selectedAnalysis.is_pe ? 'YES' : 'NO'}</span></div>
                  <div className="flex justify-between"><span className="text-[#576575]">Analysis Duration:</span> <span>{selectedAnalysis.scan_duration_seconds} seconds</span></div>
                </div>

                {/* Hashes metadata */}
                <div className="bg-[#0b0f19]/40 border border-white/5 p-6 rounded-2xl space-y-4 font-mono text-[11px]">
                  <h4 className="text-[#25a5ff] font-bold uppercase tracking-wider text-xs border-b border-[#25a5ff]/15 pb-2">File Hashes</h4>
                  <div><span className="text-[#576575] block uppercase">MD5:</span> <span className="text-white">{selectedAnalysis.hashes.md5}</span></div>
                  <div><span className="text-[#576575] block uppercase">SHA-1:</span> <span className="text-white">{selectedAnalysis.hashes.sha1}</span></div>
                  <div><span className="text-[#576575] block uppercase">SHA-256:</span> <span className="text-white">{selectedAnalysis.hashes.sha256}</span></div>
                </div>
              </div>

              {/* Suspicious APIs and YARA matching */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                
                {/* Suspicious APIs */}
                <div className="bg-[#0b0f19]/40 border border-white/5 p-6 rounded-2xl">
                  <h4 className="text-[#25a5ff] font-mono font-bold uppercase tracking-wider text-xs border-b border-[#25a5ff]/15 pb-2 mb-4">Suspicious Code Functions</h4>
                  {selectedAnalysis.suspicious_apis.length === 0 ? (
                    <p className="text-xs text-[#576575] font-mono">No suspicious code functions found.</p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {selectedAnalysis.suspicious_apis.map((api, idx) => (
                        <span key={idx} className="bg-red-500/10 border border-red-500/20 text-red-400 font-mono text-[10px] px-2.5 py-1 rounded-lg">{api}</span>
                      ))}
                    </div>
                  )}
                </div>

                {/* YARA signature hits */}
                <div className="bg-[#0b0f19]/40 border border-white/5 p-6 rounded-2xl">
                  <h4 className="text-[#25a5ff] font-mono font-bold uppercase tracking-wider text-xs border-b border-[#25a5ff]/15 pb-2 mb-4">YARA Signatures</h4>
                  {selectedAnalysis.yara_matches.length === 0 ? (
                    <p className="text-xs text-[#576575] font-mono">No YARA signatures triggered.</p>
                  ) : (
                    <div className="space-y-2">
                      {selectedAnalysis.yara_matches.map((rule, idx) => (
                        <div key={idx} className="flex items-center gap-2 bg-red-950/20 border border-red-500/20 p-2.5 rounded-xl text-xs text-red-400 font-mono">
                          <AlertTriangle size={14} /> Rule hit: {rule}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* MITRE ATT&CK Matrix and Extracted IOCs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                
                {/* MITREATTACK */}
                <div className="bg-[#0b0f19]/40 border border-white/5 p-6 rounded-2xl">
                  <h4 className="text-[#25a5ff] font-mono font-bold uppercase tracking-wider text-xs border-b border-[#25a5ff]/15 pb-2 mb-4">Attack Techniques</h4>
                  {selectedAnalysis.mitre_attack.length === 0 ? (
                    <p className="text-xs text-[#576575] font-mono">No attack techniques found.</p>
                  ) : (
                    <div className="space-y-2">
                      {selectedAnalysis.mitre_attack.map((t, idx) => (
                        <div key={idx} className="bg-purple-950/20 border border-purple-500/20 p-2.5 rounded-xl text-xs text-purple-400 font-mono">
                          {t}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Extracted IOCs */}
                <div className="bg-[#0b0f19]/40 border border-white/5 p-6 rounded-2xl space-y-4 text-xs font-mono">
                  <h4 className="text-[#25a5ff] font-mono font-bold uppercase tracking-wider text-xs border-b border-[#25a5ff]/15 pb-2">Suspicious Indicators</h4>
                  <div>
                    <span className="text-[#576575] block mb-1">Suspicious IP Addresses ({selectedAnalysis.iocs.ips.length})</span>
                    {selectedAnalysis.iocs.ips.length === 0 ? (
                      <span className="text-[#576575] text-[10px]">None identified</span>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {selectedAnalysis.iocs.ips.map((ip, i) => <span key={i} className="bg-white/5 px-2 py-0.5 rounded text-[10px] text-white">{ip}</span>)}
                      </div>
                    )}
                  </div>
                  <div>
                    <span className="text-[#576575] block mb-1">Suspicious Domains ({selectedAnalysis.iocs.domains.length})</span>
                    {selectedAnalysis.iocs.domains.length === 0 ? (
                      <span className="text-[#576575] text-[10px]">None identified</span>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {selectedAnalysis.iocs.domains.map((dom, i) => <span key={i} className="bg-white/5 px-2 py-0.5 rounded text-[10px] text-white truncate max-w-xs">{dom}</span>)}
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Embedded strings scroll */}
              <div className="bg-[#0b0f19]/40 border border-white/5 p-6 rounded-2xl">
                <h4 className="text-[#25a5ff] font-mono font-bold uppercase tracking-wider text-xs border-b border-[#25a5ff]/15 pb-2 mb-4">Embedded Strings (Found Text)</h4>
                <div className="bg-[#04060d] border border-white/5 p-4 rounded-2xl h-48 overflow-y-auto font-mono text-[10px] text-[#9aa4b2] leading-relaxed">
                  {selectedAnalysis.embedded_strings.map((str, idx) => (
                    <div key={idx} className="hover:bg-white/5 px-2 py-0.5 rounded truncate">{str}</div>
                  ))}
                </div>
              </div>

              {/* VirusTotal Reputations Section */}
              <div className="bg-[#0b0f19]/40 border border-white/5 p-6 rounded-2xl">
                <h4 className="text-[#25a5ff] font-mono font-bold uppercase tracking-wider text-xs border-b border-[#25a5ff]/15 pb-2 mb-4">VirusTotal Results</h4>
                {!selectedAnalysis.virus_total_report.positives ? (
                  <p className="text-xs text-[#576575] font-mono">VirusTotal results empty. Provide a VirusTotal API Key in settings to compare findings.</p>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
                    <div className="bg-white/5 p-4 rounded-xl">
                      <span className="text-[#576575] block mb-1">Detections</span>
                      <span className="text-md font-bold text-red-400">{selectedAnalysis.virus_total_report.positives} / {selectedAnalysis.virus_total_report.total} AVs</span>
                    </div>
                    <div className="bg-white/5 p-4 rounded-xl">
                      <span className="text-[#576575] block mb-1">Scan Status</span>
                      <span className="text-md font-bold text-white truncate block">{selectedAnalysis.virus_total_report.scan_id ? 'Scan completed' : 'N/A'}</span>
                    </div>
                    <div className="bg-white/5 p-4 rounded-xl">
                      <span className="text-[#576575] block mb-1">Analysis Link</span>
                      <span className="text-md font-bold text-white">{selectedAnalysis.virus_total_report.permalink ? <a href={selectedAnalysis.virus_total_report.permalink} target="_blank" rel="noreferrer" className="text-[#25a5ff] hover:underline">Link to VT Page</a> : 'N/A'}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Claude SecOps Autonomous AI Agent Workspace */}
              <div className="bg-[#0b0f19]/60 border border-[#25a5ff]/25 p-6 rounded-2xl space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#25a5ff]/15 pb-4">
                  <div>
                    <h4 className="text-sm font-bold font-mono uppercase text-[#25a5ff] tracking-wider flex items-center gap-2">
                      <Terminal size={16} className="text-[#25a5ff]" /> AI Security Assistant
                    </h4>
                    <p className="text-[10px] text-[#576575] font-mono mt-1">Ask the AI to explain malware behavior and security findings.</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="relative flex h-2 w-2">
                      <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${isAiLoading ? 'bg-amber-400' : 'bg-green-400'}`}></span>
                      <span className={`relative inline-flex rounded-full h-2 w-2 ${isAiLoading ? 'bg-amber-500' : 'bg-green-500'}`}></span>
                    </span>
                    <span className="text-[10px] font-mono text-white tracking-wider">
                      {isAiLoading ? 'AI: ANALYZING...' : 'AI: READY'}
                    </span>
                  </div>
                </div>

                {/* Claude Agent Debugger Console Logs (True Realtime Logs Feed) */}
                <div className="bg-[#020408] border border-[#25a5ff]/15 rounded-xl p-4 font-mono text-[10px] text-green-400 h-32 overflow-y-auto space-y-1 shadow-[inset_0_0_15px_rgba(0,0,0,0.8)]">
                  <div className="text-white/40 border-b border-white/5 pb-1 mb-2 uppercase tracking-wider flex justify-between">
                    <span>AI Activity Logs</span>
                    <span className="text-[9px] text-[#25a5ff]">PID: {Math.floor(Math.random() * 9000 + 1000)}</span>
                  </div>
                  {agentLogs.map((log, idx) => (
                    <div key={idx} className="leading-relaxed whitespace-pre-wrap">{log}</div>
                  ))}
                  {isAiLoading && (
                    <div className="animate-pulse text-[#25a5ff]">&gt;&gt; [PENDING] Sending secure REST call to Claude Node...</div>
                  )}
                </div>

                {/* Interactive Preset Action Command Deck */}
                <div className="space-y-2">
                  <h5 className="text-[10px] font-mono font-bold uppercase text-[#576575] tracking-wider">AI Actions</h5>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <button
                      type="button"
                      disabled={isAiLoading}
                      onClick={() => executeAgentAction("/audit-apis", "Investigate all imported APIs and suspicious system calls. Highlight and explain functions related to evasion, injection, or networking.")}
                      className="bg-[#04060d] hover:bg-[#25a5ff]/10 border border-[#25a5ff]/20 hover:border-[#25a5ff]/50 px-3 py-2.5 rounded-xl text-left transition-all group disabled:opacity-50"
                    >
                      <div className="text-[10px] font-mono font-bold text-white group-hover:text-[#25a5ff]">🔍 Audit Code</div>
                      <div className="text-[8px] text-[#576575] font-mono mt-0.5">Explain suspicious functions</div>
                    </button>
                    <button
                      type="button"
                      disabled={isAiLoading}
                      onClick={() => executeAgentAction("/yara-forge", "Generate a custom, production-ready YARA signature rule specifically tailored to detect this file's attributes (entropy, imports, strings) and include comments explaining each field.")}
                      className="bg-[#04060d] hover:bg-[#25a5ff]/10 border border-[#25a5ff]/20 hover:border-[#25a5ff]/50 px-3 py-2.5 rounded-xl text-left transition-all group disabled:opacity-50"
                    >
                      <div className="text-[10px] font-mono font-bold text-white group-hover:text-[#25a5ff]">🛡️ YARA Rules</div>
                      <div className="text-[8px] text-[#576575] font-mono mt-0.5">Write custom match rules</div>
                    </button>
                    <button
                      type="button"
                      disabled={isAiLoading}
                      onClick={() => executeAgentAction("/mitre-map", "Perform a complete mapping of this file's attributes to the MITRE ATT&CK framework. Provide detailed explanations for each technique (e.g. Injection, Evasion) and suggest defensive counters.")}
                      className="bg-[#04060d] hover:bg-[#25a5ff]/10 border border-[#25a5ff]/20 hover:border-[#25a5ff]/50 px-3 py-2.5 rounded-xl text-left transition-all group disabled:opacity-50"
                    >
                      <div className="text-[10px] font-mono font-bold text-white group-hover:text-[#25a5ff]">🚨 Attack Techniques</div>
                      <div className="text-[8px] text-[#576575] font-mono mt-0.5">Map code to attack techniques</div>
                    </button>
                    <button
                      type="button"
                      disabled={isAiLoading}
                      onClick={() => executeAgentAction("/remediate", "Write an actionable remediation playbook script (PowerShell or Bash) to clean up files, registry keys, and processes that this malware might spawn.")}
                      className="bg-[#04060d] hover:bg-[#25a5ff]/10 border border-[#25a5ff]/20 hover:border-[#25a5ff]/50 px-3 py-2.5 rounded-xl text-left transition-all group disabled:opacity-50"
                    >
                      <div className="text-[10px] font-mono font-bold text-white group-hover:text-[#25a5ff]">🧪 How to Fix</div>
                      <div className="text-[8px] text-[#576575] font-mono mt-0.5">Create clean up script</div>
                    </button>
                  </div>
                </div>

                {/* Conversation Panel */}
                <div className="space-y-4 pt-2">
                  <h5 className="text-[10px] font-mono font-bold uppercase text-[#576575] tracking-wider">AI Chat History</h5>
                  
                  <div className="space-y-4 max-h-96 overflow-y-auto p-4 bg-[#04060d] border border-white/5 rounded-2xl text-xs">
                    {/* Render initial report message as baseline */}
                    <div className="bg-white/5 text-[#9aa4b2] p-4 rounded-xl mr-auto text-left whitespace-pre-wrap font-sans border border-white/5">
                      <span className="block text-[8px] text-[#25a5ff] mb-2 font-mono font-bold uppercase">🚨 AI Analysis Summary</span>
                      {selectedAnalysis.ai_generated_report || "No initial playbook generated."}
                    </div>

                    {/* Chat history list */}
                    {aiReportChat.map((msg, i) => (
                      <div key={i} className={`p-4 rounded-xl max-w-2xl border ${msg.role === 'user' ? 'bg-[#25a5ff]/5 border-[#25a5ff]/30 ml-auto text-right text-white font-mono' : 'bg-white/5 border-white/5 text-[#9aa4b2] mr-auto text-left whitespace-pre-wrap font-sans'}`}>
                        <span className="block text-[8px] text-[#576575] mb-2 font-mono font-bold uppercase">
                          {msg.role === 'user' ? 'USER' : 'AI ASSISTANT'}
                        </span>
                        {msg.text}
                      </div>
                    ))}

                    {isAiLoading && (
                      <div className="flex items-center gap-2 text-xs text-[#576575] font-mono bg-white/5 p-4 rounded-xl mr-auto border border-white/5">
                        <span className="animate-bounce">●</span>
                        <span className="animate-bounce [animation-delay:0.2s]">●</span>
                        <span className="animate-bounce [animation-delay:0.4s]">●</span>
                        <span>AI is analyzing file details...</span>
                      </div>
                    )}
                  </div>

                  {/* Conversation Input Bar */}
                  <form onSubmit={submitAiQuestion} className="flex gap-3">
                    <input 
                      type="text"
                      value={aiReportQuery}
                      onChange={(e) => setAiReportQuery(e.target.value)}
                      placeholder="ENTER MANUAL COMMAND OR TASK (E.G. EXPLAIN APIS, mitigation vectors...)"
                      className="flex-1 bg-[#04060d] border border-[#25a5ff]/20 rounded-xl px-4 py-3 text-xs text-white placeholder-[#576575] focus:border-[#25a5ff] outline-none font-mono tracking-wide"
                    />
                    <button 
                      type="submit" 
                      disabled={isAiLoading || !aiReportQuery.trim()}
                      className="px-5 bg-[#25a5ff] text-black font-bold font-mono uppercase tracking-wider text-[10px] rounded-xl cursor-pointer hover:bg-white transition-all disabled:opacity-50 flex items-center gap-1.5"
                    >
                      <span>EXECUTE</span>
                    </button>
                  </form>
                </div>
              </div>

            </div>

          </div>
        </div>
      )}

    </div>
  );
}

function WorldThreatGlobe() {
  const canvasRef = React.useRef(null);
  const [worldLogs, setWorldLogs] = useState([
    { id: 1, time: new Date().toLocaleTimeString(), type: 'Ransomware push', source: 'Pyongyang', target: 'London', status: 'ACTIVE', actor: 'Lazarus Group' },
    { id: 2, time: new Date().toLocaleTimeString(), type: 'Zero-Day Exploit', source: 'Chengdu', target: 'Berlin', status: 'SUCCESS', actor: 'APT41' }
  ]);
  
  const [agentMapLogs, setAgentMapLogs] = useState([
    `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Listening on global attack vectors...`
  ]);
  const [isAgentMapLoading, setIsAgentMapLoading] = useState(false);
  const [selectedThreatLog, setSelectedThreatLog] = useState(null);

  const handleMapAgentInvestigation = async (log) => {
    if (isAgentMapLoading) return;
    setIsAgentMapLoading(true);
    setSelectedThreatLog(log);
    
    setAgentMapLogs(prev => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] COMMAND: /investigate_threat --actor "${log.actor}" --target "${log.target}"`,
      `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Fetching intelligence briefs for ${log.actor}...`,
      `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Mapping TTP signatures to historical outbreaks...`
    ]);

    try {
      const res = await fetch(`${API_BASE}/api/v1/ai-report/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysis_results: {
            file_name: `${log.actor}_Infiltration_Vector`,
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            entropy: 7.9,
            yara_matches: [log.type],
            iocs: { ips: ["194.22.84.11"], domains: ["c2-command-hub.net"], registry_keys: [] }
          },
          query: `Write a quick, highly professional threat advisory bulletin about ${log.actor} targeting ${log.target} using ${log.type}. Outline threat motives, historical context, and immediate remediation steps.`
        })
      });

      if (res.ok) {
        const data = await res.json();
        setAgentMapLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Advisory completed. Rendering bulletin below:`,
          `--------------------------------------------------------------------------------`,
          data.report,
          `--------------------------------------------------------------------------------`
        ]);
      } else {
        setAgentMapLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Error contacting Secure Node.`]);
      }
    } catch (err) {
      setAgentMapLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Connection timeout.`]);
    } finally {
      setIsAgentMapLoading(false);
    }
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    let animationFrameId;
    let rotationY = 0;
    let rotationX = 0.25; 
    
    const radius = 120;
    
    const CITIES = {
      Pyongyang: { lat: 39.03, lon: 125.76, name: "Pyongyang", color: "#ef4444" },
      Chengdu: { lat: 30.57, lon: 104.06, name: "Chengdu", color: "#f59e0b" },
      Moscow: { lat: 55.75, lon: 37.61, name: "Moscow", color: "#a855f7" },
      "Washington D.C.": { lat: 38.90, lon: -77.03, name: "Washington D.C.", color: "#25a5ff" },
      London: { lat: 51.50, lon: -0.12, name: "London", color: "#10b981" },
      Berlin: { lat: 52.52, lon: 13.40, name: "Berlin", color: "#3b82f6" },
      Chicago: { lat: 41.87, lon: -87.62, name: "Chicago", color: "#38bdf8" },
      Sydney: { lat: -33.86, lon: 151.20, name: "Sydney", color: "#ec4899" },
      Frankfurt: { lat: 50.11, lon: 8.68, name: "Frankfurt", color: "#6366f1" },
      Tokyo: { lat: 35.67, lon: 139.65, name: "Tokyo", color: "#14b8a6" }
    };

    const latLonTo3D = (lat, lon) => {
      const theta = lat * Math.PI / 180;
      const phi = lon * Math.PI / 180;
      return {
        x: radius * Math.cos(theta) * Math.sin(phi),
        y: -radius * Math.sin(theta),
        z: radius * Math.cos(theta) * Math.cos(phi)
      };
    };

    let activeArcs = [];
    
    const simAttacksList = [
      { source: 'Pyongyang', target: 'London', actor: 'Lazarus Group', type: 'Ransomware push' },
      { source: 'Chengdu', target: 'Berlin', actor: 'APT41', type: 'Zero-Day Exploit' },
      { source: 'Moscow', target: 'Washington D.C.', actor: 'Fancy Bear', type: 'Phishing Storm' },
      { source: 'London', target: 'Tokyo', actor: 'Fin7', type: 'POS Scraper payload' },
      { source: 'Tokyo', target: 'Sydney', actor: 'DarkSide', type: 'Double Extortion push' },
      { source: 'Washington D.C.', target: 'Frankfurt', actor: 'Equation Group', type: 'Rootkit payload' }
    ];

    const launchAttackSim = () => {
      const template = simAttacksList[Math.floor(Math.random() * simAttacksList.length)];
      if (activeArcs.some(a => a.source === template.source && a.target === template.target)) return;
      
      const arcId = Math.random();
      activeArcs.push({
        id: arcId,
        source: template.source,
        target: template.target,
        progress: 0,
        speed: 0.012 + Math.random() * 0.008,
        color: template.source === 'Pyongyang' ? '#ef4444' : template.source === 'Chengdu' ? '#f59e0b' : '#a855f7'
      });

      const newLog = {
        id: Math.random(),
        time: new Date().toLocaleTimeString(),
        type: template.type,
        source: template.source,
        target: template.target,
        status: 'ACTIVE',
        actor: template.actor
      };

      setWorldLogs(prev => [newLog, ...prev.slice(0, 14)]);
      
      setAgentMapLogs(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] CLAUDE_AGENT: Outbreak alert - ${template.actor} triggered "${template.type}" targetting ${template.target}.`
      ]);
    };

    const interval = setInterval(launchAttackSim, 3500);

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;
      
      rotationY += 0.005;
      
      const project = (x, y, z) => {
        let x1 = x * Math.cos(rotationY) - z * Math.sin(rotationY);
        let z1 = x * Math.sin(rotationY) + z * Math.cos(rotationY);
        let y2 = y * Math.cos(rotationX) - z1 * Math.sin(rotationX);
        let z2 = y * Math.sin(rotationX) + z1 * Math.cos(rotationX);
        const distance = 350;
        const scale = distance / (distance + z2);
        return {
          x: centerX + x1 * scale,
          y: centerY + y2 * scale,
          zDepth: z2 
        };
      };

      const radialGrad = ctx.createRadialGradient(centerX, centerY, 5, centerX, centerY, radius + 30);
      radialGrad.addColorStop(0, 'rgba(37, 165, 255, 0.03)');
      radialGrad.addColorStop(0.8, 'rgba(124, 58, 237, 0.01)');
      radialGrad.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = radialGrad;
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius + 40, 0, Math.PI * 2);
      ctx.fill();

      ctx.lineWidth = 0.5;
      
      for (let i = -4; i <= 4; i++) {
        const bandLat = (i * 18) * Math.PI / 180;
        const bandR = radius * Math.cos(bandLat);
        const bandY = -radius * Math.sin(bandLat);
        
        ctx.beginPath();
        for (let j = 0; j <= 50; j++) {
          const bandLon = (j * 7.2) * Math.PI / 180;
          const x = bandR * Math.sin(bandLon);
          const z = bandR * Math.cos(bandLon);
          const pt = project(x, bandY, z);
          ctx.strokeStyle = pt.zDepth > 0 ? 'rgba(37, 165, 255, 0.04)' : 'rgba(37, 165, 255, 0.12)';
          if (j === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.stroke();
      }

      for (let i = 0; i < 10; i++) {
        const lonAngle = (i * 18) * Math.PI / 180;
        ctx.beginPath();
        for (let j = 0; j <= 50; j++) {
          const latAngle = (j * 7.2) * Math.PI / 180;
          const x = radius * Math.cos(latAngle) * Math.sin(lonAngle);
          const y = -radius * Math.sin(latAngle);
          const z = radius * Math.cos(latAngle) * Math.cos(lonAngle);
          const pt = project(x, y, z);
          ctx.strokeStyle = pt.zDepth > 0 ? 'rgba(37, 165, 255, 0.04)' : 'rgba(37, 165, 255, 0.12)';
          if (j === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
        }
        ctx.stroke();
      }

      activeArcs.forEach((arc) => {
        const sCity = CITIES[arc.source];
        const tCity = CITIES[arc.target];
        if (!sCity || !tCity) return;
        
        const s3d = latLonTo3D(sCity.lat, sCity.lon);
        const t3d = latLonTo3D(tCity.lat, tCity.lon);
        
        ctx.beginPath();
        let prevPt = null;
        const stepsCount = 30;
        const limitStep = Math.floor(stepsCount * arc.progress);
        
        for (let k = 0; k <= limitStep; k++) {
          const t = k / stepsCount;
          const xC = s3d.x * (1 - t) + t3d.x * t;
          const yC = s3d.y * (1 - t) + t3d.y * t;
          const zC = s3d.z * (1 - t) + t3d.z * t;
          const len = Math.sqrt(xC * xC + yC * yC + zC * zC);
          const uX = xC / len;
          const uY = yC / len;
          const uZ = zC / len;
          const heightOffset = 35 * Math.sin(t * Math.PI);
          const xF = xC + uX * heightOffset;
          const yF = yC + uY * heightOffset;
          const zF = zC + uZ * heightOffset;
          
          const pt = project(xF, yF, zF);
          ctx.strokeStyle = arc.color + (pt.zDepth > 0 ? '25' : '99'); 
          ctx.lineWidth = pt.zDepth > 0 ? 0.75 : 1.5;
          
          if (k === 0) ctx.moveTo(pt.x, pt.y);
          else ctx.lineTo(pt.x, pt.y);
          prevPt = pt;
        }
        ctx.stroke();
        
        if (prevPt) {
          ctx.beginPath();
          ctx.fillStyle = '#ffffff';
          ctx.shadowColor = arc.color;
          ctx.shadowBlur = 10;
          ctx.arc(prevPt.x, prevPt.y, prevPt.zDepth > 0 ? 2 : 3.5, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0; 
        }
        
        arc.progress += arc.speed;
        if (arc.progress >= 1.0) {
          setWorldLogs(prev => prev.map(l => {
            if (l.source === arc.source && l.target === arc.target && l.status === 'ACTIVE') {
              return { ...l, status: 'SUCCESS' };
            }
            return l;
          }));
        }
      });
      
      activeArcs = activeArcs.filter(a => a.progress < 1.0);

      Object.values(CITIES).forEach(city => {
        const c3d = latLonTo3D(city.lat, city.lon);
        const pt = project(c3d.x, c3d.y, c3d.z);
        if (pt.zDepth < 0) {
          const pulse = 1 + 0.25 * Math.sin(Date.now() / 200 + city.lat);
          ctx.beginPath();
          ctx.fillStyle = city.color;
          ctx.shadowColor = city.color;
          ctx.shadowBlur = 8;
          ctx.arc(pt.x, pt.y, 3 * pulse, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
          
          ctx.beginPath();
          ctx.strokeStyle = city.color + '40';
          ctx.lineWidth = 0.5;
          ctx.arc(pt.x, pt.y, 8 * pulse, 0, Math.PI * 2);
          ctx.stroke();
          
          ctx.fillStyle = '#ffffffb0';
          ctx.font = '8px monospace';
          ctx.fillText(city.name, pt.x + 8, pt.y + 3);
        }
      });
      
      animationFrameId = requestAnimationFrame(render);
    };
    
    render();
    
    return () => {
      cancelAnimationFrame(animationFrameId);
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="space-y-8 animate-fadeIn">
      <div>
        <h2 className="text-xl font-bold uppercase tracking-wider text-white">3D Threat Globe</h2>
        <p className="text-xs text-[#576575] font-mono mt-1 uppercase">View simulated malware threat activity on a rotating 3D globe.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        <div className="lg:col-span-7 bg-[#050711]/60 border border-[#25a5ff]/15 rounded-3xl p-6 flex flex-col items-center justify-center relative overflow-hidden h-[420px] shadow-[0_0_50px_rgba(0,0,0,0.5)]">
          <div className="absolute top-4 left-4 bg-black/60 border border-white/5 rounded-xl px-3 py-1.5 font-mono text-[9px] text-[#25a5ff] uppercase tracking-wider z-10 flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#25a5ff] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#25a5ff]"></span>
            </span>
            <span>Real-time Threat Activity</span>
          </div>

          <canvas 
            ref={canvasRef} 
            width={480} 
            height={340} 
            className="cursor-pointer max-w-full drop-shadow-[0_0_30px_rgba(37,165,255,0.15)]"
          />

          <div className="absolute bottom-4 left-4 right-4 flex justify-between font-mono text-[8px] text-[#576575] uppercase border-t border-white/5 pt-2">
            <span>Projection: orthographic 3d</span>
            <span>Grid scale: R=120px</span>
            <span>FPS: 60 (Hardware Accelerated)</span>
          </div>
        </div>

        <div className="lg:col-span-5 flex flex-col gap-6">
          <div className="bg-[#020408]/90 border border-[#25a5ff]/20 rounded-3xl p-5 flex flex-col h-[200px] shadow-[0_0_20px_rgba(0,0,0,0.8)]">
            <h4 className="text-[10px] font-mono font-bold text-white uppercase tracking-wider border-b border-[#25a5ff]/15 pb-2 mb-3 flex items-center justify-between">
              <span className="flex items-center gap-1.5"><Terminal size={12} className="text-[#25a5ff]" /> AI Security Assistant Console</span>
              <span className="text-green-500 text-[8px] animate-pulse">● SECURE GATEWAY</span>
            </h4>
            <div className="flex-1 overflow-y-auto font-mono text-[9px] text-green-400 space-y-1 scrollbar-none leading-relaxed">
              {agentMapLogs.map((log, idx) => (
                <div key={idx} className="whitespace-pre-wrap">{log}</div>
              ))}
              {isAgentMapLoading && (
                <div className="text-[#25a5ff] animate-pulse">&gt;&gt; Fetching autonomous intelligence advisories...</div>
              )}
            </div>
          </div>

          <div className="bg-[#050711]/60 border border-[#25a5ff]/15 rounded-3xl p-5 flex flex-col h-[200px] shadow-[0_0_20px_rgba(0,0,0,0.3)]">
            <h4 className="text-[10px] font-mono font-bold text-[#576575] uppercase tracking-wider border-b border-white/5 pb-2 mb-3">Threat Activity Feed</h4>
            <div className="flex-1 overflow-y-auto space-y-2 font-mono text-[10px] scrollbar-none">
              {worldLogs.length === 0 ? (
                <div className="text-center py-10 text-[#576575]">Waiting for transmissions...</div>
              ) : (
                worldLogs.map((log) => (
                  <div key={log.id} className="p-3 bg-black/40 border border-white/5 rounded-xl hover:border-[#25a5ff]/20 transition-all flex items-center justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-1.5 mb-0.5">
                        <span className="font-bold text-white">{log.actor}</span>
                        <span className="text-[#576575]">({log.time})</span>
                      </div>
                      <div className="text-[#9aa4b2] text-[9px]">
                        {log.source} &rarr; <span className="text-[#25a5ff]">{log.target}</span>
                      </div>
                      <div className="text-[#ef4444] text-[8px] mt-0.5 uppercase tracking-wide">{log.type}</div>
                    </div>
                    <button
                      type="button"
                      disabled={isAgentMapLoading}
                      onClick={() => handleMapAgentInvestigation(log)}
                      className="px-2 py-1 bg-[#25a5ff]/10 hover:bg-[#25a5ff] border border-[#25a5ff]/30 text-white hover:text-black rounded text-[8px] font-mono font-bold uppercase cursor-pointer transition-all disabled:opacity-50 shrink-0"
                    >
                      Investigate
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
