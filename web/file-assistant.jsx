/**
 * File Assistant Component
 * AI-powered file chat using local Ollama
 */

import React, { useState, useEffect, useRef } from 'react';

// API Client
class FileAssistantAPI {
  constructor(baseURL = '/api/file-assistant') {
    this.baseURL = baseURL;
  }

  async health() {
    const res = await fetch(`${this.baseURL}/health`);
    return res.json();
  }

  async createSession(files, model = 'llama3.2') {
    const res = await fetch(`${this.baseURL}/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files, model })
    });
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
  }

  async getSession(sessionId) {
    const res = await fetch(`${this.baseURL}/sessions/${sessionId}`);
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
  }

  async listSessions() {
    const res = await fetch(`${this.baseURL}/sessions`);
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
  }

  async sendMessage(sessionId, content) {
    const res = await fetch(`${this.baseURL}/sessions/${sessionId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content })
    });
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
  }

  async getMessages(sessionId) {
    const res = await fetch(`${this.baseURL}/sessions/${sessionId}/messages`);
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
  }

  async getSummaries(sessionId) {
    const res = await fetch(`${this.baseURL}/sessions/${sessionId}/summaries`);
    if (!res.ok) throw new Error(`API error: ${res.status}`);
    return res.json();
  }

  async deleteSession(sessionId) {
    const res = await fetch(`${this.baseURL}/sessions/${sessionId}`, {
      method: 'DELETE'
    });
    return res.ok;
  }
}

// Home Screen - Browse Sessions
function HomeScreen({ onCreateSession, onResumeSession, sessions = [] }) {
  return (
    <div style={{ padding: '2rem' }}>
      <h1>File Assistant</h1>
      <p>Chat with your files using local Ollama AI</p>

      <button
        onClick={onCreateSession}
        style={{
          padding: '10px 20px',
          background: 'var(--fill-accent)',
          color: 'white',
          border: 'none',
          borderRadius: '6px',
          cursor: 'pointer',
          fontSize: '16px'
        }}
      >
        + New Chat Session
      </button>

      {sessions.length > 0 && (
        <div style={{ marginTop: '2rem' }}>
          <h2>Recent Sessions</h2>
          <div style={{ display: 'grid', gap: '12px' }}>
            {sessions.map(session => (
              <div
                key={session.id}
                onClick={() => onResumeSession(session.id)}
                style={{
                  padding: '1rem',
                  border: '0.5px solid var(--border)',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  background: 'var(--surface-1)',
                  transition: 'background 0.2s'
                }}
                onMouseOver={(e) => e.currentTarget.style.background = 'var(--surface-2)'}
                onMouseOut={(e) => e.currentTarget.style.background = 'var(--surface-1)'}
              >
                <h3 style={{ margin: '0 0 8px' }}>{session.title}</h3>
                <p style={{ margin: '0', fontSize: '14px', color: 'var(--text-secondary)' }}>
                  {session.message_count} messages • {session.files.length} files
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// File Selector Screen
function FileSelector({ onConfirm, onCancel }) {
  const [selectedFiles, setSelectedFiles] = useState([]);

  const handleAddFile = () => {
    const newFile = {
      path: '/home/user/example.py',
      name: 'example.py',
      size_bytes: 2400,
      type: 'python'
    };
    if (selectedFiles.length < 3) {
      setSelectedFiles([...selectedFiles, newFile]);
    }
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '600px' }}>
      <h2>Select Files</h2>
      <p>Choose 1-3 files to chat with</p>

      <div style={{ marginBottom: '1.5rem' }}>
        <button
          onClick={handleAddFile}
          disabled={selectedFiles.length >= 3}
          style={{
            padding: '10px 20px',
            background: selectedFiles.length >= 3 ? '#ccc' : 'var(--fill-accent)',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            cursor: selectedFiles.length >= 3 ? 'not-allowed' : 'pointer'
          }}
        >
          + Add File
        </button>
      </div>

      {selectedFiles.map((file, idx) => (
        <div
          key={idx}
          style={{
            padding: '10px 12px',
            marginBottom: '8px',
            background: 'var(--surface-1)',
            border: '0.5px solid var(--border)',
            borderRadius: '6px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}
        >
          <div>
            <p style={{ margin: '0', fontWeight: '500' }}>{file.name}</p>
            <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
              {(file.size_bytes / 1024).toFixed(1)} KB
            </p>
          </div>
          <button
            onClick={() => setSelectedFiles(selectedFiles.filter((_, i) => i !== idx))}
            style={{
              padding: '4px 8px',
              background: 'transparent',
              border: '0.5px solid var(--border)',
              borderRadius: '4px',
              cursor: 'pointer',
              color: 'var(--text-secondary)'
            }}
          >
            Remove
          </button>
        </div>
      ))}

      <div style={{ marginTop: '2rem', display: 'flex', gap: '8px' }}>
        <button
          onClick={() => onConfirm(selectedFiles)}
          disabled={selectedFiles.length === 0}
          style={{
            flex: 1,
            padding: '10px',
            background: selectedFiles.length === 0 ? '#ccc' : 'var(--fill-accent)',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            cursor: selectedFiles.length === 0 ? 'not-allowed' : 'pointer'
          }}
        >
          Start Chat
        </button>
        <button
          onClick={onCancel}
          style={{
            padding: '10px 20px',
            background: 'transparent',
            border: '0.5px solid var(--border)',
            borderRadius: '6px',
            cursor: 'pointer'
          }}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// Chat Screen
function ChatScreen({ sessionId, session, onBack }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [summaries, setSummaries] = useState([]);
  const messagesEndRef = useRef(null);
  const api = new FileAssistantAPI();

  useEffect(() => {
    loadMessages();
    loadSummaries();

    // Poll for new messages every 2 seconds
    const interval = setInterval(loadMessages, 2000);
    return () => clearInterval(interval);
  }, [sessionId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const loadMessages = async () => {
    try {
      const msgs = await api.getMessages(sessionId);
      setMessages(msgs);
    } catch (e) {
      console.error('Failed to load messages:', e);
    }
  };

  const loadSummaries = async () => {
    try {
      const sums = await api.getSummaries(sessionId);
      setSummaries(sums);
    } catch (e) {
      console.error('Failed to load summaries:', e);
    }
  };

  const handleSendMessage = async () => {
    if (!input.trim()) return;

    const userMessage = input;
    setInput('');
    setLoading(true);

    try {
      const response = await api.sendMessage(sessionId, userMessage);
      await loadMessages();
    } catch (e) {
      alert('Failed to send message: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', height: '100vh', flexDirection: 'column' }}>
      {/* Header */}
      <div style={{ padding: '1rem', borderBottom: '0.5px solid var(--border)', background: 'var(--surface-1)' }}>
        <button
          onClick={onBack}
          style={{
            padding: '8px 16px',
            background: 'transparent',
            border: '0.5px solid var(--border)',
            borderRadius: '6px',
            cursor: 'pointer',
            marginBottom: '8px'
          }}
        >
          ← Back
        </button>
        <h2 style={{ margin: '0' }}>{session?.title || 'Chat'}</h2>
      </div>

      {/* Main Content */}
      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        {/* Sidebar - Files */}
        <div style={{
          width: '280px',
          borderRight: '0.5px solid var(--border)',
          background: 'var(--surface-1)',
          overflow: 'auto',
          padding: '1rem'
        }}>
          <h3 style={{ margin: '0 0 1rem', fontSize: '14px' }}>Files ({session?.files.length})</h3>
          {session?.files.map((file, idx) => (
            <div key={idx} style={{ marginBottom: '1rem', fontSize: '13px' }}>
              <p style={{ margin: '0 0 4px', fontWeight: '500' }}>📄 {file.name}</p>
              <p style={{ margin: '0', color: 'var(--text-secondary)', fontSize: '11px' }}>
                {(file.size_bytes / 1024).toFixed(1)} KB
              </p>
            </div>
          ))}

          <hr style={{ margin: '1rem 0', border: 'none', borderTop: '0.5px solid var(--border)' }} />

          <h4 style={{ margin: '0 0 8px', fontSize: '12px' }}>Summary</h4>
          {summaries.length > 0 ? (
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '0' }}>
              {summaries[0].summary.substring(0, 150)}...
            </p>
          ) : (
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '0' }}>
              Generating summary...
            </p>
          )}
        </div>

        {/* Chat Area */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {messages.length === 0 && (
              <div style={{ textAlign: 'center', color: 'var(--text-secondary)', marginTop: '2rem' }}>
                <p>No messages yet. Ask a question about the files!</p>
              </div>
            )}

            {messages.map((msg) => (
              <div
                key={msg.id}
                style={{
                  display: 'flex',
                  justifyContent: msg.role === 'USER' ? 'flex-end' : 'flex-start'
                }}
              >
                <div
                  style={{
                    maxWidth: '70%',
                    padding: '12px 16px',
                    borderRadius: '12px',
                    background: msg.role === 'USER' ? 'var(--fill-accent)' : 'var(--surface-2)',
                    color: msg.role === 'USER' ? 'white' : 'var(--text-primary)',
                    border: msg.role === 'USER' ? 'none' : '0.5px solid var(--border)',
                    wordWrap: 'break-word'
                  }}
                >
                  {msg.content}
                </div>
              </div>
            ))}

            {loading && (
              <div style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
                <p>Ollama is thinking...</p>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div style={{ borderTop: '0.5px solid var(--border)', padding: '1rem', background: 'var(--surface-1)' }}>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                placeholder="Ask about your files..."
                disabled={loading}
                style={{
                  flex: 1,
                  padding: '10px 12px',
                  border: '0.5px solid var(--border)',
                  borderRadius: '6px',
                  background: 'var(--surface-2)',
                  color: 'var(--text-primary)',
                  fontSize: '14px'
                }}
              />
              <button
                onClick={handleSendMessage}
                disabled={loading || !input.trim()}
                style={{
                  padding: '10px 20px',
                  background: loading || !input.trim() ? '#ccc' : 'var(--fill-accent)',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: loading || !input.trim() ? 'not-allowed' : 'pointer'
                }}
              >
                Send
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Main App Component
export default function FileAssistantApp() {
  const [screen, setScreen] = useState('home'); // 'home', 'file-selector', 'chat'
  const [sessions, setSessions] = useState([]);
  const [activeSession, setActiveSession] = useState(null);
  const [systemHealth, setSystemHealth] = useState(null);
  const api = new FileAssistantAPI();

  useEffect(() => {
    checkHealth();
    loadSessions();
  }, []);

  const checkHealth = async () => {
    try {
      const health = await api.health();
      setSystemHealth(health);
      if (!health.ollama_available) {
        alert('⚠️ Ollama is not running. Start it with: ollama serve');
      }
    } catch (e) {
      console.error('Health check failed:', e);
    }
  };

  const loadSessions = async () => {
    try {
      const data = await api.listSessions();
      setSessions(data.sessions);
    } catch (e) {
      console.error('Failed to load sessions:', e);
    }
  };

  const handleCreateSession = async (files) => {
    try {
      const session = await api.createSession(files);
      setActiveSession(session);
      setScreen('chat');
      await loadSessions();
    } catch (e) {
      alert('Failed to create session: ' + e.message);
    }
  };

  const handleResumeSession = async (sessionId) => {
    try {
      const session = await api.getSession(sessionId);
      setActiveSession(session);
      setScreen('chat');
    } catch (e) {
      alert('Failed to load session: ' + e.message);
    }
  };

  const handleBackToHome = () => {
    setScreen('home');
    setActiveSession(null);
    loadSessions();
  };

  return (
    <div>
      {systemHealth && !systemHealth.ollama_available && (
        <div style={{
          padding: '12px',
          background: 'var(--bg-warning)',
          color: 'var(--text-warning)',
          fontSize: '14px'
        }}>
          ⚠️ Ollama offline. Start with: ollama serve
        </div>
      )}

      {screen === 'home' && (
        <HomeScreen
          onCreateSession={() => setScreen('file-selector')}
          onResumeSession={handleResumeSession}
          sessions={sessions}
        />
      )}

      {screen === 'file-selector' && (
        <FileSelector
          onConfirm={handleCreateSession}
          onCancel={() => setScreen('home')}
        />
      )}

      {screen === 'chat' && activeSession && (
        <ChatScreen
          sessionId={activeSession.id}
          session={activeSession}
          onBack={handleBackToHome}
        />
      )}
    </div>
  );
}
