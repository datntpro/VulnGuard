# File Assistant — Implementation Plan & Architecture

**File Assistant** extends VulnGuard with AI-powered file chat using local Ollama. This document covers architecture, tech stack, development phases, and file structure.

---

## 1. ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Browser (User)                        │
│  File Assistant Tab in VulnGuard Web Dashboard              │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTP/WebSocket
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              VulnGuard FastAPI Backend                       │
│  ├─ /api/file-assistant/* routes                            │
│  ├─ Session management                                      │
│  ├─ File processing (chunking, summarization)              │
│  └─ Ollama API client (local integration)                   │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTP
                     ▼
┌─────────────────────────────────────────────────────────────┐
│         Ollama (Host Machine via coworker_host)             │
│  ├─ llama3.2 (default)                                      │
│  ├─ deepseek-coder (optional for code)                     │
│  └─ Custom models (user choice)                             │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              SQLite Database (Persistent)                    │
│  ├─ Sessions & messages                                     │
│  ├─ File summaries & chunk index                           │
│  └─ User preferences                                        │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Ollama runs on host** (not Docker) — ensures data stays local
2. **Coworker_host reuse** — same permission model as Co-work feature
3. **SQLite for persistence** — sessions survive browser close
4. **Streaming responses** — real-time Ollama output to UI via WebSocket
5. **Chunking strategy** — ~4KB logical chunks (aligned at code boundaries)
6. **Auto-summarization** — files > 50KB summarized before chat starts

---

## 2. TECH STACK

| Layer | Technology | Version | Notes |
|-------|-----------|---------|-------|
| **Frontend** | React | 18+ | Reuse VulnGuard's existing setup |
| | TypeScript | 5+ | Type safety |
| | CSS | Tailwind (CSS vars) | Match VulnGuard theme |
| **Backend** | Python | 3.9+ | FastAPI routes |
| | FastAPI | 0.100+ | REST + WebSocket support |
| | SQLAlchemy | 2.0+ | ORM for sessions/messages |
| | Pydantic | 2.0+ | Request/response validation |
| **Local AI** | Ollama | Latest | Running on host (not Docker) |
| **Database** | SQLite | 3.37+ | Same as VulnGuard |
| **File Processing** | PyPDF2 | 3.0+ | PDF extraction |
| | python-docx | 0.8+ | DOCX extraction |
| | csv | Built-in | CSV parsing |
| **Async** | asyncio | Built-in | Concurrent requests |
| | aiofiles | 23+ | Async file I/O |

---

## 3. DATABASE SCHEMA

```sql
-- Sessions: main container for chat context
CREATE TABLE file_assistant_sessions (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    title TEXT,
    status TEXT CHECK (status IN ('ACTIVE', 'ARCHIVED', 'DELETED')),
    model_used TEXT,
    files_json TEXT  -- JSON array of {path, size, hash, type}
);

-- Messages: chat history
CREATE TABLE file_assistant_messages (
    id TEXT PRIMARY KEY,
    session_id TEXT FOREIGN KEY,
    role TEXT CHECK (role IN ('USER', 'ASSISTANT')),
    content TEXT,
    token_count INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES file_assistant_sessions(id) ON DELETE CASCADE
);

-- Summaries: cached file summaries & chunk index
CREATE TABLE file_assistant_summaries (
    id TEXT PRIMARY KEY,
    session_id TEXT FOREIGN KEY,
    file_path TEXT,
    summary TEXT,
    chunk_index_json TEXT,  -- JSON: [{"start": 0, "end": 50, "lines": "1-50"}, ...]
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES file_assistant_sessions(id) ON DELETE CASCADE
);

-- Preferences: user settings
CREATE TABLE file_assistant_preferences (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    auto_summarize_threshold INTEGER DEFAULT 51200,  -- 50KB
    context_window_tokens INTEGER DEFAULT 8000,
    max_turns_per_session INTEGER DEFAULT 10,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 4. API ENDPOINTS

All endpoints prefix: `/api/file-assistant/`

### Sessions

```
POST   /sessions                Create new session
GET    /sessions                List active sessions
GET    /sessions/{id}           Get session + last 10 messages
DELETE /sessions/{id}           Delete session
PATCH  /sessions/{id}           Update session (archive, rename)
```

### Files

```
POST   /sessions/{id}/files              Add files to session
GET    /sessions/{id}/files              List files in session
DELETE /sessions/{id}/files/{file_id}    Remove file from session
GET    /sessions/{id}/files/{file_id}/preview  Get file preview/chunk
```

### Chat

```
POST   /sessions/{id}/messages           Send message (async)
GET    /sessions/{id}/messages           Get message history
WS     /sessions/{id}/messages/stream    WebSocket for streaming responses
```

### Summarization

```
POST   /sessions/{id}/summarize          Trigger summarization for all files > 50KB
GET    /sessions/{id}/summaries          Get cached summaries
GET    /sessions/{id}/chunks             Get chunk index for all files
```

### Utilities

```
GET    /file-types                       Supported file types + max sizes
GET    /health                           System health (Ollama, DB)
GET    /preferences                      User preferences
PUT    /preferences                      Update preferences
```

---

## 5. FILE STRUCTURE (Backend - Python)

```
api/
├── routes/
│   ├── file_assistant/
│   │   ├── __init__.py
│   │   ├── sessions.py           # Session CRUD
│   │   ├── messages.py           # Chat messages + streaming
│   │   ├── files.py              # File operations
│   │   ├── summarize.py          # Summarization + chunking
│   │   ├── export.py             # Export to HTML/PDF
│   │   └── health.py             # Health checks
│   └── __init__.py
├── models/
│   ├── file_assistant.py         # SQLAlchemy models
│   └── __init__.py
├── schemas/
│   ├── file_assistant.py         # Pydantic request/response schemas
│   └── __init__.py
├── services/
│   ├── file_processor.py         # Extract text from PDF/DOCX/CSV
│   ├── chunker.py                # Break large files into chunks
│   ├── summarizer.py             # Call Ollama for summarization
│   ├── chat_engine.py            # Main chat loop + context management
│   ├── ollama_client.py          # Ollama API wrapper (HTTP + streaming)
│   └── __init__.py
├── utils/
│   ├── file_types.py             # Supported types + validators
│   ├── token_counter.py          # Estimate token count (for context tracking)
│   ├── cache.py                  # Cache summaries/chunks
│   └── __init__.py
├── constants.py                  # Max sizes, timeouts, model names
└── file_assistant_main.py        # Mount routes on FastAPI app
```

---

## 6. FILE STRUCTURE (Frontend - React)

```
web/
├── src/
│   ├── components/
│   │   ├── FileAssistant/
│   │   │   ├── FileAssistant.jsx           # Main container
│   │   │   ├── FileSelector.jsx            # File browser modal
│   │   │   ├── ChatInterface.jsx           # Chat UI + messages
│   │   │   ├── FilePanel.jsx               # Sidebar with file list
│   │   │   ├── FilePreview.jsx             # File preview / chunk viewer
│   │   │   ├── MessageBubble.jsx           # User/Assistant message component
│   │   │   └── SessionList.jsx             # List of past sessions
│   │   └── index.js
│   ├── hooks/
│   │   ├── useFileAssistant.js             # Main logic hook
│   │   ├── useChat.js                      # Chat loop + WebSocket
│   │   ├── useSummarization.js             # Summarization progress
│   │   └── useFilePreview.js               # Chunk navigation
│   ├── api/
│   │   └── fileAssistantApi.js             # HTTP + WebSocket client
│   ├── styles/
│   │   └── FileAssistant.css               # Component styles
│   └── pages/
│       └── FileAssistantPage.jsx           # Route page
├── index.html
└── package.json
```

---

## 7. INTEGRATION WITH EXISTING VULNGUARD

### Tab Placement

```
Web Dashboard Navigation:
  VulnGuard → [Scan Engine] [Settings] [Co-work ▼]
                                         ├── File Assistant  ← NEW
                                         └── Folder Manager
```

### Reuse from VulnGuard

| Component | Reuse | Notes |
|-----------|-------|-------|
| Sidebar navigation | ✅ Existing nav bar | Add File Assistant tab |
| Theme/CSS variables | ✅ Tailwind vars | Match dark mode, spacing |
| Auth | ✅ If VulnGuard has it | Use same session/token |
| Coworker_host integration | ✅ Same permission model | Reuse folder whitelist |
| Database connection | ✅ Existing SQLite | New tables in same DB |
| Ollama client wrapper | ✅ Already in `ai_analyzer.py` | Adapt for streaming |

### New Dependencies (Python)

```bash
pip install aiofiles==23.2.1
pip install PyPDF2==3.0.1
pip install python-docx==0.8.11
# All other deps already in VulnGuard
```

### New Dependencies (Node)

Reuse existing VulnGuard build tools; no new packages needed (React already installed).

---

## 8. DEVELOPMENT PHASES

### Phase 1: MVP (Weeks 1-2)

**Goal:** Single-file chat with Ollama

**Deliverables:**
- [x] Database schema + models (sessions, messages)
- [x] File selection UI + backend upload
- [x] Basic chat loop (send message → Ollama → response)
- [x] Session persistence (SQLite)
- [ ] Error handling for Ollama offline/timeout
- [ ] Simple UI: chat interface + file sidebar

**Out of Scope (Phase 2):**
- Multi-file mode
- Large file summarization
- Streaming responses
- Session export

**Acceptance Criteria:**
- User can start new session, select 1 file, chat, see responses
- Chat history persists
- UI is responsive in light + dark mode
- Ollama errors are handled gracefully

---

### Phase 2: Long Files + Multi-File (Weeks 3-4)

**Goal:** Handle large files + compare across files

**Deliverables:**
- [ ] Auto-summarization (files > 50KB)
- [ ] Chunking + chunk navigator
- [ ] Multi-file UI (file tabs)
- [ ] Multi-file chat context (combine summaries)
- [ ] Session resume (list past sessions)

**Acceptance Criteria:**
- 10MB file summarized in < 2 min
- User can navigate chunks with "← Previous Chunk" / "Next Chunk →"
- Multi-file chat works (Ollama receives context from all files)
- Resume session loads full history

---

### Phase 3: Polish + Export (Weeks 5-6)

**Goal:** Production-ready features

**Deliverables:**
- [ ] Streaming responses (WebSocket)
- [ ] Export to HTML + PDF
- [ ] Search within files
- [ ] Custom system prompts
- [ ] Performance optimization (caching, lazy loading)
- [ ] Unit + integration tests (80%+ coverage)
- [ ] Documentation (dev guide, user guide)

**Acceptance Criteria:**
- Export includes full chat history + syntax highlighting
- Response latency < 3 sec (cached) / < 30 sec (fresh)
- 100+ sessions load in < 1 sec
- All error paths tested

---

## 9. DEPLOYMENT CHECKLIST

- [ ] Database migrations applied
- [ ] Environment variables set (.env):
  - `OLLAMA_TIMEOUT=120`
  - `FILE_ASSISTANT_MAX_SESSIONS=100`
  - `FILE_ASSISTANT_CHUNK_SIZE=4096`
- [ ] Ollama health check passes
- [ ] API tests pass (pytest)
- [ ] Frontend built + assets optimized
- [ ] Browser support verified (Chrome, Firefox, Safari, Edge)
- [ ] Dark mode verified
- [ ] Performance tested (Lighthouse > 80)
- [ ] Security: file access validated against coworker_host whitelist
- [ ] Documentation updated

---

## 10. SUCCESS METRICS

| Metric | Target | Measurement |
|--------|--------|-------------|
| User adoption | 30%+ of daily active users | GA tracking / session count |
| Avg session length | 3-10 messages | DB query on message counts |
| Response latency | < 5 sec median | Backend logs / APM |
| Error rate | < 2% of requests | Exception tracking |
| User satisfaction | ≥ 4/5 stars | In-app rating (optional) |
| Chat quality | Useful answers 80%+ | Manual audit of 50 sessions |

---

## 11. KNOWN RISKS & MITIGATION

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Ollama unavailable | 🔴 HIGH | Health check endpoint + graceful fallback UI |
| Token limit exceeded | 🟡 MEDIUM | Aggressive context pruning (keep last 5 turns) |
| Large file timeout | 🟡 MEDIUM | Configurable timeout (default 5 min); show progress |
| DB corruption | 🔴 HIGH | Backups before each summarization; validation on load |
| Memory leak in streaming | 🔴 HIGH | Async cleanup; max message size 2MB |

---

## 12. FUTURE ENHANCEMENTS (Post-Phase 3)

- **Semantic search:** Find files by description ("error handling function")
- **Code refactoring:** AI suggests improvements (read-only first, write in Phase 4)
- **Test generation:** Auto-create test cases from code
- **Diagram generation:** Create flowcharts from code
- **Team sharing:** Session collaboration + comments
- **Custom models:** Fine-tune Ollama on user's codebase
- **Browser extension:** File Assistant in any IDE

---

## 13. RESOURCES & REFERENCES

- VulnGuard README: `/README.md`
- Ollama API Docs: https://github.com/ollama/ollama/blob/main/docs/api.md
- FastAPI WebSocket: https://fastapi.tiangolo.com/advanced/websockets/
- React Hooks Guide: https://react.dev/reference/react/hooks
- SQLAlchemy ORM: https://docs.sqlalchemy.org/20/orm/

---

**Document Version:** 1.0  
**Last Updated:** 2026-06-29  
**Status:** Ready for Development
