# File Assistant — Quick Start Guide

Complete Phase 1 (MVP) implementation for AI-powered file chat with local Ollama.

## 📋 What's Implemented

✅ **Backend (Python/FastAPI)**
- Database models (SQLAlchemy): `file_assistant_models.py`
- Services:
  - `ollama_client.py` — Ollama API client with streaming
  - `file_processor.py` — Extract text from PDF/DOCX/CSV/Code files
  - `chunker.py` — Break large files into ~4KB logical chunks
  - `summarizer.py` — Auto-summarize files > 50KB
  - `chat_engine.py` — Main orchestration engine
- API Routes: `/api/file-assistant/*` (20+ endpoints)
  - Sessions (create, list, get, delete)
  - Messages (send, list)
  - Files (summaries, chunks, search)
  - WebSocket streaming (optional)

✅ **Frontend (React)**
- `file-assistant.jsx` — Complete UI component
  - Home screen (browse sessions)
  - File selector (1-3 files)
  - Chat interface (real-time messages)
  - File sidebar (summaries, metadata)

✅ **Pydantic Schemas**
- `file_assistant_schemas.py` — Request/response validation

---

## 🚀 Setup & Deployment

### Step 1: Ensure Ollama is Running

```bash
# On your host machine (NOT in Docker)
ollama serve

# In another terminal, pull a model
ollama pull llama3.2

# Verify
curl http://localhost:11434/api/tags
```

### Step 2: Install Python Dependencies

```bash
cd /path/to/VulnGuard

# Already in requirements.txt, but ensure installed:
pip install httpx PyPDF2 python-docx --break-system-packages
```

### Step 3: Create Database Tables

The app auto-creates tables on startup via `create_all()` in `main.py`:

```bash
# Tables auto-created:
# - file_assistant_sessions
# - file_assistant_messages
# - file_assistant_summaries
# - file_assistant_preferences
```

### Step 4: Start the Backend

**If using Docker:**
```bash
docker compose up -d vulnguard
```

**If using native Python:**
```bash
cd /path/to/VulnGuard
python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### Step 5: Verify Backend

```bash
curl http://localhost:8000/api/file-assistant/health
```

Expected response:
```json
{
  "status": "ok",
  "ollama_available": true,
  "database_available": true,
  "coworker_host_available": true
}
```

---

## 🎨 Frontend Integration

### Option A: Single React File (Easiest)

1. Copy `web/file-assistant.jsx` to your web folder
2. Add mount point in your HTML:

```html
<div id="file-assistant-app"></div>
<script src="file-assistant.jsx"></script>
<script>
  ReactDOM.render(
    <FileAssistantApp />,
    document.getElementById('file-assistant-app')
  );
</script>
```

### Option B: Add as Tab in Existing UI

If VulnGuard has a tab-based navigation, add:

```html
<nav>
  <a href="#scan-engine">Scan Engine</a>
  <a href="#file-assistant">File Assistant</a> <!-- NEW -->
  <a href="#settings">Settings</a>
</nav>
```

### Option C: Build & Bundle

```bash
cd /path/to/VulnGuard/web

# If using Create React App or similar:
npm install
npm run build

# Copy dist to static folder
```

---

## 🧪 Quick Test

### 1. Create a Chat Session

```bash
curl -X POST http://localhost:8000/api/file-assistant/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Chat",
    "files": [
      {
        "path": "/path/to/your/app.py",
        "name": "app.py",
        "size_bytes": 2400,
        "type": "python"
      }
    ],
    "model": "llama3.2"
  }'
```

Response:
```json
{
  "id": "session-uuid",
  "title": "Test Chat",
  "status": "ACTIVE",
  "model_used": "llama3.2",
  "message_count": 0,
  "files": [...]
}
```

### 2. Send a Message

```bash
curl -X POST http://localhost:8000/api/file-assistant/sessions/{session-id}/messages \
  -H "Content-Type: application/json" \
  -d '{"content": "What does this file do?"}'
```

### 3. Get Chat History

```bash
curl http://localhost:8000/api/file-assistant/sessions/{session-id}/messages
```

---

## 📁 File Structure

```
VulnGuard/
├── api/
│   ├── file_assistant_models.py      ← ORM models
│   ├── file_assistant_schemas.py     ← Pydantic schemas
│   ├── services/
│   │   ├── ollama_client.py          ← Ollama API client
│   │   ├── file_processor.py         ← Extract text from files
│   │   ├── chunker.py                ← Break into chunks
│   │   ├── summarizer.py             ← Auto-summarize
│   │   └── chat_engine.py            ← Main orchestration
│   ├── routes/
│   │   └── file_assistant.py         ← FastAPI routes
│   └── main.py                       ← Includes router
└── web/
    └── file-assistant.jsx             ← React component
```

---

## ⚙️ Environment Configuration

Add to `.env`:

```bash
# Ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
OLLAMA_TIMEOUT=120

# File Assistant
FILE_ASSISTANT_AUTO_SUMMARIZE_THRESHOLD=51200  # 50KB
FILE_ASSISTANT_CONTEXT_WINDOW_TOKENS=8000
FILE_ASSISTANT_MAX_TURNS_PER_SESSION=10
FILE_ASSISTANT_MAX_FILE_SIZE=5242880  # 5MB
```

---

## 🐛 Troubleshooting

### "Ollama not responding"

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve

# Check port
netstat -an | grep 11434
```

### "Unsupported file type"

Supported types: `.py, .js, .ts, .java, .go, .json, .yaml, .md, .pdf, .docx, .csv, .txt`

### "File too large"

Max file size: 5MB. Larger files are chunked automatically.

### Database errors

```bash
# Clear database (WARNING: deletes all sessions!)
rm ./storage/db/vulnguard.sqlite

# Restart app to recreate tables
```

### WebSocket connection refused

Ensure your frontend connects to correct WebSocket URL:
```javascript
const ws = new WebSocket('ws://localhost:8000/api/file-assistant/sessions/{id}/chat/stream');
```

---

## 📊 API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/file-assistant/health` | System health |
| POST | `/api/file-assistant/sessions` | Create session |
| GET | `/api/file-assistant/sessions` | List sessions |
| GET | `/api/file-assistant/sessions/{id}` | Get session details |
| DELETE | `/api/file-assistant/sessions/{id}` | Delete session |
| POST | `/api/file-assistant/sessions/{id}/messages` | Send message |
| GET | `/api/file-assistant/sessions/{id}/messages` | Get messages |
| GET | `/api/file-assistant/sessions/{id}/summaries` | Get file summaries |
| GET | `/api/file-assistant/sessions/{id}/chunks/{file_index}` | Get file chunk |
| WS | `/api/file-assistant/sessions/{id}/chat/stream` | WebSocket chat |

---

## 📈 Performance Tips

1. **Chunking Strategy**: Files > 50KB are automatically chunked (~4KB per chunk)
2. **Message Pruning**: Keep last 10 messages in context (auto-pruned)
3. **Ollama Model**: Use `llama3.2` for balance of speed/quality
   - `deepseek-coder:6.7b` for better code analysis
   - `phi3:mini` for low-RAM systems
4. **Caching**: Summaries cached in DB, re-used across messages

---

## 🔮 Phase 2 (Coming Soon)

- Multi-file chat (combine contexts)
- Streaming responses (WebSocket)
- Session export (HTML/PDF)
- File search across chunks
- Custom system prompts
- Performance optimizations

---

## 📝 Notes

- All data stays local (no external API calls)
- Supports coworker_host folder whitelist for security
- Session history persisted to SQLite
- Streaming responses supported via WebSocket
- Token counting for context management

---

**Questions?** Check `/api/file-assistant/docs` (Swagger UI) for interactive API testing.

Happy chatting! 🚀
