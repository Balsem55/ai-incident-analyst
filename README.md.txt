
Pipeline intelligent d'analyse de logs avec n8n et Ollama (LLM local).

Logs → Webhook → Parse → Ollama LLM → Détection → Alerte

- n8n (orchestration du pipeline)
- Ollama + llama3.2:1b (LLM local)
- Docker


```bash
docker-compose up -d
```

Télécharger sur ollama.com puis :
```bash
ollama pull llama3.2:1b
```

- Ouvrir http://localhost:5678
- Importer le fichier workflow.json dans n8n
- Activer le workflow

```powershell
Invoke-RestMethod -Uri "http://localhost:5678/webhook/logs" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"source": "firewall", "log": "Failed login attempt from IP 192.168.1.105"}'
```