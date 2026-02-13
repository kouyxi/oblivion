# 🛡️ Oblivion WAF

Um Web Application Firewall (WAF) e Reverse Proxy de alta performance escrito em **Rust**.

O objetivo é simples: proteger o backend (Python, Node, Go) de ataques comuns e volumétricos sem sacrificar a latência. Construído sobre o **Tokio**, o Oblivion usa I/O não-bloqueante para segurar milhares de conexões simultâneas com consumo mínimo de RAM.

---

## 🧠 Arquitetura e Algoritmos

Nada de `if` solto no código. O sistema é modular e pensado pra escala.

### 1. Async Core (The Reactor)

Esquece o modelo de "uma thread por cliente". Usamos o **Tokio Runtime** (Event Loop).

- O servidor aceita a conexão TCP/TLS.
- O processamento é suspenso (`await`) enquanto espera dados da rede.
- Isso permite lidar com 10k+ conexões (C10k) usando pouquíssimas threads de OS.

### 2. Rate Limiting (Sharded Token Bucket)

Para evitar DoS volumétrico, implementei o algoritmo **Token Bucket** com **Lazy Refill**.

- **Lógica:** Cada IP tem um balde de "fichas". Requisição custa ficha. O balde enche com o tempo.
- **Otimização (Sharding):** Em vez de um `Mutex` global (que causaria gargalo), dividi o mapa de IPs em 16 shards (`Vec<Mutex<HashMap>>`). O lock é feito baseado no Hash do IP, reduzindo a disputa de threads em 16x.
- **Garbage Collection:** Uma task em background limpa IPs inativos a cada minuto pra não vazar memória.

### 3. Inspection Engine (O Cérebro)

Não é apenas um "grep" de strings. O motor segue um pipeline estrito:

1.  **Protocol Sanitization:** Verifica headers conflitantes (`Content-Length` + `Transfer-Encoding`) para matar ataques de **Request Smuggling**.
2.  **Deep Normalization:** Um loop recursivo que decodifica URL Encoding (`%2527` -> `'`) e normaliza espaços (`+` -> ` `) até a string estabilizar. Isso previne **Bypass por Double Encoding**.
3.  **Pattern Matching:** Busca assinaturas estáticas de SQL Injection, XSS e Path Traversal no payload limpo.

### 4. Hardening (A Blindagem)

- **Anti-Slowloris:** Timeouts rígidos na leitura do Header. Se o cliente conectar e ficar quieto, o socket é dropado em 5s.
- **Body Limit:** Streams de upload são limitados a 10MB via `take()`. Se passar disso, a conexão corta.
- **HTTPS Nativo:** Suporte a TLS 1.3 via `rustls` (mais seguro e rápido que OpenSSL).

---

## 🚀 Como Rodar

### Pré-requisitos

Você precisa do Rust instalado e, para HTTPS, gerar os certificados locais:

```bash
# Gera chave e certificado auto-assinado
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```
