#!/usr/bin/env python3
import socket
import threading
import json
import os
import time
import sqlite3
from llama_cpp import Llama
from pathlib import Path

# ─── CONFIG ────────────────────────────────────────────────────────────────────
HOST = '127.0.0.1'
PORT = 5005
MODEL_PATH = '/home/autosecure/FYP/llama.cpp/models/Llama-3-WhiteRabbitNeo-8B-v2.0.Q4_K_M.gguf'
#MODEL_PATH = '/home/autosecure/FYP/llama.cpp/models/Llama-3-WhiteRabbitNeo-8B-v2.0.Q4_K_S.gguf'
CACHE_DB = 'llama_cache.db'
THREADS = 4
N_CTX = 256
MAX_TOKENS = 512
TEMPERATURE = 0.0
REPEAT_PENALTY = 1.1
GPU_LAYERS = 10
# ────────────────────────────────────────────────────────────────────────────────

# Thread-safe SQLite connection handler
class DiskCache:
    def __init__(self):
        self.connections = threading.local()
        Path(CACHE_DB).touch()
        
    def get_conn(self):
        if not hasattr(self.connections, 'db'):
            self.connections.db = sqlite3.connect(CACHE_DB, check_same_thread=False)
            self.connections.db.execute('''CREATE TABLE IF NOT EXISTS cache
                                        (prompt TEXT PRIMARY KEY, response TEXT)''')
        return self.connections.db
    
    def get(self, prompt):
        conn = self.get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT response FROM cache WHERE prompt=?", (prompt,))
        return cursor.fetchone()
    
    def set(self, prompt, response):
        conn = self.get_conn()
        conn.execute("INSERT OR REPLACE INTO cache VALUES (?, ?)", 
                   (prompt, response))
        conn.commit()

# Initialize cache
cache = DiskCache()

if not os.path.isfile(MODEL_PATH):
    print(f"[!] Model not found at {MODEL_PATH}")
    exit(1)

def load_model():
    print(f"[+] Loading model with {GPU_LAYERS} GPU layers...")
    llm = Llama(
        model_path=MODEL_PATH,
        n_threads=THREADS,
        n_ctx=N_CTX,
        n_gpu_layers=GPU_LAYERS,
        use_mmap=True,
        use_mlock=False,
        verbose=True
    )
    
    print("[+] Warming up model...")
    llm("Warmup", max_tokens=1, temperature=0)
    return llm

llm = load_model()
print("[+] Model ready!")

def handle_client(conn, addr):
    print(f"[>] Connection from {addr}")
    try:
        raw = conn.recv(4096).decode('utf-8')
        req = json.loads(raw)
        prompt = req['prompt'].strip()
        
        print(f"[>] Processing: {prompt[:60]}...")
        start = time.time()

        # Check cache
        if cached := cache.get(prompt):
            print("[+] Cache hit")
            conn.sendall(cached[0].encode('utf-8'))
            return

        # Stream new response
        response = []
        stream = llm(
            prompt=prompt,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            repeat_penalty=REPEAT_PENALTY,
            stream=True
        )

        for chunk in stream:
            token = chunk['choices'][0]['text']
            if token.strip():
                response.append(token)
                conn.sendall(token.encode('utf-8'))

        # Cache complete response
        cache.set(prompt, ''.join(response))
        print(f"[+] Generated in {time.time()-start:.2f}s")

    except Exception as e:
        print(f"[!] Error: {e}")
        conn.sendall(f"ERROR: {e}".encode('utf-8'))
    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[+] Server ready on {HOST}:{PORT}")
        
        try:
            while True:
                conn, addr = s.accept()
                threading.Thread(
                    target=handle_client,
                    args=(conn, addr),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\n[+] Shutting down...")

if __name__ == '__main__':
    main()
