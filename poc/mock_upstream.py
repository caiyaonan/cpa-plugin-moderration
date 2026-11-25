"""Fake upstream for the PoC: answers OpenAI / Claude style calls and logs every hit."""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = sys.argv[2] if len(sys.argv) > 2 else "upstream.jsonl"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080


def log(entry):
    entry["ts"] = time.time()
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        log({"method": "GET", "path": self.path})
        self._json(200, {"object": "list", "data": [
            {"id": m, "object": "model", "owned_by": "mock"}
            for m in ["mock-chat", "gpt-image-1", "gpt-6-mini", "claude-mock"]]})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        ctype = self.headers.get("Content-Type", "")
        stream = False
        try:
            stream = bool(json.loads(body).get("stream"))
        except Exception:
            pass
        log({"method": "POST", "path": self.path, "content_type": ctype,
             "len": len(body), "stream": stream, "head": body[:300].decode("utf-8", "replace")})
        p = self.path
        if p.endswith("/moderations"):
            return self._moderations(body)
        if b"SLOW_UPSTREAM" in body:
            time.sleep(4)
        if b"UPSTREAM_500" in body:
            return self._json(500, {"error": {"message": "mock upstream failure", "type": "server_error"}})
        if "/messages" in p:
            if stream:
                return self._sse([
                    ("message_start", {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-mock", "content": [], "stop_reason": None, "usage": {"input_tokens": 1, "output_tokens": 0}}}),
                    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}}),
                    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 1}}),
                    ("message_stop", {"type": "message_stop"}),
                ])
            return self._json(200, {"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-mock",
                                    "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
                                    "usage": {"input_tokens": 1, "output_tokens": 1}})
        if "/images/" in p:
            return self._json(200, {"created": 1, "data": [{"b64_json": "iVBORw0KGgo="}],
                                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}})
        if "/responses" in p:
            resp = {"id": "resp_1", "object": "response", "status": "completed", "model": "mock-chat",
                    "output": [{"type": "message", "id": "m1", "role": "assistant", "status": "completed",
                                "content": [{"type": "output_text", "text": "ok", "annotations": []}]}],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
            if stream:
                return self._sse([
                    ("response.created", {"type": "response.created", "response": {**resp, "status": "in_progress", "output": []}}),
                    ("response.output_text.delta", {"type": "response.output_text.delta", "item_id": "m1", "output_index": 0, "content_index": 0, "delta": "ok"}),
                    ("response.completed", {"type": "response.completed", "response": resp}),
                ])
            return self._json(200, resp)
        # chat completions (default)
        if stream:
            chunk = {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "mock-chat",
                     "choices": [{"index": 0, "delta": {"role": "assistant", "content": "ok"}, "finish_reason": None}]}
            done = {**chunk, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            return self._sse([(None, chunk), (None, done), (None, "[DONE]")])
        return self._json(200, {"id": "c1", "object": "chat.completion", "created": 1, "model": "mock-chat",
                                "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    def _moderations(self, body):
        if self.headers.get("Authorization") != "Bearer test-moderation-key":
            return self._json(401, {"error": {"message": "bad key"}})
        req = json.loads(body)
        items = req.get("input")
        items = items if isinstance(items, list) else [items]
        def flagged(it):
            s = it if isinstance(it, str) else json.dumps(it)
            return "FLAGME" in s
        if any("MODERATION_DOWN" in (i if isinstance(i, str) else "") for i in items):
            return self._json(500, {"error": {"message": "down"}})
        multimodal = any(isinstance(i, dict) for i in items)
        if multimodal:
            res = [{"flagged": any(flagged(i) for i in items), "categories": {"violence": any(flagged(i) for i in items)}}]
        else:
            res = [{"flagged": flagged(i), "categories": {"violence": flagged(i), "harassment": False}} for i in items]
        return self._json(200, {"id": "modr-1", "model": req.get("model"), "results": res})

    def _sse(self, events):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        for name, data in events:
            payload = data if isinstance(data, str) else json.dumps(data)
            if name:
                self.wfile.write(f"event: {name}\n".encode())
            self.wfile.write(f"data: {payload}\n\n".encode())
            self.wfile.flush()
        self.close_connection = True


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
