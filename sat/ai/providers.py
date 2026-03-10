"""
providers.py – LLM provider configs + fallback chain for Security Audit Tool.

Chỉ cần copy .env.example → .env, ném key vào, chạy là xong.
Tool tự load .env và thử từng provider theo FALLBACK_ORDER.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.request import Request, urlopen


# ── Auto-load .env (tìm từ thư mục hiện tại lên đến root) ────────────────────
def _load_dotenv() -> None:
    """Load .env file mà không cần thư viện ngoài."""
    search = Path(__file__).resolve()
    for parent in [search.parent, search.parent.parent, Path.cwd()]:
        env_file = parent / ".env"
        if env_file.exists():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and value and key not in os.environ:
                    os.environ[key] = value
            break  # chỉ load file .env đầu tiên tìm thấy

_load_dotenv()

# ══════════════════════════════════════════════════════════════════════════════
# 1.  API KEY PATTERNS – chỉnh key của bạn vào đây
# ══════════════════════════════════════════════════════════════════════════════

API_KEYS: dict[str, str] = {
    # ── Anthropic ────────────────────────────────────────────────────────────
    # Format: sk-ant-api03-[86 ký tự base64]
    # Lấy tại: https://console.anthropic.com/settings/keys
    "anthropic":     os.environ.get("ANTHROPIC_API_KEY", ""),

    # ── OpenRouter ───────────────────────────────────────────────────────────
    # Format: sk-or-v1-[64 ký tự hex]
    # Lấy tại: https://openrouter.ai/keys
    "openrouter":    os.environ.get("OPENROUTER_API_KEY", ""),

    # ── OpenAI ───────────────────────────────────────────────────────────────
    # Format: sk-proj-[48 ký tự] HOẶC sk-[48 ký tự] (legacy)
    # Lấy tại: https://platform.openai.com/api-keys
    "openai":        os.environ.get("OPENAI_API_KEY", ""),

    # ── Google Gemini (AI Studio) ─────────────────────────────────────────────
    # Format: AIza[35 ký tự base64]
    # Lấy tại: https://aistudio.google.com/app/apikey
    "gemini":        os.environ.get("GEMINI_API_KEY", ""),

    # ── Google Vertex AI ──────────────────────────────────────────────────────
    # Dùng service account JSON, hoặc gcloud auth token
    # Format token: ya29.[ký tự dài]
    # Lấy tại: https://cloud.google.com/vertex-ai
    "vertex":        os.environ.get("VERTEX_API_KEY", ""),

    # ── Groq ─────────────────────────────────────────────────────────────────
    # Format: gsk_[52 ký tự]
    # Lấy tại: https://console.groq.com/keys
    "groq":          os.environ.get("GROQ_API_KEY", ""),

    # ── Together AI ───────────────────────────────────────────────────────────
    # Format: [64 ký tự hex]
    # Lấy tại: https://api.together.xyz/settings/api-keys
    "together":      os.environ.get("TOGETHER_API_KEY", ""),

    # ── Mistral AI ────────────────────────────────────────────────────────────
    # Format: [32 ký tự alphanum]
    # Lấy tại: https://console.mistral.ai/api-keys
    "mistral":       os.environ.get("MISTRAL_API_KEY", ""),

    # ── Cohere ───────────────────────────────────────────────────────────────
    # Format: [40 ký tự alphanum]
    # Lấy tại: https://dashboard.cohere.com/api-keys
    "cohere":        os.environ.get("COHERE_API_KEY", ""),

    # ── DeepSeek ─────────────────────────────────────────────────────────────
    # Format: sk-[32 ký tự hex]
    # Lấy tại: https://platform.deepseek.com/api_keys
    "deepseek":      os.environ.get("DEEPSEEK_API_KEY", ""),

    # ── Ollama (local) ────────────────────────────────────────────────────────
    # Không cần API key — chỉ cần Ollama đang chạy
    # Cài tại: https://ollama.com  →  ollama serve
    "ollama":        "local",

    # ── LM Studio (local) ────────────────────────────────────────────────────
    # Không cần API key — chạy LM Studio, bật Local Server
    # Download tại: https://lmstudio.ai
    "lmstudio":      "local",
}


# ══════════════════════════════════════════════════════════════════════════════
# 2.  PROVIDER CONFIGS – endpoint, headers, payload format, response parser
# ══════════════════════════════════════════════════════════════════════════════

def _openai_style(url: str, key: str, model: str) -> dict:
    """Shared config for any OpenAI-compatible endpoint."""
    return {
        "url": url,
        "headers": {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        },
        "make_payload": lambda prompt, max_tokens: {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        },
        "parse_response": lambda data: data["choices"][0]["message"]["content"],
    }


PROVIDERS: dict[str, dict] = {

    # ── Anthropic ─────────────────────────────────────────────────────────────
    "anthropic": {
        "url": "https://api.anthropic.com/v1/messages",
        "headers": {
            "Content-Type": "application/json",
            "x-api-key": lambda key: key,          # injected at call time
            "anthropic-version": "2023-06-01",
        },
        "make_payload": lambda prompt, max_tokens: {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        },
        "parse_response": lambda data: data["content"][0]["text"],
    },

    # ── OpenRouter ────────────────────────────────────────────────────────────
    # Hỗ trợ 200+ model, chọn qua OPENROUTER_MODEL env var
    "openrouter": {
        **_openai_style(
            url="https://openrouter.ai/api/v1/chat/completions",
            key="",                                 # injected at call time
            model=os.environ.get("OPENROUTER_MODEL", "anthropic/claude-sonnet-4"),
        ),
        "extra_headers": {
            "HTTP-Referer": "https://localhost",
            "X-Title": "Security Audit Tool",
        },
    },

    # ── OpenAI ────────────────────────────────────────────────────────────────
    "openai": _openai_style(
        url="https://api.openai.com/v1/chat/completions",
        key="",
        model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    ),

    # ── Google Gemini ─────────────────────────────────────────────────────────
    # Dùng REST API v1beta (không phải OpenAI-compat)
    "gemini": {
        "url": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "model": os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"),
        "make_payload": lambda prompt, max_tokens: {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens},
        },
        "parse_response": lambda data: data["candidates"][0]["content"]["parts"][0]["text"],
        # key appended as ?key=... query param
    },

    # ── Groq (OpenAI-compat, rất nhanh) ──────────────────────────────────────
    "groq": _openai_style(
        url="https://api.groq.com/openai/v1/chat/completions",
        key="",
        model=os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
    ),

    # ── Together AI ───────────────────────────────────────────────────────────
    "together": _openai_style(
        url="https://api.together.xyz/v1/chat/completions",
        key="",
        model=os.environ.get("TOGETHER_MODEL", "meta-llama/Llama-3-70b-chat-hf"),
    ),

    # ── Mistral AI ────────────────────────────────────────────────────────────
    "mistral": _openai_style(
        url="https://api.mistral.ai/v1/chat/completions",
        key="",
        model=os.environ.get("MISTRAL_MODEL", "mistral-small-latest"),
    ),

    # ── DeepSeek (OpenAI-compat) ──────────────────────────────────────────────
    "deepseek": _openai_style(
        url="https://api.deepseek.com/v1/chat/completions",
        key="",
        model=os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
    ),

    # ── Cohere ───────────────────────────────────────────────────────────────
    "cohere": {
        "url": "https://api.cohere.com/v2/chat",
        "headers": {
            "Content-Type": "application/json",
            "Authorization": lambda key: f"Bearer {key}",
        },
        "make_payload": lambda prompt, max_tokens: {
            "model": os.environ.get("COHERE_MODEL", "command-r-plus-08-2024"),
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
        },
        "parse_response": lambda data: data["message"]["content"][0]["text"],
    },

    # ── Ollama (local – không cần key) ────────────────────────────────────────
    "ollama": _openai_style(
        url=os.environ.get("OLLAMA_HOST", "http://localhost:11434") + "/api/chat",
        key="ollama",
        model=os.environ.get("OLLAMA_MODEL", "llama3.2"),
    ),

    # ── LM Studio (local – không cần key) ─────────────────────────────────────
    "lmstudio": _openai_style(
        url=os.environ.get("LMSTUDIO_HOST", "http://localhost:1234") + "/v1/chat/completions",
        key="lm-studio",
        model=os.environ.get("LMSTUDIO_MODEL", "local-model"),
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
# 3.  FALLBACK ORDER – thử lần lượt, dừng khi có key
#     Chỉnh thứ tự theo ý bạn
# ══════════════════════════════════════════════════════════════════════════════

FALLBACK_ORDER: list[str] = [
    "anthropic",    # ưu tiên cao nhất nếu có key
    "openrouter",   # nhiều model, giá linh hoạt
    "openai",
    "gemini",
    "groq",         # nhanh, rẻ
    "deepseek",
    "together",
    "mistral",
    "cohere",
    "ollama",       # local fallback cuối cùng
    "lmstudio",
]


# ══════════════════════════════════════════════════════════════════════════════
# 4.  CALLER – tự chọn provider + fallback
# ══════════════════════════════════════════════════════════════════════════════

def _call_provider(provider_name: str, prompt: str, max_tokens: int = 600) -> str | None:
    """Gọi một provider cụ thể. Trả về text hoặc None nếu lỗi."""
    key = API_KEYS.get(provider_name, "")
    if not key:
        return None

    cfg = PROVIDERS.get(provider_name)
    if not cfg:
        return None

    # Build URL
    url = cfg["url"]
    if provider_name == "gemini":
        model = cfg.get("model", "gemini-2.0-flash")
        url = url.format(model=model) + f"?key={key}"

    # Build headers
    raw_headers = {**cfg.get("headers", {}), **cfg.get("extra_headers", {})}
    headers: dict[str, str] = {}
    for k, v in raw_headers.items():
        headers[k] = v(key) if callable(v) else v

    # Inject Authorization for OpenAI-style if not Gemini/Anthropic
    if provider_name not in ("anthropic", "gemini", "cohere") and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {key}"

    # Build payload
    payload = cfg["make_payload"](prompt, max_tokens)

    req = Request(url, method="POST",
                  data=json.dumps(payload).encode(), headers=headers)
    try:
        with urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
            return cfg["parse_response"](data)
    except Exception:
        return None


def call_with_fallback(
    prompt: str,
    max_tokens: int = 600,
    provider: str | None = None,
) -> tuple[str | None, str | None]:
    """
    Gọi LLM với provider chỉ định hoặc tự động fallback.
    Returns: (text_response, provider_used)
    """
    if provider:
        result = _call_provider(provider, prompt, max_tokens)
        return (result, provider) if result else (None, None)

    for p in FALLBACK_ORDER:
        result = _call_provider(p, prompt, max_tokens)
        if result:
            return result, p

    return None, None


# ══════════════════════════════════════════════════════════════════════════════
# 5.  QUICK REFERENCE – model names hay dùng trên mỗi provider
# ══════════════════════════════════════════════════════════════════════════════
#
#  ANTHROPIC
#    claude-opus-4-20250514         (mạnh nhất)
#    claude-sonnet-4-20250514       (cân bằng) ← default
#    claude-haiku-4-5-20251001      (nhanh, rẻ)
#
#  OPENROUTER  (prefix provider/model)
#    anthropic/claude-sonnet-4      ← default
#    openai/gpt-4o
#    google/gemini-2.0-flash
#    deepseek/deepseek-r1
#    meta-llama/llama-3.3-70b-instruct:free   ← free tier
#    microsoft/phi-4                           ← nhỏ, nhanh
#
#  OPENAI
#    gpt-4o                         (mạnh)
#    gpt-4o-mini                    (rẻ) ← default
#    o3-mini                        (reasoning)
#
#  GEMINI
#    gemini-2.5-pro-preview-03-25   (mạnh nhất)
#    gemini-2.0-flash               ← default
#    gemini-2.0-flash-lite          (rẻ nhất)
#
#  GROQ
#    llama-3.3-70b-versatile        ← default
#    llama-3.1-8b-instant           (siêu nhanh)
#    mixtral-8x7b-32768
#    gemma2-9b-it
#
#  DEEPSEEK
#    deepseek-chat                  ← default (V3)
#    deepseek-reasoner              (R1, reasoning)
#
#  MISTRAL
#    mistral-large-latest
#    mistral-small-latest           ← default
#    codestral-latest               (code)
#
#  OLLAMA  (phải pull model trước: ollama pull <model>)
#    llama3.2                       ← default
#    qwen2.5:7b
#    deepseek-r1:7b
#    mistral:7b
#    phi4:latest
#
#  TOGETHER
#    meta-llama/Llama-3-70b-chat-hf  ← default
#    mistralai/Mixtral-8x22B-Instruct-v0.1
#
# ══════════════════════════════════════════════════════════════════════════════
