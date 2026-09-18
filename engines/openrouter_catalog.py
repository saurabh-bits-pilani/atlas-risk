"""
OpenRouter Model Catalog & Discovery Engine.

Provides:
- Live dynamic fetching of OpenRouter model catalog with 3s timeout.
- Rich pre-cached catalog of all verified free models and popular Meta/Google/NVIDIA models.
- Accurate Company/Provider identification (Meta, Google, NVIDIA, DeepSeek, Alibaba/Qwen, etc.).
- Robust filtering by company name and search query.
"""

import json
import logging
import urllib.request
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Curated, always-available catalog of verified free models and popular Meta/Google/NVIDIA models
FALLBACK_OPENROUTER_MODELS = [
    # Universal auto-router
    {
        "id": "openrouter/free",
        "name": "Free Models Universal Auto-Router",
        "company": "OpenRouter",
        "is_free": True,
        "description": "Auto-routes to currently available free community models without 404s"
    },
    # Meta / Llama
    {
        "id": "meta-llama/llama-3.3-70b-instruct:free",
        "name": "Llama 3.3 70B Instruct (Free Tier)",
        "company": "Meta (Llama)",
        "is_free": True,
        "description": "Meta's flagship 70B open weight reasoning and coding model"
    },
    {
        "id": "meta-llama/llama-3.2-3b-instruct:free",
        "name": "Llama 3.2 3B Instruct (Free Tier)",
        "company": "Meta (Llama)",
        "is_free": True,
        "description": "Meta lightweight 3B edge-optimized instruction model"
    },
    {
        "id": "meta-llama/llama-3.1-8b-instruct:free",
        "name": "Llama 3.1 8B Instruct (Free Tier)",
        "company": "Meta (Llama)",
        "is_free": True,
        "description": "Meta highly versatile 8B instruction tuned LLM"
    },
    {
        "id": "meta-llama/llama-3.3-70b-instruct",
        "name": "Llama 3.3 70B Instruct",
        "company": "Meta (Llama)",
        "is_free": False,
        "description": "Meta 70B production model ($0.0000001/token micro-tier)"
    },
    {
        "id": "meta-llama/llama-3.2-3b-instruct",
        "name": "Llama 3.2 3B Instruct",
        "company": "Meta (Llama)",
        "is_free": False,
        "description": "Meta fast 3B instruction model ($0.00000005/token micro-tier)"
    },
    {
        "id": "meta-llama/llama-3.2-1b-instruct",
        "name": "Llama 3.2 1B Instruct",
        "company": "Meta (Llama)",
        "is_free": False,
        "description": "Meta ultra-compact 1B model ($0.000000027/token micro-tier)"
    },
    {
        "id": "meta/muse-spark-1.3-contributor",
        "name": "Muse Spark 1.3 Contributor",
        "company": "Meta (Llama)",
        "is_free": False,
        "description": "Meta multimodal reasoning contributor model"
    },
    # Google
    {
        "id": "google/gemma-4-31b-it:free",
        "name": "Gemma 4 31B Instruct (Free)",
        "company": "Google",
        "is_free": True,
        "description": "Google DeepMind open weights 31B instruction model"
    },
    {
        "id": "google/gemma-4-26b-a4b-it:free",
        "name": "Gemma 4 26B A4B Instruct (Free)",
        "company": "Google",
        "is_free": True,
        "description": "Google DeepMind lightweight Gemma 4 variant"
    },
    {
        "id": "google/gemma-2-9b-it:free",
        "name": "Gemma 2 9B Instruct (Free)",
        "company": "Google",
        "is_free": True,
        "description": "Google Gemma 2 9B high performance open model"
    },
    # NVIDIA
    {
        "id": "nvidia/nemotron-3.5-lightning:free",
        "name": "Nemotron 3.5 Lightning (Free)",
        "company": "NVIDIA",
        "is_free": True,
        "description": "NVIDIA ultra-fast low-latency generative model"
    },
    {
        "id": "nvidia/nemotron-3.5-content-safety:free",
        "name": "Nemotron 3.5 Content Safety (Free)",
        "company": "NVIDIA",
        "is_free": True,
        "description": "NVIDIA guardrail and safety evaluation model"
    },
    {
        "id": "nvidia/nemotron-3-ultra-550b-a55b:free",
        "name": "Nemotron 3 Ultra (Free)",
        "company": "NVIDIA",
        "is_free": True,
        "description": "NVIDIA massive MoE architecture model"
    },
    {
        "id": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
        "name": "Nemotron 3 Nano Omni (Free)",
        "company": "NVIDIA",
        "is_free": True,
        "description": "NVIDIA multimodal reasoning model"
    },
    {
        "id": "nvidia/nemotron-3-super-120b-a12b:free",
        "name": "Nemotron 3 Super (Free)",
        "company": "NVIDIA",
        "is_free": True,
        "description": "NVIDIA 120B high-throughput model"
    },
    # DeepSeek
    {
        "id": "deepseek/deepseek-v4-flash-0731:free",
        "name": "DeepSeek V4 Flash 0731 (Free)",
        "company": "DeepSeek",
        "is_free": True,
        "description": "DeepSeek fast reasoning and code generation model"
    },
    {
        "id": "deepseek/deepseek-r1:free",
        "name": "DeepSeek R1 Reasoning (Free Tier)",
        "company": "DeepSeek",
        "is_free": True,
        "description": "DeepSeek breakthrough open reasoning model"
    },
    # Alibaba / Qwen
    {
        "id": "qwen/qwen3.8-27b:free",
        "name": "Qwen 3.8 27B (Free)",
        "company": "Alibaba (Qwen)",
        "is_free": True,
        "description": "Alibaba Cloud high-capability bilingual LLM"
    },
    {
        "id": "qwen/qwen-2.5-72b-instruct:free",
        "name": "Qwen 2.5 72B Instruct (Free Tier)",
        "company": "Alibaba (Qwen)",
        "is_free": True,
        "description": "Alibaba 72B flagship open instruction model"
    },
    # Cohere
    {
        "id": "cohere/north-mini-code:free",
        "name": "North Mini Code (Free)",
        "company": "Cohere",
        "is_free": True,
        "description": "Cohere enterprise code assistant model"
    },
    # Z.ai
    {
        "id": "z-ai/glm-5.2:free",
        "name": "GLM 5.2 (Free)",
        "company": "Z.ai (GLM)",
        "is_free": True,
        "description": "General Language Model by Z.ai"
    },
    # LiquidAI
    {
        "id": "liquid/lfm-2.5-2.6b:free",
        "name": "LFM 2.5 2.6B (Free)",
        "company": "LiquidAI",
        "is_free": True,
        "description": "Liquid Neural Network foundation model"
    },
    # inclusionAI
    {
        "id": "inclusionai/ling-3.0-flash-vl:free",
        "name": "Ling 3.0 Flash VL (Free)",
        "company": "inclusionAI",
        "is_free": True,
        "description": "InclusionAI vision-language multimodal model"
    },
    {
        "id": "inclusionai/ling-3.0-flash-sante:free",
        "name": "Ling 3.0 Flash Sante (Free)",
        "company": "inclusionAI",
        "is_free": True,
        "description": "InclusionAI healthcare & scientific domain model"
    },
    {
        "id": "inclusionai/ling-3.0-flash-fin:free",
        "name": "Ling 3.0 Flash Fin (Free)",
        "company": "inclusionAI",
        "is_free": True,
        "description": "InclusionAI finance & accounting domain model"
    },
    # Nex AGI
    {
        "id": "nex-agi/nex-n2.5-mini:free",
        "name": "Nex-N2.5-Mini (Free)",
        "company": "Nex AGI",
        "is_free": True,
        "description": "Agentic coding and planning model"
    },
    {
        "id": "nex-agi/nex-n2.5-pro:free",
        "name": "Nex-N2.5-Pro (Free)",
        "company": "Nex AGI",
        "is_free": True,
        "description": "Advanced multi-file coding agent model"
    },
    # Thinking Machines
    {
        "id": "thinkingmachines/inkling-small:free",
        "name": "Inkling Small (Free)",
        "company": "Thinking Machines",
        "is_free": True,
        "description": "Compact conversational reasoning LLM"
    },
    # Poolside
    {
        "id": "poolside/laguna-s-2.1:free",
        "name": "Laguna S 2.1 (Free)",
        "company": "Poolside",
        "is_free": True,
        "description": "Code synthesis and software engineering model"
    },
    # Dots Studio
    {
        "id": "dots-studio/dots-3-note-preview:free",
        "name": "Dots3-Note Preview (Free)",
        "company": "Dots Studio",
        "is_free": True,
        "description": "Document parsing and note generation model"
    },
]

# Company normalization map
COMPANY_ALIASES = {
    "meta-llama": "Meta (Llama)",
    "meta": "Meta (Llama)",
    "google": "Google",
    "nvidia": "NVIDIA",
    "deepseek": "DeepSeek",
    "qwen": "Alibaba (Qwen)",
    "openrouter": "OpenRouter",
    "cohere": "Cohere",
    "z-ai": "Z.ai (GLM)",
    "liquid": "LiquidAI",
    "inclusionai": "inclusionAI",
    "nex-agi": "Nex AGI",
    "thinkingmachines": "Thinking Machines",
    "poolside": "Poolside",
    "dots-studio": "Dots Studio",
    "mistralai": "Mistral AI",
    "microsoft": "Microsoft",
    "anthropic": "Anthropic",
    "openai": "OpenAI",
}


def _normalize_company(slug_or_id: str, raw_name: str = "") -> str:
    """Derive clean, human-friendly company name."""
    lower_slug = slug_or_id.lower()
    prefix = lower_slug.split("/")[0] if "/" in lower_slug else lower_slug
    
    if prefix in COMPANY_ALIASES:
        return COMPANY_ALIASES[prefix]
    
    # Check if raw_name contains company prefix e.g. "Meta: Llama..."
    if ":" in raw_name:
        company_part = raw_name.split(":")[0].strip()
        if "meta" in company_part.lower():
            return "Meta (Llama)"
        if "google" in company_part.lower():
            return "Google"
        if "qwen" in company_part.lower() or "alibaba" in company_part.lower():
            return "Alibaba (Qwen)"
        if "z.ai" in company_part.lower() or "glm" in company_part.lower():
            return "Z.ai (GLM)"
        return company_part
        
    return prefix.capitalize()


def fetch_live_openrouter_catalog(timeout_sec: float = 3.5) -> List[Dict]:
    """
    Fetch live model list from OpenRouter API.
    Falls back cleanly to FALLBACK_OPENROUTER_MODELS on network issues or timeout.
    """
    url = "https://openrouter.ai/api/v1/models"
    headers = {"User-Agent": "ATLAS-Risk-Security-Scanner/1.0"}
    
    models = list(FALLBACK_OPENROUTER_MODELS)
    seen_ids = {m["id"] for m in models}
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode("utf-8")).get("data", [])
                
                for item in data:
                    mid = item.get("id", "")
                    if not mid:
                        continue
                        
                    pricing = item.get("pricing", {})
                    p_prompt = str(pricing.get("prompt", "1"))
                    p_comp = str(pricing.get("completion", "1"))
                    
                    is_free = (
                        ":free" in mid or 
                        mid == "openrouter/free" or 
                        (p_prompt == "0" and p_comp == "0")
                    )
                    
                    # Also include Meta models even if low-tier so Meta filtering is rich
                    is_meta = "meta" in mid.lower() or "llama" in mid.lower()
                    
                    if not (is_free or is_meta):
                        continue
                        
                    company = _normalize_company(mid, item.get("name", ""))
                    clean_name = item.get("name", mid)
                    
                    # If this model is already in catalog, update description/free status
                    if mid in seen_ids:
                        for existing in models:
                            if existing["id"] == mid:
                                existing["is_free"] = is_free
                                if item.get("description"):
                                    existing["description"] = item["description"][:160]
                                break
                    else:
                        models.append({
                            "id": mid,
                            "name": clean_name,
                            "company": company,
                            "is_free": is_free,
                            "description": (item.get("description") or "OpenRouter hosted model")[:160]
                        })
                        seen_ids.add(mid)
    except Exception as e:
        logger.warning(f"Could not refresh live OpenRouter catalog: {e}. Using bundled catalog.")
        
    return models


def get_available_companies(catalog: List[Dict]) -> List[str]:
    """Get sorted list of all unique company providers for filtering."""
    companies = set()
    for m in catalog:
        companies.add(m.get("company", "Other"))
        
    # Order: All at top, Meta, Google, NVIDIA, DeepSeek, Alibaba, OpenRouter, then alphabetically
    priority_order = [
        "Meta (Llama)",
        "Google",
        "NVIDIA",
        "DeepSeek",
        "Alibaba (Qwen)",
        "OpenRouter",
    ]
    
    sorted_companies = []
    for p in priority_order:
        if p in companies:
            sorted_companies.append(p)
            companies.remove(p)
            
    sorted_companies.extend(sorted(list(companies)))
    return ["All Providers (Free & Meta)"] + sorted_companies


def filter_models(
    catalog: List[Dict],
    selected_company: str = "All Providers (Free & Meta)",
    search_query: str = "",
    free_only: bool = False
) -> List[Dict]:
    """
    Filter catalog by company and/or search text.
    """
    query = (search_query or "").strip().lower()
    filtered = []
    
    for m in catalog:
        # Company check
        if selected_company and not selected_company.startswith("All"):
            if m.get("company") != selected_company:
                continue
                
        # Free only check
        if free_only and not m.get("is_free", False):
            continue
            
        # Search query check
        if query:
            match_id = query in m.get("id", "").lower()
            match_name = query in m.get("name", "").lower()
            match_company = query in m.get("company", "").lower()
            match_desc = query in m.get("description", "").lower()
            if not (match_id or match_name or match_company or match_desc):
                continue
                
        filtered.append(m)
        
    # Sort: OpenRouter Free router first, then free models, then alphabetically by name
    def sort_key(item):
        is_free_router = 0 if item["id"] == "openrouter/free" else 1
        is_free = 0 if item.get("is_free", False) else 1
        return (is_free_router, is_free, item.get("company", ""), item.get("name", ""))
        
    filtered.sort(key=sort_key)
    return filtered


def format_model_label(model_item: Dict) -> str:
    """
    Format model item for user-facing selectbox display.
    Example:
    Meta (Llama) | Llama 3.3 70B Instruct (Free Tier) (🟢 FREE) — meta-llama/llama-3.3-70b-instruct:free
    """
    company = model_item.get("company", "Cloud AI")
    name = model_item.get("name", model_item["id"])
    # Strip redundant company prefix from name if already present
    if ":" in name and name.split(":")[0].strip().lower() in company.lower():
        name = name.split(":", 1)[1].strip()
        
    badge = "🟢 FREE" if model_item.get("is_free", False) else "🔹 MICRO-TIER"
    return f"{company} • {name} ({badge})"
