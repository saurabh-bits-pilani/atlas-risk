import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engines.openrouter_catalog import (
    FALLBACK_OPENROUTER_MODELS,
    fetch_live_openrouter_catalog,
    get_available_companies,
    filter_models,
    format_model_label,
    _normalize_company
)


def test_company_normalization():
    assert _normalize_company("meta-llama/llama-3.3-70b-instruct") == "Meta (Llama)"
    assert _normalize_company("meta/muse-spark-1.3") == "Meta (Llama)"
    assert _normalize_company("google/gemma-4-31b-it:free") == "Google"
    assert _normalize_company("nvidia/nemotron-3.5-lightning:free") == "NVIDIA"
    assert _normalize_company("deepseek/deepseek-v4-flash-0731:free") == "DeepSeek"
    assert _normalize_company("qwen/qwen3.8-27b:free") == "Alibaba (Qwen)"
    assert _normalize_company("openrouter/free") == "OpenRouter"


def test_fallback_catalog_structure():
    assert len(FALLBACK_OPENROUTER_MODELS) >= 20
    for m in FALLBACK_OPENROUTER_MODELS:
        assert "id" in m
        assert "name" in m
        assert "company" in m
        assert "is_free" in m
        assert isinstance(m["is_free"], bool)


def test_filter_by_company():
    catalog = FALLBACK_OPENROUTER_MODELS
    
    # Meta filter
    meta_models = filter_models(catalog, selected_company="Meta (Llama)")
    assert len(meta_models) >= 3
    for m in meta_models:
        assert m["company"] == "Meta (Llama)"
        assert ("meta" in m["id"].lower() or "llama" in m["id"].lower())

    # Google filter
    google_models = filter_models(catalog, selected_company="Google")
    assert len(google_models) >= 2
    for m in google_models:
        assert m["company"] == "Google"
        assert "google" in m["id"].lower()

    # NVIDIA filter
    nvidia_models = filter_models(catalog, selected_company="NVIDIA")
    assert len(nvidia_models) >= 3
    for m in nvidia_models:
        assert m["company"] == "NVIDIA"

    # DeepSeek filter
    deepseek_models = filter_models(catalog, selected_company="DeepSeek")
    assert len(deepseek_models) >= 1
    for m in deepseek_models:
        assert m["company"] == "DeepSeek"


def test_filter_free_only():
    catalog = FALLBACK_OPENROUTER_MODELS
    free_models = filter_models(catalog, free_only=True)
    assert len(free_models) > 0
    for m in free_models:
        assert m["is_free"] is True


def test_display_label_formatting():
    item = {
        "id": "meta-llama/llama-3.3-70b-instruct:free",
        "name": "Meta: Llama 3.3 70B Instruct (Free Tier)",
        "company": "Meta (Llama)",
        "is_free": True
    }
    label = format_model_label(item)
    assert "Meta (Llama)" in label
    assert "FREE" in label


def test_get_available_companies_ordering():
    catalog = FALLBACK_OPENROUTER_MODELS
    comps = get_available_companies(catalog)
    assert comps[0].startswith("All Providers")
    assert "Meta (Llama)" in comps
    assert "Google" in comps
    assert "NVIDIA" in comps
    assert "DeepSeek" in comps
