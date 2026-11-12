import re


def _normalize_words(value: str) -> set[str]:
    """Normalize item and policy names for matching."""
    words = set(re.findall(r"[a-z0-9]+", str(value or "").lower()))
    normalized = set()

    for word in words:
        if len(word) > 4 and word.endswith("ies"):
            normalized.add(word[:-3] + "y")
        elif len(word) > 3 and word.endswith("s"):
            normalized.add(word[:-1])
        else:
            normalized.add(word)

    return normalized


def _matches_prohibited(
    item_text: str,
    prohibited_terms: list[str],
) -> bool:
    item_words = _normalize_words(item_text)

    return any(
        bool(rule_words) and rule_words.issubset(item_words)
        for rule_words in (
            _normalize_words(term)
            for term in prohibited_terms
        )
    )