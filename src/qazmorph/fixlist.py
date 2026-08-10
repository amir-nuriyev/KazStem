"""Small, auditable user dictionaries that override the compiled lexicon."""

from __future__ import annotations

import json
from pathlib import Path
import re
import unicodedata

from .stream import parse_analysis
from .tags import UD_PROFILES
from .types import Analysis


class FixlistError(ValueError):
    pass


TAG_PATTERN = re.compile(r"^[A-Za-z0-9_:-]+$")


def load_fixlist(
    path: str | Path, *, ud_profile: str = "universal"
) -> dict[str, list[Analysis]]:
    """Load JSONL or ``form<TAB>lemma<TAB>tag,tag`` entries."""

    if ud_profile not in UD_PROFILES:
        raise ValueError(f"unknown UD projection profile: {ud_profile}")
    source = Path(path)
    entries: dict[str, list[Analysis]] = {}
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            if stripped.startswith("{"):
                row = json.loads(stripped)
                form = str(row["form"])
                lemma = str(row["lemma"])
                raw_tags = row.get("tags", ("x",))
                if not isinstance(raw_tags, (list, tuple)) or not all(
                    isinstance(tag, str) for tag in raw_tags
                ):
                    raise FixlistError("tags must be a list of strings")
                tags = tuple(raw_tags)
            else:
                fields = line.split("\t")
                if len(fields) != 3:
                    raise FixlistError("expected three tab-separated columns")
                form, lemma, tag_field = fields
                tags = tuple(tag.strip(" <>") for tag in tag_field.replace("><", ",").split(",") if tag.strip())
            if any(not TAG_PATTERN.fullmatch(tag) for tag in tags):
                raise FixlistError("tags may contain only letters, digits, _, :, and -")
            if any(char in lemma for char in "<>\r\n"):
                raise FixlistError("lemma contains reserved morphology syntax")
            form = unicodedata.normalize("NFC", form)
            lemma = unicodedata.normalize("NFC", lemma)
            escaped_lemma = lemma.replace("\\", "\\\\").replace("+", "\\+")
            raw = escaped_lemma + "".join(f"<{tag}>" for tag in tags)
            analysis = parse_analysis(
                raw, source="fixlist", ud_profile=ud_profile
            )
            if analysis is None:
                raise FixlistError("entry produced no analysis")
            entries.setdefault(form.casefold(), []).append(analysis)
        except (KeyError, TypeError, json.JSONDecodeError, FixlistError) as exc:
            raise FixlistError(f"{source}:{line_number}: {exc}") from exc
    return entries
