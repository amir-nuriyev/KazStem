"""Loss-aware projection from apertium-kaz tags to legal UD v2 values."""

from __future__ import annotations

from collections.abc import Iterable


POS_MAP: dict[str, str] = {
    "n": "NOUN",
    "np": "PROPN",
    "adj": "ADJ",
    "adv": "ADV",
    "v": "VERB",
    "vaux": "AUX",
    "cop": "AUX",
    "prn": "PRON",
    "det": "DET",
    "num": "NUM",
    "post": "ADP",
    "postadv": "ADV",
    "cnjcoo": "CCONJ",
    "cnjsub": "SCONJ",
    "cnjadv": "SCONJ",
    "ij": "INTJ",
    "ideo": "X",
    "paren": "X",
    "qst": "PART",
    "mod": "PART",
    "mod_ass": "PART",
    "mod_emo": "PART",
    "emph": "PART",
    "sent": "PUNCT",
    "cm": "PUNCT",
    "apos": "PUNCT",
    "lquot": "PUNCT",
    "rquot": "PUNCT",
    "lpar": "PUNCT",
    "rpar": "PUNCT",
    "guio": "PUNCT",
    "punct": "PUNCT",
    "ltr": "SYM",
    "sym": "SYM",
    "abbr": "NOUN",
}

PRIMARY_CASE_MAP = {
    "nom": "Nom",
    "gen": "Gen",
    "dat": "Dat",
    "acc": "Acc",
    "loc": "Loc",
    "abl": "Abl",
    "ins": "Ins",
}
SECONDARY_CASE_MAP = {"abe": "Abe", "equ": "Equ", "sim": "Equ", "reas": "Cau"}

VERB_FORM_MAP = {
    "ger": "Ger",
    "ger2": "Ger",
    "ger_abs": "Ger",
    "ger_fut": "Ger",
    "ger_impf": "Ger",
    "ger_obs": "Ger",
    "ger_past": "Ger",
    "ger_perf": "Ger",
    "ger_ppot": "Ger",
    "gpr_fut": "Part",
    "gpr_impf": "Part",
    "gpr_past": "Part",
    "gpr_pot": "Part",
    "gpr_pot2": "Part",
    "gpr_ppot": "Part",
    "gna_after": "Conv",
    "gna_cond": "Conv",
    "gna_impf": "Conv",
    "gna_perf": "Conv",
    "gna_until": "Conv",
    "prc_cond": "Inf",
    "prc_fplan": "Inf",
    "prc_impf": "Inf",
    "prc_irre": "Inf",
    "prc_perf": "Inf",
    "prc_plan": "Inf",
    "prc_vol": "Inf",
}

FINITE_TAGS = frozenset({"imp", "opt", "pres", "aor", "past", "ifi", "ifi_evid", "fut", "fut_plan", "pih"})
UD_PROFILES = frozenset({"universal", "ktb"})


def _first(tags: tuple[str, ...], mapping: dict[str, str]) -> str | None:
    return next((mapping[tag] for tag in tags if tag in mapping), None)


def _last(tags: tuple[str, ...], mapping: dict[str, str]) -> str | None:
    return next((mapping[tag] for tag in reversed(tags) if tag in mapping), None)


def project_ud(
    tags: Iterable[str], *, profile: str = "universal"
) -> tuple[str, tuple[tuple[str, str], ...]]:
    """Return ``(UPOS, sorted UD features)`` without discarding raw tags.

    ``profile='universal'`` uses semantically appropriate legal UD v2 values.
    ``profile='ktb'`` reproduces Kazakh-KTB's Coll/Fh values and omits legal
    universal features that are outside that treebank's annotation inventory.
    """

    if profile not in UD_PROFILES:
        raise ValueError(f"unknown UD projection profile: {profile}")
    ordered = tuple(tags)
    upos = _first(ordered, POS_MAP) or "X"
    features: dict[str, str] = {}

    # Kazakh suffix chains may contain secondary and primary cases. UD exposes
    # the final primary case; the ordered raw chain remains available losslessly.
    case = _last(ordered, PRIMARY_CASE_MAP)
    if case is None:
        case = _last(ordered, SECONDARY_CASE_MAP)
    if case is None and "attr" in ordered:
        case = "Nom"
    if case:
        features["Case"] = case

    verb_form = _first(ordered, VERB_FORM_MAP)
    if verb_form:
        features["VerbForm"] = verb_form
    elif upos in {"VERB", "AUX"} and any(tag in FINITE_TAGS for tag in ordered):
        features["VerbForm"] = "Fin"

    mood = _first(
        ordered,
        {
            "imp": "Imp",
            "opt": "Opt",
            "prc_cond": "Cnd",
            "gna_cond": "Cnd",
            "prc_vol": "Des",
            "prc_fplan": "Des",
            "prc_plan": "Prp",
            "fut_plan": "Des",
            "gpr_pot": "Pot",
            "gpr_pot2": "Pot",
            "gpr_ppot": "Pot",
            "ger_ppot": "Pot",
        },
    )
    if mood:
        features["Mood"] = mood
    elif upos in {"VERB", "AUX"} and features.get("VerbForm") == "Fin":
        features["Mood"] = "Ind"

    tense = _first(
        ordered,
        {
            "past": "Past",
            "ifi": "Past",
            "ifi_evid": "Past",
            "pih": "Past",
            "pres": "Pres",
            "aor": "Pres",
            "fut": "Fut",
            "fut_plan": "Fut",
            "prc_fplan": "Fut",
            "gpr_fut": "Fut",
            "gpr_past": "Past",
            "gpr_ppot": "Past",
            "ger_fut": "Fut",
            "ger_obs": "Fut",
            "ger_past": "Past",
            "ger_ppot": "Past",
        },
    )
    if tense:
        features["Tense"] = tense

    aspect = _first(
        ordered,
        {
            "aor": "Hab",
            "pih": "Imp",
            "prc_impf": "Imp",
            "gna_impf": "Imp",
            "gpr_impf": "Imp",
            "ger_impf": "Imp",
            "prc_perf": "Perf",
            "gna_perf": "Perf",
            "ger_perf": "Perf",
        },
    )
    if aspect:
        features["Aspect"] = aspect

    if "neg" in ordered:
        if upos in {"PRON", "DET"}:
            features["PronType"] = "Neg"
        elif upos in {"VERB", "AUX"}:
            features["Polarity"] = "Neg"
    if "comp" in ordered:
        features["Degree"] = "Cmp"

    voices = {
        value
        for tag, value in {"pass": "Pass", "caus": "Cau", "coop": "Rcp", "recip": "Rcp"}.items()
        if tag in ordered and (tag != "recip" or upos == "VERB")
    }
    if "ref" in ordered and upos == "VERB":
        voices.add("Rfl")
    if voices:
        features["Voice"] = ",".join(sorted(voices))

    if "evid" in ordered or "ifi_evid" in ordered:
        features["Evident"] = "Fh" if profile == "ktb" else "Nfh"
    if "frm" in ordered:
        features["Polite"] = "Form"

    person = next((tag[1:] for tag in ordered if tag in {"p1", "p2", "p3"}), None)
    if person:
        features["Person"] = person
    if "pl" in ordered and upos in {"VERB", "AUX", "PRON", "NOUN", "PROPN", "ADJ"}:
        features["Number"] = "Plur"
    elif "sg" in ordered and upos in {"VERB", "AUX", "PRON"}:
        features["Number"] = "Sing"

    possessor = next((tag for tag in ordered if tag.startswith("px") and len(tag) >= 4), None)
    if possessor:
        tail = possessor[2:]
        if tail and tail[0] in "123":
            features["Person[psor]"] = tail[0]
        if tail.endswith("pl"):
            features["Number[psor]"] = "Plur"
        elif tail.endswith("sg"):
            features["Number[psor]"] = "Sing"
        elif tail.endswith("sp"):
            features["Number[psor]"] = "Plur,Sing"

    if "dem" in ordered:
        features["PronType"] = "Dem"
    else:
        pron_type = _first(
            ordered,
            {"pers": "Prs", "recip": "Rcp", "itg": "Int", "qnt": "Tot", "ind": "Ind", "ref": "Prs"},
        )
        if pron_type and upos in {"PRON", "DET", "ADV"}:
            features["PronType"] = pron_type
    if "ref" in ordered and upos in {"PRON", "DET"}:
        features["Reflex"] = "Yes"

    if "ord" in ordered:
        features["NumType"] = "Ord"
    elif "coll" in ordered:
        features["NumType"] = "Coll" if profile == "ktb" else "Sets"
    elif "dist" in ordered:
        features["NumType"] = "Dist"
    elif upos == "NUM":
        features["NumType"] = "Card"

    name_type = _first(
        ordered,
        {"top": "Geo", "ant": "Giv", "cog": "Sur", "pat": "Pat", "org": "Com", "al": "Oth"},
    )
    if name_type:
        features["NameType"] = name_type
    if upos == "PROPN":
        if "m" in ordered:
            features["Gender"] = "Masc"
        elif "f" in ordered:
            features["Gender"] = "Fem"

    if "abbr" in ordered:
        features["Abbr"] = "Yes"
    if "qst" in ordered:
        features["PartType"] = "Int"
    elif "emph" in ordered:
        features["PartType"] = "Emp"
    elif any(tag in ordered for tag in ("mod", "mod_ass", "mod_emo")):
        features["PartType"] = "Mod"
    if "unk" in ordered:
        features["Foreign"] = "Yes"
    if "err_orth" in ordered:
        features["Typo"] = "Yes"

    if profile == "ktb":
        # KTB r2.18 does not annotate these otherwise legal UD distinctions.
        # Keep them in the universal profile and in the ordered raw tags; this
        # compatibility projection is deliberately opt-in rather than a
        # weakening of QazMorph's default analysis.
        for key in ("Abbr", "NameType", "PartType"):
            features.pop(key, None)
        if features.get("Case") == "Equ":
            features.pop("Case")

    return upos, tuple(sorted(features.items()))


def project_ud_alternatives(
    tags: Iterable[str],
    *,
    profile: str = "universal",
    bare_decimal: bool = False,
) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    """Return conservative additional UD views licensed by explicit evidence.

    The ordinary :func:`project_ud` result remains the primary projection.  A
    caller may append these alternatives to a *licensed* raw reading, but must
    not use them to turn an unmatched surface into a dictionary analysis.

    ``subst``, ``attr``, and ``advl`` are explicitly documented by
    apertium-kaz as syntactic-use tags.  They therefore license an additional
    UPOS view while retaining every raw-derived feature.  In contrast, a bare
    ``prn`` or ``det`` tag contains no evidence for swapping those categories,
    so this function deliberately adds no PRON/DET alternatives.

    Bare decimal surfaces are semantically underspecified by raw ``<num>``.
    They receive an ordinal alternative in both profiles and KTB's combined
    ``Card,Ord`` convention only in the opt-in compatibility profile.  An
    explicit ``ord``, ``coll``, or ``dist`` tag is never overridden.
    """

    if profile not in UD_PROFILES:
        raise ValueError(f"unknown UD projection profile: {profile}")
    ordered = tuple(tags)
    upos, features = project_ud(ordered, profile=profile)
    alternatives: list[tuple[str, tuple[tuple[str, str], ...]]] = []

    if (
        bare_decimal
        and upos == "NUM"
        and "num" in ordered
        and not any(tag in ordered for tag in ("ord", "coll", "dist"))
    ):
        ordinal = dict(features)
        ordinal["NumType"] = "Ord"
        alternatives.append((upos, tuple(sorted(ordinal.items()))))
        if profile == "ktb":
            combined = dict(features)
            combined["NumType"] = "Card,Ord"
            alternatives.append((upos, tuple(sorted(combined.items()))))

    # Preserve a stable order when a malformed or future reading carries more
    # than one usage tag.  No lexical/surface heuristic participates here.
    if upos == "ADJ" and "subst" in ordered:
        alternatives.append(("NOUN", features))
    if upos == "NOUN" and "attr" in ordered:
        alternatives.append(("ADJ", features))
    if upos == "ADJ" and "advl" in ordered:
        alternatives.append(("ADV", features))

    unique: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    seen = {(upos, features)}
    for alternative in alternatives:
        if alternative not in seen:
            unique.append(alternative)
            seen.add(alternative)
    return tuple(unique)
