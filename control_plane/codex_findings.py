from __future__ import annotations

import hashlib
import re
import unicodedata

_FINDING_HEADER = re.compile(
    r"^\s{0,3}(?:#{1,6}\s*)?(?:[-*]\s*)?(?:\*\*)?"
    r"\[(P[0-4])\]\s+(.+?)(?:\*\*)?\s*$",
    re.IGNORECASE,
)
_SECTION_HEADER = re.compile(r"^\s{0,3}#{1,6}\s+\S")
_HORIZONTAL_RULE = re.compile(r"^\s{0,3}(?:---+|\*\*\*+|___+)\s*$")


def normalize_codex_finding_text(*parts: str) -> str:
    value = unicodedata.normalize("NFKC", " ".join(parts)).casefold()
    return " ".join(re.sub(r"[\W_]+", " ", value).split())


def codex_review_body_finding_id(
    *,
    run_id: str,
    head_sha: str,
    review_id: int,
    priority: str,
    title: str,
    body: str,
) -> str:
    normalized = normalize_codex_finding_text(priority, title, body)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return (
        f"codex-body:run-{run_id}:head-{head_sha.lower()}:"
        f"review-{review_id}:{digest}"
    )


def parse_codex_review_body(body: str) -> tuple[dict[str, str], ...]:
    lines = (body or "").splitlines()
    findings: list[dict[str, str]] = []
    for index, line in enumerate(lines):
        match = _FINDING_HEADER.match(line)
        if match is None:
            continue
        title = match.group(2).strip().strip("*").strip()
        if not title:
            continue
        end = index + 1
        while end < len(lines):
            if _SECTION_HEADER.match(lines[end]) or _FINDING_HEADER.match(lines[end]):
                break
            if _HORIZONTAL_RULE.match(lines[end]):
                break
            end += 1
        raw_block = "\n".join(lines[index:end]).strip()
        description = "\n".join(lines[index + 1 : end]).strip()
        findings.append(
            {
                "priority": match.group(1).upper(),
                "title": title,
                "body": description[:4000],
                "evidence_sha256": hashlib.sha256(
                    raw_block.encode("utf-8")
                ).hexdigest(),
            }
        )
    return tuple(findings)