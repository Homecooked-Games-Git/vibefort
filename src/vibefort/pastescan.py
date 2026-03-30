"""Paste injection scanner — detects malicious content in pasted text."""

import re
from dataclasses import dataclass

MIN_SCAN_LENGTH = 2


@dataclass
class PasteFinding:
    rule: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    position: int = 0


# Zero-width / invisible Unicode characters
_ZERO_WIDTH_CHARS = frozenset([
    "\u200b",  # zero-width space
    "\u200c",  # ZWNJ
    "\u200d",  # ZWJ
    "\u200e",  # LTR mark
    "\u200f",  # RTL mark
    "\u2060",  # word joiner
    "\u2061",  # function application
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
    "\ufeff",  # BOM
    "\u00ad",  # soft hyphen
])

# RTL/LTR override and isolate characters
_BIDI_CHARS = frozenset([
    "\u202a",  # LTR embedding
    "\u202b",  # RTL embedding
    "\u202c",  # pop directional formatting
    "\u202d",  # LTR override
    "\u202e",  # RTL override
    "\u2066",  # LTR isolate
    "\u2067",  # RTL isolate
    "\u2068",  # first strong isolate
    "\u2069",  # pop directional isolate
])

# Homoglyph map: confusable character -> ASCII look-alike
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic uppercase
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0421": "C",  # С
    "\u0415": "E",  # Е
    "\u041d": "H",  # Н
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    # Cyrillic lowercase
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    # Greek uppercase
    "\u0391": "A",  # Α
    "\u0392": "B",  # Β
    "\u0395": "E",  # Ε
    "\u0397": "H",  # Η
    "\u0399": "I",  # Ι
    "\u039a": "K",  # Κ
    "\u039c": "M",  # Μ
    "\u039d": "N",  # Ν
    "\u039f": "O",  # Ο
    "\u03a1": "P",  # Ρ
    "\u03a4": "T",  # Τ
    "\u03a7": "X",  # Χ
    # Greek lowercase
    "\u03b1": "a",  # α
    "\u03bf": "o",  # ο
}

_HOMOGLYPH_CHARS = frozenset(_HOMOGLYPHS.keys())

# Base64 pattern: 40+ chars of base64-valid characters
_BASE64_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")

# Comment line pattern
_COMMENT_LINE_RE = re.compile(r"^\s*(?:#\s|//\s?|/\*|\*\s)", re.MULTILINE)

# Hex escape: 4+ consecutive \xNN
_HEX_ESCAPE_RE = re.compile(r"(\\x[0-9a-fA-F]{2}){4,}")

# Dangerous ANSI sequences (CSI)
_ANSI_DANGEROUS_RE = re.compile(
    r"\x1b\["
    r"(?:"
    r"\d*[ABCD]"          # cursor movement
    r"|\d+(?:;\d+)?H"    # cursor positioning
    r"|\d*[JK]"          # erase
    r"|8m"               # hidden text
    r")"
)

# OSC sequences (terminal hyperlinks, title setting)
_OSC_DANGEROUS_RE = re.compile(
    r"\x1b\]"
    r"(?:"
    r"8;;"                # OSC 8 terminal hyperlinks (can spoof URLs)
    r"|0;"                # title setting (social engineering)
    r")"
)

# Other dangerous escape sequences (DCS, APC, PM, SOS)
_OTHER_ESCAPE_RE = re.compile(r"\x1b[P_X^]")


def _scan_hidden_unicode(text: str, findings: list[PasteFinding]) -> None:
    """Detect zero-width / invisible Unicode characters."""
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH_CHARS:
            findings.append(PasteFinding(
                rule="hidden-unicode",
                description=f"Hidden Unicode character U+{ord(ch):04X} detected",
                severity="high",
                position=i,
            ))
            return  # break after first find


def _scan_bidi(text: str, findings: list[PasteFinding]) -> None:
    """Detect RTL/LTR override and isolate characters."""
    for i, ch in enumerate(text):
        if ch in _BIDI_CHARS:
            findings.append(PasteFinding(
                rule="rtl-override",
                description=f"Bidirectional override character U+{ord(ch):04X} detected — can reverse displayed text",
                severity="high",
                position=i,
            ))
            return


def _scan_homoglyphs(text: str, findings: list[PasteFinding]) -> None:
    """Detect homoglyph attacks (confusable characters mixed with ASCII)."""
    has_ascii = False
    first_homoglyph_pos = -1
    first_homoglyph_char = ""

    for i, ch in enumerate(text):
        if ch.isascii() and ch.isalpha():
            has_ascii = True
        if ch in _HOMOGLYPH_CHARS and first_homoglyph_pos == -1:
            first_homoglyph_pos = i
            first_homoglyph_char = ch

    if has_ascii and first_homoglyph_pos >= 0:
        lookalike = _HOMOGLYPHS[first_homoglyph_char]
        findings.append(PasteFinding(
            rule="homoglyph",
            description=f"Homoglyph detected: U+{ord(first_homoglyph_char):04X} looks like '{lookalike}'",
            severity="high",
            position=first_homoglyph_pos,
        ))


def _scan_obfuscated(text: str, findings: list[PasteFinding]) -> None:
    """Detect obfuscated payloads: base64 in comments, hex escapes."""
    # Base64 in comments
    for match in _COMMENT_LINE_RE.finditer(text):
        line_start = match.start()
        # Find end of line
        line_end = text.find("\n", line_start)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]
        if _BASE64_RE.search(line):
            findings.append(PasteFinding(
                rule="obfuscated-payload",
                description="Base64-encoded payload hidden in comment",
                severity="critical",
                position=line_start,
            ))
            break  # one finding is enough

    # Hex escape sequences
    m = _HEX_ESCAPE_RE.search(text)
    if m:
        findings.append(PasteFinding(
            rule="obfuscated-payload",
            description="Hex escape sequence payload detected",
            severity="high",
            position=m.start(),
        ))


def _scan_ansi(text: str, findings: list[PasteFinding]) -> None:
    """Detect dangerous ANSI and OSC escape sequences."""
    m = _ANSI_DANGEROUS_RE.search(text)
    if m:
        findings.append(PasteFinding(
            rule="ansi-escape-attack",
            description="Dangerous ANSI escape sequence detected — can manipulate terminal display",
            severity="critical",
            position=m.start(),
        ))

    m = _OSC_DANGEROUS_RE.search(text)
    if m:
        findings.append(PasteFinding(
            rule="osc-escape-attack",
            description="OSC escape sequence detected — can spoof URLs or manipulate terminal",
            severity="critical",
            position=m.start(),
        ))

    m = _OTHER_ESCAPE_RE.search(text)
    if m:
        findings.append(PasteFinding(
            rule="ansi-escape-attack",
            description="Dangerous terminal escape sequence (DCS/APC/PM) detected",
            severity="critical",
            position=m.start(),
        ))


def scan_paste(text: str) -> list[PasteFinding]:
    """Scan pasted text for injection attacks.

    Returns a list of PasteFinding instances describing any threats detected.
    Returns an empty list for strings shorter than MIN_SCAN_LENGTH characters.
    """
    if len(text) < MIN_SCAN_LENGTH:
        return []

    findings: list[PasteFinding] = []

    _scan_hidden_unicode(text, findings)
    _scan_bidi(text, findings)
    _scan_homoglyphs(text, findings)
    _scan_obfuscated(text, findings)
    _scan_ansi(text, findings)

    return findings
