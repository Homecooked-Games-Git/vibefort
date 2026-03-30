"""Tests for paste injection scanner."""

from vibefort.pastescan import scan_paste, PasteFinding


# --- Empty / short strings ---

def test_empty_string_returns_empty():
    assert scan_paste("") == []


def test_single_char_returns_empty():
    assert scan_paste("x") == []


def test_normal_text_returns_empty():
    assert scan_paste("Hello, this is normal text with no issues.") == []


# --- Zero-width Unicode characters ---

def test_detects_zero_width_space():
    text = "hello\u200bworld"
    findings = scan_paste(text)
    assert any(f.rule == "hidden-unicode" for f in findings)
    f = next(f for f in findings if f.rule == "hidden-unicode")
    assert f.severity == "high"
    assert f.position == 5


def test_detects_zwnj():
    text = "foo\u200cbar"
    findings = scan_paste(text)
    assert any(f.rule == "hidden-unicode" for f in findings)


def test_detects_zwj():
    text = "test\u200dstring"
    findings = scan_paste(text)
    assert any(f.rule == "hidden-unicode" for f in findings)


def test_detects_bom():
    text = "data\ufeffhere"
    findings = scan_paste(text)
    assert any(f.rule == "hidden-unicode" for f in findings)


def test_detects_soft_hyphen():
    text = "soft\u00adhyphen"
    findings = scan_paste(text)
    assert any(f.rule == "hidden-unicode" for f in findings)


def test_detects_word_joiner():
    text = "word\u2060joiner"
    findings = scan_paste(text)
    assert any(f.rule == "hidden-unicode" for f in findings)


def test_detects_invisible_operators():
    text = "op\u2061erator"
    findings = scan_paste(text)
    assert any(f.rule == "hidden-unicode" for f in findings)


def test_hidden_unicode_breaks_after_first():
    # Multiple zero-width chars should produce only one finding
    text = "a\u200bb\u200cc\u200d"
    findings = scan_paste(text)
    hidden = [f for f in findings if f.rule == "hidden-unicode"]
    assert len(hidden) == 1
    assert hidden[0].position == 1  # first occurrence


# --- RTL/LTR override characters ---

def test_detects_rtl_override():
    text = "document\u202eFDP.exe"
    findings = scan_paste(text)
    assert any(f.rule == "rtl-override" for f in findings)
    f = next(f for f in findings if f.rule == "rtl-override")
    assert f.severity == "high"


def test_detects_ltr_embedding():
    text = "text\u202awith ltr"
    findings = scan_paste(text)
    assert any(f.rule == "rtl-override" for f in findings)


def test_detects_isolate_chars():
    text = "test\u2066isolate"
    findings = scan_paste(text)
    assert any(f.rule == "rtl-override" for f in findings)


# --- Homoglyph attacks ---

def test_detects_cyrillic_homoglyph_mixed():
    # Cyrillic 'а' (U+0430) mixed with ASCII
    text = "p\u0430ssword"
    findings = scan_paste(text)
    assert any(f.rule == "homoglyph" for f in findings)
    f = next(f for f in findings if f.rule == "homoglyph")
    assert f.severity == "high"


def test_detects_cyrillic_upper_homoglyph():
    # Cyrillic 'А' (U+0410) mixed with ASCII
    text = "\u0410dmin"
    findings = scan_paste(text)
    assert any(f.rule == "homoglyph" for f in findings)


def test_pure_ascii_no_homoglyph():
    text = "password admin hello world"
    findings = scan_paste(text)
    assert not any(f.rule == "homoglyph" for f in findings)


def test_pure_cyrillic_no_homoglyph():
    # Pure Cyrillic text should not flag (no mixing)
    text = "\u0410\u0411\u0412\u0413\u0414"
    findings = scan_paste(text)
    assert not any(f.rule == "homoglyph" for f in findings)


# --- Obfuscated payloads ---

def test_detects_base64_in_python_comment():
    b64 = "A" * 45  # 45 chars of base64
    text = f"# {b64}"
    findings = scan_paste(text)
    assert any(f.rule == "obfuscated-payload" for f in findings)
    f = next(f for f in findings if f.rule == "obfuscated-payload")
    assert f.severity == "critical"


def test_detects_base64_in_js_comment():
    b64 = "B" * 45
    text = f"// {b64}"
    findings = scan_paste(text)
    assert any(f.rule == "obfuscated-payload" for f in findings)


def test_detects_base64_in_block_comment():
    b64 = "C" * 45
    text = f"* {b64}"
    findings = scan_paste(text)
    assert any(f.rule == "obfuscated-payload" for f in findings)


def test_normal_code_no_obfuscated():
    text = "x = 42\nprint(x)\n"
    findings = scan_paste(text)
    assert not any(f.rule == "obfuscated-payload" for f in findings)


def test_detects_hex_escapes():
    text = r"payload = '\x41\x42\x43\x44'"
    findings = scan_paste(text)
    assert any(f.rule == "obfuscated-payload" for f in findings)
    f = next(f for f in findings if f.rule == "obfuscated-payload")
    assert f.severity == "high"


def test_short_hex_no_detection():
    # Fewer than 4 consecutive hex escapes should not flag
    text = r"char = '\x41\x42'"
    findings = scan_paste(text)
    assert not any(f.rule == "obfuscated-payload" for f in findings)


# --- ANSI escape attacks ---

def test_detects_ansi_cursor_movement():
    text = "normal\x1b[5Ahidden"
    findings = scan_paste(text)
    assert any(f.rule == "ansi-escape-attack" for f in findings)
    f = next(f for f in findings if f.rule == "ansi-escape-attack")
    assert f.severity == "critical"


def test_detects_ansi_cursor_positioning():
    text = "text\x1b[1;1Hoverwrite"
    findings = scan_paste(text)
    assert any(f.rule == "ansi-escape-attack" for f in findings)


def test_detects_ansi_erase():
    text = "safe\x1b[2Jerased"
    findings = scan_paste(text)
    assert any(f.rule == "ansi-escape-attack" for f in findings)


def test_detects_ansi_hidden_text():
    text = "visible\x1b[8mhidden_command\x1b[0m"
    findings = scan_paste(text)
    assert any(f.rule == "ansi-escape-attack" for f in findings)


def test_normal_ansi_colors_ok():
    # Simple color codes should not trigger (no cursor/erase/hide)
    text = "\x1b[31mred text\x1b[0m"
    findings = scan_paste(text)
    assert not any(f.rule == "ansi-escape-attack" for f in findings)


# --- OSC escape attacks ---

def test_osc8_hyperlink_detected():
    from vibefort.pastescan import scan_paste
    text = "Click here: \x1b]8;;https://evil.com\x1b\\safe text\x1b]8;;\x1b\\"
    findings = scan_paste(text)
    assert any(f.rule == "osc-escape-attack" for f in findings)


def test_osc_title_setting_detected():
    from vibefort.pastescan import scan_paste
    text = "\x1b]0;malicious title\x07 normal text here"
    findings = scan_paste(text)
    assert any(f.rule == "osc-escape-attack" for f in findings)
