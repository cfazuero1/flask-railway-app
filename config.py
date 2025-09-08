import os

def _split_entries(raw: str, sep="|"):
    # Normalize accidental newlines into separators; strip whitespace
    return [e.strip() for e in raw.replace("\n", sep).split(sep) if e.strip()]

def parse_controls(raw):
    items = []
    for entry in _split_entries(raw):
        if ":" in entry:
            key, label = entry.split(":", 1)
            items.append((key.strip(), label.strip()))
        else:
            print(f"[config] WARN controls skip: {entry!r}")
    return items

def parse_policies(raw):
    policies = []
    for entry in _split_entries(raw):
        parts = entry.split(":", 2)
        if len(parts) == 3:
            pid, text, correct = parts
            policies.append({"id": pid.strip(), "text": text.strip(), "correct": correct.strip()})
        else:
            print(f"[config] WARN policy skip: {entry!r}")
    return policies

def parse_insiders_true(raw):
    parts = _split_entries(raw)  # already splits on | and strips
    items = {}
    if len(parts) % 5 != 0:
        print(f"[config] WARN insiders_true length {len(parts)} not multiple of 5")
    for i in range(0, len(parts), 5):
        chunk = parts[i:i+5]
        if len(chunk) < 5: 
            print(f"[config] WARN insiders_true skip tail: {chunk!r}")
            break
        pid, name, role, tactic, blocked = [c.strip() for c in chunk]
        items[pid] = {"name": name, "role": role, "tactic": tactic, "blocked_by": blocked}
    return items

def parse_insiders_fp(raw):
    parts = _split_entries(raw)
    items = []
    if len(parts) % 4 != 0:
        print(f"[config] WARN insiders_fp length {len(parts)} not multiple of 4")
    for i in range(0, len(parts), 4):
        chunk = parts[i:i+4]
        if len(chunk) < 4:
            print(f"[config] WARN insiders_fp skip tail: {chunk!r}")
            break
        name, role, signal, exon = [c.strip() for c in chunk]
        items.append({"name": name, "role": role, "signal": signal, "exoneration": exon})
    return items

def parse_wrong_story(raw):
    d = {}
    for entry in _split_entries(raw):
        if ":" not in entry or "," not in entry.split(":",1)[0]:
            print(f"[config] WARN wrong_story skip: {entry!r}")
            continue
        key, story = entry.split(":", 1)
        pid, cid = key.split(",", 1)
        d[(pid.strip(), cid.strip())] = story.strip()
    return d

ROOM4_FLAG   = os.getenv("ROOM4_FLAG", "FLAG{DEV_DEFAULT}")
GRC_CONTROLS = parse_controls(os.getenv("GRC_CONTROLS", ""))
GRC_POLICIES = parse_policies(os.getenv("GRC_POLICIES", ""))
INSIDERS_TRUE= parse_insiders_true(os.getenv("INSIDERS_TRUE", ""))
INSIDERS_FP  = parse_insiders_fp(os.getenv("INSIDERS_FP", ""))
WRONG_STORY  = parse_wrong_story(os.getenv("WRONG_STORY", ""))
GENERIC_WRONG= os.getenv("GENERIC_WRONG", "Re-evaluate the true enforcing control.")
