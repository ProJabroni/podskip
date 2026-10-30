"""Podskip scanner.

Runs in GitHub Actions. Reads your encrypted subscriptions from the `data`
branch, fetches each show's RSS feed, transcribes new episodes with
faster-whisper, finds the ads (Gemini if a key is set, keyword rules if not),
and writes encrypted results back to the `data` branch for the app to read.
"""

from __future__ import annotations

import gzip
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

import requests

# ---------------------------------------------------------------- settings

DATA = Path(os.environ.get("DATA_DIR", "data")).resolve()
# The app makes one secret, PODSKIP_KEY = "psk1.<data key>.<Gemini key or empty>",
# so you only paste one value into GitHub.
_SECRET = os.environ.get("PODSKIP_KEY", "").strip()
if _SECRET.startswith("psk1."):
    _parts = _SECRET.split(".", 2)
    KEY_TEXT = _parts[1]
    GEMINI_KEY = (_parts[2] if len(_parts) > 2 else "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
else:
    KEY_TEXT = _SECRET
    GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
WHISPER_MODEL = os.environ.get("WHISPER_MODEL", "").strip() or "base.en"
MAX_MINUTES = float(os.environ.get("MAX_MINUTES", "320"))
MAX_EPISODES = int(os.environ.get("MAX_EPISODES", "40"))
PUSH = os.environ.get("PUSH", "1") == "1"
TEST_NOTIFICATION = os.environ.get("TEST_PUSH", "").lower() == "true"
REPO_URL = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ.get('GITHUB_REPOSITORY', '')}"
EPISODES_KEPT_PER_FEED = 40
MAX_TRIES = 2
MAX_DOWNLOAD_BYTES = 900 * 1024 * 1024

FEED_UA = "Podskip/1.0 (personal podcast app; +https://github.com)"
# The phone streams with Apple's media stack, so download with a similar
# user agent. Shows with dynamically inserted ads are then more likely to
# serve the scanner the same ad load the phone will get.
AUDIO_UA = "AppleCoreMedia/1.0.0.22F76 (iPhone; U; CPU OS 18_5 like Mac OS X; en_us)"

GEMINI_MODELS = [
    m.strip()
    for m in os.environ.get(
        "GEMINI_MODELS",
        "gemini-flash-lite-latest,gemini-2.5-flash-lite,gemini-flash-latest,gemini-2.5-flash",
    ).split(",")
    if m.strip()
]

START = time.time()


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------- crypto
# Format: b"PSK1" + 12-byte IV + AES-256-GCM(gzip(json)), AAD b"podskip".
# Key = SHA-256("podskip/v1/" + passphrase). The passphrase is a random
# 32-character string made by the app, so no slow key stretching is needed.

MAGIC = b"PSK1"
AAD = b"podskip"


def _key() -> bytes:
    if not KEY_TEXT:
        raise SystemExit("PODSKIP_KEY secret is missing. Open the app and finish setup.")
    return hashlib.sha256(b"podskip/v1/" + KEY_TEXT.encode()).digest()


def seal(obj) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    raw = gzip.compress(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode(), 6)
    iv = os.urandom(12)
    return MAGIC + iv + AESGCM(_key()).encrypt(iv, raw, AAD)


def unseal(blob: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if blob[:4] != MAGIC:
        raise ValueError("not a podskip file")
    raw = AESGCM(_key()).decrypt(blob[4:16], blob[16:], AAD)
    return json.loads(gzip.decompress(raw))


def read_enc(name, default):
    p = DATA / name
    if not p.exists():
        return default
    try:
        return unseal(p.read_bytes())
    except Exception as e:  # wrong key or damaged file
        log(f"Could not open {name}: {e}")
        if name == "subs.enc":
            raise SystemExit(
                "Can't open your shows: the PODSKIP_KEY secret doesn't match the key in the app. "
                "Copy the PODSKIP_KEY value from the app's Settings into the GitHub secret, then scan again."
            )
        return default


def write_enc(name, obj):
    p = DATA / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(seal(obj))


def write_status(**fields):
    p = DATA / "status.json"
    try:
        cur = json.loads(p.read_text())
    except Exception:
        cur = {}
    cur.update(fields)
    cur["at"] = int(time.time())
    p.write_text(json.dumps(cur, indent=1))


# ---------------------------------------------------------------- git


def git(*args, check=True):
    return subprocess.run(["git", "-C", str(DATA), *args], check=check, capture_output=True, text=True)


def commit(msg):
    if not PUSH:
        return
    git("add", "-A")
    if git("diff", "--cached", "--quiet", check=False).returncode == 0:
        return
    git("commit", "-q", "-m", msg)
    for attempt in range(5):
        r = git("push", "-q", "origin", "HEAD:data", check=False)
        if r.returncode == 0:
            return
        log("push rejected, rebasing:", r.stderr.strip()[:200])
        git("pull", "-q", "--rebase", "origin", "data", check=False)
        time.sleep(2 + attempt * 2)
    log("Giving up on push for now; will retry at the next commit.")


def pull_latest():
    """Pick up subscription changes the app made during this run."""
    if PUSH:
        git("pull", "-q", "--rebase", "origin", "data", check=False)


# ---------------------------------------------------------------- feeds


def short_id(text: str, n: int) -> str:
    return hashlib.sha1(text.encode()).hexdigest()[:n]


def clean_text(s: str | None, limit=600) -> str:
    if not s:
        return ""
    s = re.sub(r"<(br|/p|/div|/li)[^>]*>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n", s).strip()
    return s[:limit].rstrip() + ("…" if len(s) > limit else "")


def parse_duration(v) -> int | None:
    if v is None:
        return None
    v = str(v).strip()
    if not v:
        return None
    try:
        if ":" in v:
            secs = 0
            for part in v.split(":"):
                secs = secs * 60 + float(part)
            return int(secs)
        return int(float(v))
    except ValueError:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _ns(tag: str) -> str:
    return tag[1:].split("}", 1)[0] if isinstance(tag, str) and tag.startswith("{") else ""


def _kids(el, name, ns_hint=None):
    for c in el:
        if _local(c.tag) == name and (ns_hint is None or ns_hint in _ns(c.tag)):
            yield c


def _text(el, *names):
    """First non-empty text among child elements; a name may be 'itunes:x'."""
    for n in names:
        hint = None
        if ":" in n:
            hint, n = n.split(":", 1)
            hint = {"itunes": "itunes.com", "content": "purl.org/rss/1.0/modules/content", "media": "search.yahoo.com/mrss", "atom": "w3.org/2005/Atom"}[hint]
        for c in _kids(el, n, hint):
            if hint is None and _ns(c.tag) not in ("", "http://www.w3.org/2005/Atom"):
                continue
            t = "".join(c.itertext()).strip()
            if t:
                return t
    return ""


def _date(s: str) -> int:
    from email.utils import parsedate_to_datetime
    from datetime import datetime

    if not s:
        return 0
    try:
        return int(parsedate_to_datetime(s).timestamp())
    except Exception:
        pass
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except Exception:
        return 0


AUDIO_EXT = re.compile(r"\.(mp3|m4a|aac|mp4|ogg|opus|wav)(\?|$)", re.I)


def parse_feed(body: bytes, url: str) -> dict:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        raise ValueError(f"Couldn't read this feed ({e})")
    atom = _local(root.tag) == "feed"
    chan = root if atom else next(iter(_kids(root, "channel")), None)
    if chan is None:
        raise ValueError("This link isn't a podcast feed")

    image = ""
    for c in _kids(chan, "image", "itunes.com"):
        image = c.get("href", "")
    if not image:
        for c in _kids(chan, "image"):
            image = _text(c, "url") or image
    if not image:
        image = _text(chan, "logo", "icon")

    episodes = []
    for it in _kids(chan, "entry" if atom else "item"):
        enc = None
        for c in it:
            name = _local(c.tag)
            href = c.get("url") or c.get("href")
            typ = (c.get("type") or "").lower()
            if not href:
                continue
            if name == "enclosure" or (name == "link" and c.get("rel") == "enclosure") or (name == "content" and "mrss" in _ns(c.tag)):
                if typ.startswith(("audio", "video")) or AUDIO_EXT.search(href):
                    enc = href
                    break
        if not enc:
            continue
        guid = _text(it, "guid", "id") or enc
        ep_img = ""
        for c in _kids(it, "image", "itunes.com"):
            ep_img = c.get("href", "")
        desc = _text(it, "itunes:summary", "description", "content:encoded", "summary", "content")
        episodes.append(
            {
                "id": short_id(url + "|" + guid, 16),
                "title": clean_text(_text(it, "title"), 200) or "Untitled episode",
                "date": _date(_text(it, "pubDate", "published", "updated")),
                "url": enc,
                "dur": parse_duration(_text(it, "itunes:duration")),
                "img": ep_img,
                "desc": clean_text(desc, 700),
            }
        )
    if not episodes:
        raise ValueError("No playable episodes in this feed")
    episodes.sort(key=lambda x: x["date"], reverse=True)
    link = _text(chan, "link")
    if atom or not link:
        for c in _kids(chan, "link"):
            if c.get("href") and c.get("rel", "alternate") == "alternate":
                link = c.get("href")
    return {
        "url": url,
        "title": clean_text(_text(chan, "title"), 200) or url,
        "author": clean_text(_text(chan, "itunes:author", "author", "managingEditor"), 120),
        "image": image,
        "link": link,
        "desc": clean_text(_text(chan, "itunes:subtitle", "description", "itunes:summary", "subtitle"), 400),
        "episodes": episodes[:EPISODES_KEPT_PER_FEED],
    }


def fetch_feed(url: str) -> dict:
    if url.startswith("file://"):
        body = Path(url[7:]).read_bytes()
    else:
        r = requests.get(url, headers={"User-Agent": FEED_UA, "Accept": "application/rss+xml, application/xml;q=0.9, */*;q=0.5"}, timeout=40)
        r.raise_for_status()
        body = r.content
    return parse_feed(body, url)


# ---------------------------------------------------------------- audio


def download(url: str, dest: Path) -> int:
    with requests.get(url, headers={"User-Agent": AUDIO_UA, "Accept": "*/*"}, stream=True, timeout=60, allow_redirects=True) as r:
        r.raise_for_status()
        total = 0
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(1 << 16):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise ValueError("Episode file is too large to scan")
                fh.write(chunk)
    return total


_model = None


def load_audio(path: Path):
    """Decode to 16 kHz mono floats with ffmpeg (sturdier than PyAV across versions)."""
    import numpy as np

    cmd = ["ffmpeg", "-nostdin", "-v", "error", "-i", str(path), "-f", "s16le", "-ac", "1", "-ar", "16000", "-"]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0 or not r.stdout:
        raise ValueError("Couldn't decode the audio: " + r.stderr.decode(errors="ignore")[-200:])
    return np.frombuffer(r.stdout, np.int16).astype(np.float32) / 32768.0


def transcribe(path: Path, on_progress=None):
    """Return (duration_seconds, lines) where lines = [[start, end, text], ...]."""
    global _model
    from faster_whisper import WhisperModel

    if _model is None:
        log(f"Loading speech model {WHISPER_MODEL}")
        _model = WhisperModel(WHISPER_MODEL, device="cpu", compute_type="int8", cpu_threads=os.cpu_count() or 4)
    lang = "en" if WHISPER_MODEL.endswith(".en") else None
    audio = load_audio(path)
    segments, info = _model.transcribe(
        audio,
        language=lang,
        beam_size=1,
        vad_filter=True,
        vad_parameters={"min_silence_duration_ms": 500},
        condition_on_previous_text=False,
        word_timestamps=True,
    )
    words = []
    total = float(info.duration) or 1.0
    for seg in segments:
        if on_progress:
            on_progress(min(0.99, seg.end / total))
        if seg.words:
            for w in seg.words:
                words.append((w.start, w.end, w.word))
        else:
            words.append((seg.start, seg.end, seg.text))
    return float(info.duration), words_to_lines(words)


def words_to_lines(words):
    """Group words into short transcript lines (a sentence, a pause, or ~14 s)."""
    lines, cur = [], []
    for i, (s, e, w) in enumerate(words):
        if cur:
            gap = s - cur[-1][1]
            span = e - cur[0][0]
            prev = cur[-1][2].strip()
            sentence_end = prev[-1:] in ".?!" and span > 4
            if gap > 0.9 or span > 14 or sentence_end:
                lines.append(cur)
                cur = []
        cur.append((s, e, w))
    if cur:
        lines.append(cur)
    out = []
    for ln in lines:
        text = "".join(w for _, _, w in ln).strip()
        text = re.sub(r"\s+", " ", text)
        if text:
            out.append([round(ln[0][0], 2), round(ln[-1][1], 2), text])
    return out


# ---------------------------------------------------------------- ad finding

AD_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "ads": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "first_line": {"type": "INTEGER"},
                    "last_line": {"type": "INTEGER"},
                    "kind": {"type": "STRING", "enum": ["sponsor", "promo", "self"]},
                    "advertiser": {"type": "STRING"},
                    "confidence": {"type": "NUMBER"},
                    "quote": {"type": "STRING"},
                },
                "required": ["first_line", "last_line", "kind", "advertiser", "confidence", "quote"],
            },
        },
        "summary": {"type": "STRING"},
        "chapters": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {"line": {"type": "INTEGER"}, "title": {"type": "STRING"}},
                "required": ["line", "title"],
            },
        },
    },
    "required": ["ads", "summary", "chapters"],
}

AD_PROMPT = """You are reading the transcript of a podcast episode called "{title}" from the show "{show}".
Each line starts with a line number and a timestamp.

Find every advertisement and mark exactly which lines it covers:
- "sponsor": paid ads and sponsor reads, including ones the host reads in their own voice, pre-roll, mid-roll and post-roll ad breaks, and short "this episode is brought to you by" mentions.
- "promo": trailers or plugs for other podcasts, shows, or the network's other products.
- "self": the show asking for Patreon/membership support, selling its own merch or tickets, or asking for ratings and reviews.

Rules:
- first_line is the first line of the ad and last_line is its last line. Include the host's lead-in ("we'll be right back", "a word from our sponsor") and the end of the ad, but not the show content around it.
- An ad break with several ads back to back can be one entry or several; either is fine.
- Only mark advertising. A host genuinely discussing a product or company as part of the episode is not an ad.
- confidence is 0 to 1. quote is up to 12 words copied from the ad.
- If there are no ads, return an empty list.

Also write:
- summary: 2 to 4 plain sentences on what the episode covers (ignore the ads).
- chapters: 4 to 12 topic changes in order, each with the line number where it starts and a title of at most 7 words. Skip ad breaks.

Transcript:
{lines}"""


def fmt_time(t: float) -> str:
    t = int(t)
    return f"{t // 3600}:{t % 3600 // 60:02d}:{t % 60:02d}" if t >= 3600 else f"{t // 60}:{t % 60:02d}"


def learned_note(learned):
    """Ads the listener reported in earlier episodes of this show, as a hint for the model."""
    if not learned:
        return ""
    items = "\n".join(f"- {x.get('who') or 'an ad'}: \"{x.get('quote', '')}\"" for x in learned[-12:])
    return f"\n\nThe listener reported these as ads in earlier episodes of this show. Treat similar segments as ads too:\n{items}"


def gemini_analyze(lines, title, show, learned=None):
    numbered = "\n".join(f"{i} [{fmt_time(s)}] {t}" for i, (s, e, t) in enumerate(lines))
    prompt = AD_PROMPT.format(title=title, show=show, lines=numbered).replace("\nTranscript:\n", learned_note(learned) + "\n\nTranscript:\n", 1)
    return gemini_json(prompt, AD_SCHEMA)


def gemini_json(prompt, schema):
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0,
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "maxOutputTokens": 8192,
        },
    }
    last_err = None
    for model in GEMINI_MODELS:
        for attempt in range(3):
            try:
                r = requests.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                    headers={"x-goog-api-key": GEMINI_KEY, "Content-Type": "application/json"},
                    json=body,
                    timeout=300,
                )
            except requests.RequestException as e:
                last_err = str(e)
                time.sleep(5)
                continue
            if r.status_code == 200:
                data = r.json()
                try:
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    return model, json.loads(text)
                except Exception as e:
                    last_err = f"{model}: unreadable answer ({e})"
                    break
            if r.status_code in (400, 401, 403) and "API key" in r.text:
                raise RuntimeError("Gemini rejected the API key. Check GEMINI_API_KEY in the app settings.")
            if r.status_code == 404:
                last_err = f"{model}: not available"
                break
            if r.status_code in (429, 500, 502, 503, 504):
                wait = 20 * (attempt + 1)
                log(f"Gemini {model} busy ({r.status_code}); waiting {wait}s")
                last_err = f"{model}: {r.status_code} {r.text[:200]}"
                time.sleep(wait)
                continue
            last_err = f"{model}: {r.status_code} {r.text[:300]}"
            break
    raise RuntimeError(f"Gemini didn't answer: {last_err}")


def ads_from_gemini(result, lines):
    ads = []
    n = len(lines)
    for a in result.get("ads", []):
        try:
            i, j = int(a["first_line"]), int(a["last_line"])
        except (KeyError, TypeError, ValueError):
            continue
        if i > j:
            i, j = j, i
        if i < 0 or j >= n:
            continue
        conf = float(a.get("confidence") or 0.5)
        s, e = lines[i][0], lines[j][1]
        # Ads longer than 8 minutes are almost always a mistake unless the model is sure.
        if e - s > 480 and conf < 0.9:
            continue
        ads.append(
            {
                "s": s,
                "e": e,
                "type": a.get("kind") if a.get("kind") in ("sponsor", "promo", "self") else "sponsor",
                "who": (a.get("advertiser") or "").strip()[:60],
                "conf": round(max(0.0, min(1.0, conf)), 2),
                "quote": (a.get("quote") or "").strip()[:120],
            }
        )
    return ads


AD_STRONG = re.compile(
    r"(brought to you by|sponsored by|today'?s sponsor|this (message|episode|podcast) (comes|is) (from|supported by)|"
    r"support for (this|the) (show|podcast|episode)|messages? from (our|these) sponsors?|following (announcements|messages)|"
    r"promo code|offer code|use (the )?code|discount code|dot com slash|\.com ?(/|slash)|terms (and conditions )?apply)",
    re.I,
)
AD_WEAK = re.compile(
    r"(\b\w+(\.| dot )com\b|\b\d{1,2} ?(%|percent) off\b|free trial|first (month|box|order) free|(visit|go to|head to) \w+)",
    re.I,
)
AD_BREAK = re.compile(r"(right back|after (this|these|the) (break|messages?|word)|word from our sponsor|quick break|and we'?re back|welcome back)", re.I)


def ads_from_keywords(lines, learned=None):
    """Rough fallback when no Gemini key is set: cluster sponsor phrases.

    A cluster counts as an ad only if it has a strong cue ("brought to you by",
    a promo code, an advertiser you reported before...) or at least two weaker
    ones (a .com address, "% off"...).
    """
    names = [re.escape(x["who"]) for x in (learned or []) if len(x.get("who") or "") >= 4]
    reported = re.compile(r"\b(" + "|".join(names) + r")\b", re.I) if names else None
    seeds = []
    for i, (_, _, t) in enumerate(lines):
        if AD_STRONG.search(t) or (reported and reported.search(t)):
            seeds.append((i, 2))
        elif AD_WEAK.search(t):
            seeds.append((i, 1))
    clusters = []
    for i, w in seeds:
        if clusters and lines[i][0] - lines[clusters[-1][-1][0]][1] < 50:
            clusters[-1].append((i, w))
        else:
            clusters.append([(i, w)])
    ads = []
    for c in clusters:
        score = sum(w for _, w in c)
        if score < 2:
            continue
        a, b = c[0][0], c[-1][0]
        # Walk back to a break cue ("we'll be right back") within 25 s, if there is one.
        k = a
        for j in range(a - 1, -1, -1):
            if lines[a][0] - lines[j][0] > 25:
                break
            if AD_BREAK.search(lines[j][2]):
                k = j
                break
        s, e = lines[k][0], lines[b][1]
        if e - s < 8:
            e = min(lines[-1][1], s + 15)
        ads.append({"s": s, "e": e, "type": "sponsor", "who": "", "conf": 0.6 if score >= 4 else 0.4, "quote": lines[a][2][:120]})
    return ads


def tidy_ads(ads, lines, duration, pad=True):
    ads = sorted(ads, key=lambda a: a["s"])
    out = []
    for a in ads:
        if pad:  # a little room on both sides, applied once when an ad is first found
            a["s"] = max(0.0, a["s"] - 0.25)
            a["e"] = min(duration, a["e"] + 0.35)
        if a["e"] - a["s"] < 4:
            continue
        if out and a["type"] == out[-1]["type"] and a["s"] - out[-1]["e"] < 2.5:
            prev = out[-1]
            prev["e"] = max(prev["e"], a["e"])
            if a["who"] and a["who"] not in prev["who"]:
                prev["who"] = f"{prev['who']}, {a['who']}".strip(", ")[:80]
            prev["conf"] = max(prev["conf"], a["conf"])
            continue
        if out and a["s"] < out[-1]["e"]:
            a["s"] = out[-1]["e"]
            if a["e"] - a["s"] < 4:
                continue
        out.append(a)
    for a in out:
        a["s"], a["e"] = round(a["s"], 2), round(a["e"], 2)
    return out


def chapters_from(result, lines):
    out = []
    for c in result.get("chapters", []):
        try:
            i = int(c["line"])
        except (KeyError, TypeError, ValueError):
            continue
        if 0 <= i < len(lines) and c.get("title"):
            out.append({"t": lines[i][0], "title": c["title"].strip()[:80]})
    out.sort(key=lambda c: c["t"])
    dedup = []
    for c in out:
        if not dedup or c["t"] - dedup[-1]["t"] > 20:
            dedup.append(c)
    if dedup:
        dedup[0]["t"] = 0.0 if dedup[0]["t"] < 60 else dedup[0]["t"]
    return dedup


# ---------------------------------------------------------------- main loop


# ---------------------------------------------------------------- progress

_last_stage = {"name": None, "at": 0.0}


def stage(name, progress):
    """Record what the scanner is doing so the app can show it.

    Pushes right away when the step changes, and at most every 40 s for progress.
    """
    now = time.time()
    changed = name != _last_stage["name"]
    if not changed and now - _last_stage["at"] < 40:
        return
    _last_stage.update(name=name, at=now)
    write_status(stage=name, progress=None if progress is None else round(progress, 2))
    commit("Progress")


# ---------------------------------------------------------------- notifications
# The app makes a VAPID key pair and saves it, with this phone's push
# subscription, in push.enc (encrypted like everything else). The scanner uses
# it to send Web Push notifications straight to the phone.

_push = {"cfg": None, "pem": None}


def load_push():
    cfg = read_enc("push.enc", None)
    _push["cfg"] = cfg if cfg and cfg.get("subs") and cfg.get("vapid") else None
    _push["pem"] = None


def _vapid_pem():
    if _push["pem"]:
        return _push["pem"]
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    jwk = _push["cfg"]["vapid"]
    d = int.from_bytes(base64.urlsafe_b64decode(jwk["d"] + "=" * (-len(jwk["d"]) % 4)), "big")
    key = ec.derive_private_key(d, ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd, path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    _push["pem"] = path
    return path


def notify(title, body, url="./", tag=None):
    cfg = _push["cfg"]
    if not cfg:
        return 0
    try:
        from pywebpush import WebPushException, webpush
    except ImportError:
        log("pywebpush isn't installed; skipping notifications")
        return 0
    payload = json.dumps({"title": title[:120], "body": body[:300], "url": url, "tag": tag or ""})
    sent = 0
    for sub in cfg["subs"]:
        try:
            webpush(
                subscription_info={"endpoint": sub["endpoint"], "keys": sub["keys"]},
                data=payload,
                vapid_private_key=_vapid_pem(),
                vapid_claims={"sub": cfg.get("contact") or "mailto:podskip@users.noreply.github.com"},
                ttl=86400,
                headers={"Urgency": "normal"},
                timeout=20,
            )
            sent += 1
        except WebPushException as e:
            code = getattr(e.response, "status_code", None)
            log(f"Notification not delivered ({code}): {str(e)[:160]}")
        except Exception as e:  # never let a notification problem stop a scan
            log(f"Notification failed: {str(e)[:160]}")
    return sent


def describe_result(feed_title, ep, entry):
    n, sec = entry["n"], entry["sec"]
    if not n:
        return feed_title, f"No ads found in “{ep['title']}”. It's ready to play."
    secs = int(round(sec))
    cut = f"{secs // 60}:{secs % 60:02d}"
    return feed_title, f"Removed {n} ad{'s' if n != 1 else ''} ({cut}) from “{ep['title']}”. Ready to play."


# ---------------------------------------------------------------- reported ads
# The app saves reports in subs.enc as {id, ep, t, end, at}: you heard an ad at
# time t (in the scanned copy's timeline) and the app jumped to `end`. Here we
# find the exact ad around t in the transcript we already have, add it to the
# episode, and remember it so later episodes of the show catch similar ads.

REPORT_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "found": {"type": "BOOLEAN"},
        "first_line": {"type": "INTEGER"},
        "last_line": {"type": "INTEGER"},
        "advertiser": {"type": "STRING"},
        "quote": {"type": "STRING"},
    },
    "required": ["found", "first_line", "last_line", "advertiser", "quote"],
}

REPORT_PROMPT = """A listener of the podcast "{show}" (episode "{title}") says an ad was playing at {when}.
Below is the part of the transcript around that moment. Each line starts with a line number and a timestamp.

Find the ad that was playing at {when}. It may have started before that moment. Mark the whole ad from its first line,
including any lead-in like "we'll be right back" or "a word from our sponsor", to its last line, just before the show
resumes. If several ads run back to back around that moment, cover the whole break. Ads include sponsor reads the host
reads in their own voice, promos for other shows, and the show's own plugs.

advertiser is the brand or show being promoted. quote is up to 12 words copied from the ad.
Set found to false only if there is clearly no advertising near {when}.

Transcript:
{lines}"""


def find_reported_ad(lines, t, title, show):
    lo = max(0, next((i for i, l in enumerate(lines) if l[1] >= t - 240), 0))
    hi = next((i for i, l in enumerate(lines) if l[0] > t + 360), len(lines))
    window = lines[lo:hi]
    if not window or not GEMINI_KEY:
        return None
    numbered = "\n".join(f"{lo + i} [{fmt_time(s)}] {txt}" for i, (s, e, txt) in enumerate(window))
    _, r = gemini_json(REPORT_PROMPT.format(show=show, title=title, when=fmt_time(t), lines=numbered), REPORT_SCHEMA)
    if not r.get("found"):
        return {"none": True}
    i, j = sorted((int(r["first_line"]), int(r["last_line"])))
    if i < lo or j >= hi:
        return None
    s, e = lines[i][0], lines[j][1]
    # The ad has to be where the listener heard it, give or take a little.
    if not (s - 20 <= t <= e + 20) or e - s > 480:
        return None
    return {"s": s, "e": e, "who": (r.get("advertiser") or "").strip()[:60], "quote": (r.get("quote") or "").strip()[:120]}


def apply_reports(subs, index, only=None):
    """Turn new reports into ads. Returns how many episodes changed."""
    done = index.setdefault("reports_done", {})
    pending = [r for r in (subs.get("reports") or []) if r.get("id") and r["id"] not in done and r.get("ep") in index["scanned"]]
    if only:
        pending = [r for r in pending if r["ep"] == only]
    changed = set()
    for r in pending:
        eid = r["ep"]
        path = f"eps/{eid}.enc"
        ep = read_enc(path, None)
        if not ep:
            continue
        fid = ep.get("fid") or next((f for f, feed in index["feeds"].items() if any(x["id"] == eid for x in feed.get("episodes", []))), "")
        show = index["feeds"].get(fid, {}).get("title", "")
        t = float(r["t"])
        found = None
        try:
            found = find_reported_ad(ep["lines"], t, ep.get("title", ""), show)
        except Exception as e:
            log(f"Report {r['id']}: Gemini didn't answer ({str(e)[:120]}); using the app's estimate")
        if found and found.get("none"):
            log(f"Report {r['id']}: no ad found near {fmt_time(t)}; keeping the listener's mark anyway")
            found = None
        if not found:
            end = float(r.get("end") or t + 30)
            found = {"s": max(0.0, t - 1), "e": max(end, t + 5), "who": "", "quote": ""}
        ad = {"s": max(0.0, found["s"] - 0.25), "e": min(ep["dur"], found["e"] + 0.35), "type": "sponsor", "who": found["who"], "conf": 1.0, "quote": found["quote"], "src": "report"}
        ads = tidy_ads(ep["ads"] + [ad], ep["lines"], ep["dur"], pad=False)
        for a in ads:  # tidy_ads merges; keep the "reported" mark on whatever covers the report
            if a["s"] <= t <= a["e"]:
                a["src"] = "report"
        ep["ads"], ep["at"] = ads, int(time.time())
        write_enc(path, ep)
        sc = index["scanned"][eid]
        sc.update(at=ep["at"], n=len(ads), sec=round(sum(a["e"] - a["s"] for a in ads if a["type"] != "self"), 1))
        if found["quote"] or found["who"]:
            learned = index.setdefault("learned", {}).setdefault(fid, [])
            learned.append({"who": found["who"], "quote": found["quote"]})
            del learned[:-20]
        done[r["id"]] = int(time.time())
        changed.add(eid)
        log(f"Report {r['id']}: skipping {fmt_time(found['s'])}–{fmt_time(found['e'])} {found['who']}".rstrip())
    # Forget reports the app no longer lists.
    live = {r.get("id") for r in (subs.get("reports") or [])}
    for rid in list(done):
        if rid not in live and int(time.time()) - done[rid] > 30 * 86400:
            del done[rid]
    return len(changed)


def build_queue(subs, index):
    per_show = max(1, min(10, int(subs.get("perShow") or 3)))
    scanned, failed = index["scanned"], index["failed"]
    by_id = {}
    for fid, feed in index["feeds"].items():
        for ep in feed.get("episodes", []):
            by_id[ep["id"]] = (fid, ep)

    # The app can ask for a fresh scan of an episode: rescan = {episode id: request time}.
    rescan = subs.get("rescan") or {}
    if not isinstance(rescan, dict):
        rescan = {}

    def ok(eid):
        asked = rescan.get(eid, 0)
        sc = scanned.get(eid)
        if sc and sc.get("at", 0) >= asked:
            return False
        f = failed.get(eid)
        if f and f.get("tries", 0) >= MAX_TRIES and f.get("at", 0) >= asked:
            return False
        return True

    wanted_ids = list(dict.fromkeys(list(rescan) + list(subs.get("want", []))))
    queue = [by_id[e] for e in wanted_ids if e in by_id and ok(e)]
    wanted = {ep["id"] for _, ep in queue}
    newest = []
    for f in subs.get("feeds", []):
        fid = short_id(f["url"], 12)
        feed = index["feeds"].get(fid)
        if not feed:
            continue
        for ep in feed["episodes"][:per_show]:
            if ok(ep["id"]) and ep["id"] not in wanted:
                newest.append((fid, ep))
    newest.sort(key=lambda x: x[1]["date"], reverse=True)
    return queue + newest


def refresh_feeds(subs, index):
    keep = set()
    for f in subs.get("feeds", []):
        fid = short_id(f["url"], 12)
        keep.add(fid)
        try:
            feed = fetch_feed(f["url"])
            feed["fetched"] = int(time.time())
            feed["error"] = ""
            index["feeds"][fid] = feed
            log(f"Feed ok: {feed['title']} ({len(feed['episodes'])} episodes)")
        except Exception as e:
            log(f"Feed failed: {f['url']}: {e}")
            old = index["feeds"].get(fid) or {"url": f["url"], "title": f.get("title") or f["url"], "image": f.get("image", ""), "episodes": []}
            old["error"] = str(e)[:200]
            index["feeds"][fid] = old
    for fid in list(index["feeds"]):
        if fid not in keep:
            del index["feeds"][fid]


def scan_episode(fid, ep, feed, index, workdir):
    log(f"Scanning: {feed['title']} — {ep['title']}")
    ext = AUDIO_EXT.search(ep["url"])
    path = workdir / f"{ep['id']}.{ext.group(1).lower() if ext else 'mp3'}"
    t0 = time.time()
    size = download(ep["url"], path)
    log(f"  downloaded {size / 1e6:.1f} MB in {time.time() - t0:.0f}s")
    stage("transcribing", 0.0)
    t0 = time.time()
    duration, lines = transcribe(path, on_progress=lambda f: stage("transcribing", f))
    log(f"  transcribed {fmt_time(duration)} of audio into {len(lines)} lines in {time.time() - t0:.0f}s")
    path.unlink(missing_ok=True)

    stage("finding ads", None)
    summary, chapters, det = None, [], "keywords"
    ads = []
    if GEMINI_KEY and lines:
        try:
            model, result = gemini_analyze(lines, ep["title"], feed["title"], index.get("learned", {}).get(fid))
            ads = ads_from_gemini(result, lines)
            summary = (result.get("summary") or "").strip() or None
            chapters = chapters_from(result, lines)
            det = "gemini:" + model
        except RuntimeError as e:
            log("  Gemini step failed, using keyword rules instead:", e)
            index.setdefault("notes", {})["gemini"] = str(e)[:300]
            ads = ads_from_keywords(lines, index.get("learned", {}).get(fid))
    elif lines:
        ads = ads_from_keywords(lines, index.get("learned", {}).get(fid))
    ads = tidy_ads(ads, lines, duration)
    log(f"  found {len(ads)} ads, {sum(a['e'] - a['s'] for a in ads):.0f}s total ({det})")

    write_enc(
        f"eps/{ep['id']}.enc",
        {
            "v": 1,
            "id": ep["id"],
            "fid": fid,
            "title": ep["title"],
            "url": ep["url"],
            "dur": round(duration, 2),
            "bytes": size,
            "at": int(time.time()),
            "det": det,
            "summary": summary,
            "chapters": chapters,
            "ads": ads,
            "lines": lines,
        },
    )
    index["scanned"][ep["id"]] = {
        "at": int(time.time()),
        "n": len(ads),
        "sec": round(sum(a["e"] - a["s"] for a in ads if a["type"] != "self"), 1),
        "dur": round(duration, 1),
        "det": det.split(":")[0],
    }
    index["failed"].pop(ep["id"], None)


def prune(index):
    """Drop scans for episodes that fell off the feeds or belong to removed shows."""
    live = {ep["id"] for f in index["feeds"].values() for ep in f.get("episodes", [])}
    for key in ("scanned", "failed"):
        for eid in list(index[key]):
            if eid not in live:
                del index[key][eid]
    eps = DATA / "eps"
    if eps.exists():
        for p in eps.glob("*.enc"):
            if p.stem not in live:
                p.unlink()


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    subs = read_enc("subs.enc", None)
    if subs is None:
        log("No subscriptions yet. Add a show in the app.")
        return
    index = read_enc("index.enc", {"v": 1, "feeds": {}, "scanned": {}, "failed": {}})
    index.setdefault("feeds", {}), index.setdefault("scanned", {}), index.setdefault("failed", {})

    # Reported ads first: they only need the transcript, so they're quick.
    if apply_reports(subs, index):
        index["updated"] = int(time.time())
        write_enc("index.enc", index)
        commit("Fix reported ads")
    if "--reports-only" in sys.argv:
        return
    index.pop("notes", None)

    load_push()
    if TEST_NOTIFICATION:
        sent = notify("Podskip", "Notifications are on. You'll get one each time an episode's ads are removed.", "./#settings", "test")
        log(f"Test notification sent to {sent} device(s)")
    write_status(state="running", started=int(time.time()), current=None, stage=None, progress=None, done=0, queue=None, error=None)
    refresh_feeds(subs, index)
    index["updated"] = int(time.time())
    write_enc("index.enc", index)
    queue = build_queue(subs, index)
    write_status(queue=len(queue))
    commit("Refresh feeds")

    done = quiet = 0
    workdir = Path(tempfile.mkdtemp(prefix="podskip-"))
    seen = set()
    while queue and done < MAX_EPISODES:
        if (time.time() - START) / 60 > MAX_MINUTES:
            log("Time budget used up; the next run continues from here.")
            break
        fid, ep = queue.pop(0)
        if ep["id"] in seen:
            continue
        seen.add(ep["id"])
        write_status(current=ep["id"], queue=len(queue) + 1, stage="downloading", progress=None)
        _last_stage.update(name="downloading", at=time.time())
        commit("Scanning")  # lets the app show which episode is in progress
        try:
            scan_episode(fid, ep, index["feeds"][fid], index, workdir)
            apply_reports(subs, index, only=ep["id"])
            done += 1
            if done <= 3:
                title, body = describe_result(index["feeds"][fid]["title"], ep, index["scanned"][ep["id"]])
                notify(title, body, f"./#ep-{ep['id']}", ep["id"])
            else:
                quiet += 1
        except Exception as e:
            traceback.print_exc()
            f = index["failed"].get(ep["id"], {"tries": 0})
            if (subs.get("rescan") or {}).get(ep["id"], 0) > f.get("at", 0):
                f = {"tries": 0}
            index["failed"][ep["id"]] = {"tries": f["tries"] + 1, "err": str(e)[:200], "at": int(time.time())}
            if index["failed"][ep["id"]]["tries"] >= MAX_TRIES:
                notify(index["feeds"][fid]["title"], f"Couldn't scan “{ep['title']}”. You can still play it, with ads.", f"./#ep-{ep['id']}", ep["id"])
            for leftover in workdir.glob("*"):
                leftover.unlink(missing_ok=True)
        index["updated"] = int(time.time())
        write_enc("index.enc", index)
        write_status(done=done, current=None, stage=None, progress=None, queue=len(queue))
        commit(f"Scan {ep['id']}")
        # Pick up shows added or episodes requested while this run was going.
        pull_latest()
        load_push()
        new_subs = read_enc("subs.enc", subs)
        if new_subs != subs:
            subs = new_subs
            apply_reports(subs, index)
            refresh_feeds(subs, index)
            write_enc("index.enc", index)
            queue = [q for q in build_queue(subs, index) if q[1]["id"] not in seen]

    if quiet:
        notify("Podskip", f"Ads removed from {quiet} more episode{'s' if quiet != 1 else ''}. Open Podskip to listen.", "./#listen", "batch")
    prune(index)
    write_enc("index.enc", index)
    write_status(state="idle", current=None, stage=None, progress=None, finished=int(time.time()), done=done, queue=len(queue))
    commit("Scan finished")
    log(f"Done: scanned {done} episode(s).")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if e.code and not isinstance(e.code, int):
            write_status(state="error", error=str(e.code), current=None)
            commit("Scan error")
            print(e.code, file=sys.stderr)
            sys.exit(1)
        raise
