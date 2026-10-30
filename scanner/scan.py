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
    event = fields.pop("event", None)
    run = fields.pop("run", None)
    cur.update(fields)
    cur["at"] = int(time.time())
    if event:
        event["at"] = cur["at"]
        cur["log"] = (cur.get("log") or [])[-59:] + [event]
    if run:
        cur["runs"] = (cur.get("runs") or [])[-9:] + [run]
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


def download(url: str, dest: Path, on_progress=None) -> int:
    with requests.get(url, headers={"User-Agent": AUDIO_UA, "Accept": "*/*"}, stream=True, timeout=60, allow_redirects=True) as r:
        r.raise_for_status()
        size = int(r.headers.get("Content-Length") or 0)
        total = 0
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(1 << 16):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise ValueError("Episode file is too large to scan")
                fh.write(chunk)
                if on_progress:
                    on_progress(total, size)
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


ENV_HZ = 10


def loudness_print(audio) -> str:
    """A fingerprint of the copy we heard: loudness every 0.1 s, in 1/3 dB steps.

    Shows that stitch ads in per listener can hand the phone a copy with
    different ads than this one. The app decodes a few seconds of whatever it's
    playing and finds where they fit in this fingerprint, so the transcript and
    ad times line up with the listener's copy exactly.
    """
    import base64

    import numpy as np

    hop = 16000 // ENV_HZ
    n = len(audio) // hop
    if not n:
        return ""
    frames = audio[: n * hop].astype(np.float64).reshape(n, hop)
    db = 10 * np.log10((frames**2).mean(axis=1) + 1e-10)
    q = np.clip(np.round((db + 80) * 3), 0, 255).astype(np.uint8)
    return base64.b64encode(q.tobytes()).decode()


def transcribe(path: Path, on_progress=None):
    """Return (duration_seconds, lines, word_timing, loudness_print): lines = [[start, end, text], ...]."""
    global _model
    from faster_whisper import WhisperModel

    if _model is None:
        log(f"Loading speech model {WHISPER_MODEL}")
        _model = WhisperModel(WHISPER_MODEL, device="cpu", compute_type="int8", cpu_threads=os.cpu_count() or 4)
    lang = "en" if WHISPER_MODEL.endswith(".en") else None
    audio = load_audio(path)
    env = loudness_print(audio)
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
    lines, timing = words_to_lines(words)
    return float(info.duration), lines, timing, env


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
    out, timing = [], []
    for ln in lines:
        # Build the text word by word and remember where each word starts, so the
        # app can light up the word being said: [seconds after line start, character index].
        text, marks = "", []
        for ws, _, w in ln:
            piece = w.strip()
            if not piece:
                continue
            if text and (w[:1].isspace() or not w[:1]):
                text += " "
            marks.append([round(max(0.0, ws - ln[0][0]), 2), len(text)])
            text += piece
        if text:
            out.append([round(ln[0][0], 2), round(ln[-1][1], 2), text])
            timing.append(marks)
    return out, timing


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
- Look especially closely at the opening. Many episodes start with one or more ads before the show itself begins,
  sometimes before any greeting; mark those from the very first line.
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
        if a["s"] < 3:  # an ad in the first seconds starts at 0:00, so not a word of it plays
            a["s"] = 0.0
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

_last_stage = {"name": None, "at": 0.0, "since": 0}


def stage(name, progress, **extra):
    """Record what the scanner is doing so the app can show it.

    Pushes right away when the step changes, and at most every 30 s for progress.
    """
    now = time.time()
    changed = name != _last_stage["name"]
    if not changed and now - _last_stage["at"] < 30:
        return
    if changed:
        _last_stage["since"] = int(now)
    _last_stage.update(name=name, at=now)
    write_status(stage=name, stage_at=_last_stage.get("since", int(now)), progress=None if progress is None else round(progress, 3), **extra)
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


# ---------------------------------------------------------------- spot checks
# Tapping "Report ad" in the app starts a spot check. The app saves it in
# subs.enc as {id, ep, t, end, at, kind}: you heard an ad at time t (in the
# scanned copy's timeline). kind says what the phone found on its own:
#   "content": the audio there is in the scanned copy, so the ad is in the transcript
#   "gap":     your copy had an ad the scanned copy doesn't have (the phone skips
#              that one itself); we still look for others nearby
#   "guess":   the phone couldn't tell
# Here Gemini re-reads 5 minutes either side of t and marks every ad in that
# stretch, including ones the full scan missed. The ad you reported is
# remembered so later episodes of the show catch similar ones.

SPOT_SCHEMA = {
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
    },
    "required": ["ads"],
}

SPOT_PROMPT = """A listener of the podcast "{show}" (episode "{title}") {heard}
Below is the transcript from 5 minutes before to 5 minutes after that moment. Each line starts with a line number and a timestamp.

Spot-check this stretch for advertising and list every ad in it:
- "sponsor": paid ads and sponsor reads, including ones the host reads in their own voice and short "brought to you by" mentions.
- "promo": trailers or plugs for other podcasts, shows, or the network's other products.
- "self": the show asking for Patreon/membership support, selling its own merch or tickets, or asking for ratings and reviews.

For each ad, first_line is its first line and last_line its last line. Include the host's lead-in ("we'll be right back",
"a word from our sponsor") and run to just before the show resumes. Back-to-back ads can be one entry.
Only mark advertising; a host genuinely discussing a product as part of the episode is not an ad.
advertiser is the brand or show promoted. confidence is 0 to 1. quote is up to 12 words copied from the ad.
Return an empty list if there are no ads in this stretch.

Transcript:
{lines}"""


OPENING_PROMPT = """This is the start of the podcast episode "{title}" from the show "{show}". Each line starts with a line number and a timestamp.

Many episodes open with ads before the show itself begins: pre-roll ads, sponsor reads, promos for other shows, or the
show's own plugs, sometimes before any greeting. Check the first 75 seconds especially carefully, then the rest of this stretch.

List every ad here:
- "sponsor": paid ads and sponsor reads, including ones the host reads in their own voice and short "brought to you by" mentions.
- "promo": trailers or plugs for other podcasts, shows, or the network's other products.
- "self": the show asking for Patreon/membership support, selling its own merch or tickets, or asking for ratings and reviews.
For each ad, first_line is its first line and last_line its last line, running to just before the show itself starts or resumes.
Only mark advertising; the show's own intro, theme or episode introduction is not an ad.
advertiser is the brand or show promoted. confidence is 0 to 1. quote is up to 12 words copied from the ad.
Return an empty list if the episode starts straight into the show with no ads.

Transcript:
{lines}"""


def opening_ads(lines, title, show):
    """A second, dedicated look at the first 3 minutes, where pre-roll ads hide.

    Gemini gets the opening on its own with instructions to look hard at the first
    75 seconds. Keyword rules back it up: a strong sponsor phrase in the first two
    minutes that nothing covers becomes an ad too.
    """
    found = []
    window = [(i, l) for i, l in enumerate(lines) if l[0] < 180]
    if window and GEMINI_KEY:
        numbered = "\n".join(f"{i} [{fmt_time(l[0])}] {l[2]}" for i, l in window)
        try:
            _, r = gemini_json(OPENING_PROMPT.format(title=title, show=show, lines=numbered), SPOT_SCHEMA)
            for a in r.get("ads", []):
                try:
                    i, j = sorted((int(a["first_line"]), int(a["last_line"])))
                except (KeyError, TypeError, ValueError):
                    continue
                if i < 0 or j >= len(window):
                    continue
                conf = float(a.get("confidence") or 0.5)
                s_, e_ = lines[i][0], lines[j][1]
                if conf < 0.5 or e_ - s_ > 360:
                    continue
                found.append({"s": s_, "e": e_, "type": a.get("kind") if a.get("kind") in ("sponsor", "promo", "self") else "sponsor",
                              "who": (a.get("advertiser") or "").strip()[:60], "conf": round(min(1.0, conf), 2),
                              "quote": (a.get("quote") or "").strip()[:120], "src": "opening"})
        except Exception as e:
            log(f"  opening check: Gemini didn't answer ({str(e)[:120]})")
    head = [l for l in lines if l[0] < 120]
    for a in ads_from_keywords(head):
        if not _overlaps(a, found):
            a["src"] = "opening"
            found.append(a)
    return found


def add_opening_ads(ads, lines, title, show):
    """ads plus whatever the opening check finds that they don't already cover."""
    extra = [a for a in opening_ads(lines, title, show) if not _overlaps(a, ads)]
    if extra:
        log(f"  opening check added {len(extra)} ad(s): " + ", ".join(f"{fmt_time(a['s'])}–{fmt_time(a['e'])} {a['who']}".rstrip() for a in extra))
    return ads + extra


def spot_check(lines, t, title, show, kind):
    """All ads within 5 minutes of t, as ad dicts. None if Gemini isn't available."""
    lo = next((i for i, l in enumerate(lines) if l[1] >= t - 300), len(lines))
    hi = next((i for i, l in enumerate(lines) if l[0] > t + 300), len(lines))
    window = lines[lo:hi]
    if not window or not GEMINI_KEY:
        return None
    if kind == "gap":
        heard = (f"heard an ad at {fmt_time(t)}, but it isn't in this transcript: their copy of the episode had an extra ad "
                 f"stitched in at that point. Ads often come in breaks, so check around it for other ads.")
    else:
        heard = f"says an ad was playing at {fmt_time(t)}. It may have started a little before that moment."
    numbered = "\n".join(f"{lo + i} [{fmt_time(s)}] {txt}" for i, (s, e, txt) in enumerate(window))
    _, r = gemini_json(SPOT_PROMPT.format(show=show, title=title, heard=heard, lines=numbered), SPOT_SCHEMA)
    found = []
    for a in r.get("ads", []):
        try:
            i, j = sorted((int(a["first_line"]), int(a["last_line"])))
        except (KeyError, TypeError, ValueError):
            continue
        if i < lo or j >= hi:
            continue
        s, e = lines[i][0], lines[j][1]
        conf = float(a.get("confidence") or 0.5)
        covers = s - 20 <= t <= e + 20
        # The ad you reported is trusted; anything else it turns up has to be a confident call.
        if e - s > 480 or (not covers and conf < 0.6):
            continue
        found.append({
            "s": s, "e": e,
            "type": a.get("kind") if a.get("kind") in ("sponsor", "promo", "self") else "sponsor",
            "who": (a.get("advertiser") or "").strip()[:60],
            "conf": round(max(0.0, min(1.0, conf)), 2),
            "quote": (a.get("quote") or "").strip()[:120],
            "covers": covers,
        })
    return found


def _overlaps(a, ads):
    return any(min(a["e"], b["e"]) - max(a["s"], b["s"]) > 0.5 * (a["e"] - a["s"]) for b in ads)


def apply_reports(subs, index, only=None):
    """Run spot checks for new reports. Returns how many it handled."""
    done = index.setdefault("reports_done", {})
    results = index.setdefault("spot", {})
    pending = [r for r in (subs.get("reports") or []) if r.get("id") and r["id"] not in done and r.get("ep") in index["scanned"]]
    if only:
        pending = [r for r in pending if r["ep"] == only]
    handled = 0
    for r in pending:
        eid = r["ep"]
        path = f"eps/{eid}.enc"
        ep = read_enc(path, None)
        if not ep:
            continue
        handled += 1
        fid = ep.get("fid") or next((f for f, feed in index["feeds"].items() if any(x["id"] == eid for x in feed.get("episodes", []))), "")
        show = index["feeds"].get(fid, {}).get("title", "")
        t = float(r["t"])
        kind = r.get("kind") or "content"
        found = None
        try:
            found = spot_check(ep["lines"], t, ep.get("title", ""), show, kind)
        except Exception as e:
            log(f"Spot check {r['id']}: Gemini didn't answer ({str(e)[:120]}); using the app's estimate")
        checked = found is not None
        found = found or []
        if kind != "gap" and not any(a["covers"] for a in found):
            # You heard an ad here; trust that even if the transcript doesn't make it obvious.
            end = float(r.get("end") or t + 30)
            found.append({"s": max(0.0, t - 1), "e": max(end, t + 5), "type": "sponsor", "who": "", "conf": 1.0, "quote": "", "covers": True})
        new = []
        for a in found:
            covers = a.pop("covers")
            a["s"], a["e"] = max(0.0, a["s"] - 0.25), min(ep["dur"], a["e"] + 0.35)
            a["src"] = "report" if covers and kind != "gap" else "spot"
            if not _overlaps(a, ep["ads"]):
                new.append(a)
        ads = tidy_ads(ep["ads"] + [dict(a) for a in new], ep["lines"], ep["dur"], pad=False)
        for a in ads:  # tidy_ads merges; keep the "reported" mark on whatever covers the report
            if kind != "gap" and a["s"] <= t <= a["e"]:
                a["src"] = "report"
        if new:
            ep["ads"], ep["at"] = ads, int(time.time())
            write_enc(path, ep)
            sc = index["scanned"][eid]
            sc.update(at=ep["at"], n=len(ads), sec=round(sum(a["e"] - a["s"] for a in ads if a["type"] != "self"), 1))
        for a in new:
            if a["src"] == "report" and (a["quote"] or a["who"]):
                learned = index.setdefault("learned", {}).setdefault(fid, [])
                learned.append({"who": a["who"], "quote": a["quote"]})
                del learned[:-20]
        now = int(time.time())
        done[r["id"]] = now
        extra = [a for a in new if a["src"] == "spot"]
        res = {"ep": eid, "t": t, "kind": kind, "checked": checked, "n": len(new),
               "sec": round(sum(a["e"] - a["s"] for a in new), 1), "who": [a["who"] for a in new if a["who"]][:4],
               "extra": len(extra), "extraSec": round(sum(a["e"] - a["s"] for a in extra), 1), "at": now}
        results[r["id"]] = res
        for rid in sorted(results, key=lambda k: results[k].get("at", 0))[:-40]:
            del results[rid]
        log(f"Spot check {r['id']} at {fmt_time(t)} ({kind}): {len(new)} new ad(s) " + ", ".join(f"{fmt_time(a['s'])}–{fmt_time(a['e'])} {a['who']}".rstrip() for a in new))
        notify(*describe_spot(index, eid, res), f"./#ep-{eid}", "spot-" + r["id"])
    # Forget reports the app no longer lists.
    live = {r.get("id") for r in (subs.get("reports") or [])}
    for rid in list(done):
        if rid not in live and int(time.time()) - done[rid] > 30 * 86400:
            del done[rid]
    return handled


def describe_spot(index, eid, res):
    title = next((e["title"] for f in index["feeds"].values() for e in f.get("episodes", []) if e["id"] == eid), "this episode")
    when = fmt_time(res["t"])
    n, extra = res["n"], res.get("extra", 0)
    who = f": {', '.join(res['who'])}" if res["who"] else ""
    if extra:
        secs = int(round(res["extraSec"]))
        also = " and pinned down the one you reported" if n > extra else ""
        return "Spot check done", f"Found {extra} more ad{'s' if extra != 1 else ''} near {when} in “{title}” ({secs // 60}:{secs % 60:02d}{who}){also}. They'll be skipped from now on."
    if n:
        secs = int(round(res["sec"]))
        return "Spot check done", f"Pinned down the ad you reported at {when} in “{title}” ({secs // 60}:{secs % 60:02d}{who}). It'll be skipped from now on."
    if res["kind"] == "gap":
        return "Spot check done", f"No other ads near {when} in “{title}”. The one you heard was only in your copy, and your phone already skips it."
    return "Spot check done", f"Nothing new near {when} in “{title}”. Podskip already had that ad marked."


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
    size = download(ep["url"], path, on_progress=lambda got, tot: stage("downloading", got / tot if tot else None, got=got, total=tot))
    took = time.time() - t0
    log(f"  downloaded {size / 1e6:.1f} MB in {took:.0f}s")
    write_status(got=size, total=size, event={"ev": "downloaded", "id": ep["id"], "mb": round(size / 1e6, 1), "took": round(took)})
    t0 = time.time()
    audio_len = ep.get("dur") or 0
    stage("transcribing", 0.0, audio=audio_len)
    result = transcribe(path, on_progress=lambda f: stage("transcribing", f, audio=audio_len, speed=round(f * audio_len / max(1, time.time() - t0), 1) if audio_len else None))
    duration, lines = result[0], result[1]
    word_timing = result[2] if len(result) > 2 else None
    env = result[3] if len(result) > 3 else ""
    took = time.time() - t0
    log(f"  transcribed {fmt_time(duration)} of audio into {len(lines)} lines in {took:.0f}s")
    write_status(audio=round(duration), speed=round(duration / max(1, took), 1), event={"ev": "transcribed", "id": ep["id"], "dur": round(duration), "took": round(took), "lines": len(lines)})
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
    if lines:
        ads = add_opening_ads(ads, lines, ep["title"], feed["title"])
    ads = tidy_ads(ads, lines, duration)
    log(f"  found {len(ads)} ads, {sum(a['e'] - a['s'] for a in ads):.0f}s total ({det})")
    write_status(event={"ev": "ads", "id": ep["id"], "n": len(ads), "sec": round(sum(a["e"] - a["s"] for a in ads)), "det": det.split(":")[0]})

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
            "words": word_timing,
            "env": env,
        },
    )
    index["scanned"][ep["id"]] = {
        "at": int(time.time()),
        "n": len(ads),
        "sec": round(sum(a["e"] - a["s"] for a in ads if a["type"] != "self"), 1),
        "dur": round(duration, 1),
        "det": det.split(":")[0],
        "env": 1 if env else 0,
        "op": 1,
    }
    index["failed"].pop(ep["id"], None)


def recheck_openings(index, limit=40):
    """Give episodes scanned before the opening check got one. Needs only the transcript."""
    names = {e["id"]: (fid, e["title"]) for fid, f in index["feeds"].items() for e in f.get("episodes", [])}
    todo = [eid for eid, sc in index["scanned"].items() if not sc.get("op") and eid in names][:limit]
    n = 0
    for eid in todo:
        if (time.time() - START) / 60 > MAX_MINUTES - 3:
            break
        ep = read_enc(f"eps/{eid}.enc", None)
        sc = index["scanned"][eid]
        if not ep or not ep.get("lines"):
            sc["op"] = 1
            continue
        fid, title = names[eid]
        before = len(ep["ads"])
        ads = tidy_ads(add_opening_ads(ep["ads"], ep["lines"], title, index["feeds"][fid].get("title", "")), ep["lines"], ep["dur"], pad=False)
        if len(ads) != before or any(a["s"] != b["s"] for a, b in zip(ads, ep["ads"])):
            ep["ads"], ep["at"] = ads, int(time.time())
            write_enc(f"eps/{eid}.enc", ep)
            sc.update(at=ep["at"], n=len(ads), sec=round(sum(a["e"] - a["s"] for a in ads if a["type"] != "self"), 1))
            n += 1
        sc["op"] = 1
    if todo:
        log(f"Opening check on {len(todo)} earlier episode(s): {n} changed")
    return len(todo)


def backfill_prints(index, workdir, limit=12):
    """Add loudness fingerprints to episodes scanned before Podskip saved them.

    Only needs a download and a quick decode, no transcription. The fresh
    download has to be the same copy that was transcribed (same length to a
    fraction of a second); shows that stitch in different ads each time won't
    match, and those keep using the older ways of lining up.
    """
    by_id = {e["id"]: e for f in index["feeds"].values() for e in f.get("episodes", [])}
    todo = [(eid, sc) for eid, sc in index["scanned"].items() if not sc.get("env") and sc.get("envTry", 0) < 2 and eid in by_id]
    todo.sort(key=lambda x: by_id[x[0]].get("date", 0), reverse=True)
    n = 0
    for eid, sc in todo[:limit]:
        if (time.time() - START) / 60 > MAX_MINUTES - 5:
            break
        path = DATA / f"eps/{eid}.enc"
        ep = read_enc(f"eps/{eid}.enc", None) if path.exists() else None
        if not ep:
            continue
        f = workdir / f"print-{eid}"
        try:
            download(ep.get("url") or by_id[eid]["url"], f)
            audio = load_audio(f)
            dur = len(audio) / 16000
            if abs(dur - float(ep["dur"])) > 0.25:
                sc["envTry"] = sc.get("envTry", 0) + 1
                log(f"  fingerprint: {eid} came back {dur - float(ep['dur']):+.1f}s different (different ads), skipping")
                continue
            ep["env"] = loudness_print(audio)
            write_enc(f"eps/{eid}.enc", ep)
            sc["env"] = 1
            n += 1
        except Exception as e:
            sc["envTry"] = sc.get("envTry", 0) + 1
            log(f"  fingerprint: {eid} failed: {str(e)[:120]}")
        finally:
            f.unlink(missing_ok=True)
    if n:
        log(f"Added fingerprints to {n} earlier episode(s)")
    return n


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

    # Spot checks first: they only need the transcript, so they're quick.
    load_push()
    fixed = apply_reports(subs, index)
    if fixed:
        index["updated"] = int(time.time())
        write_enc("index.enc", index)
        write_status(event={"ev": "reports", "n": fixed})
        commit("Spot checks")
    if "--reports-only" in sys.argv:
        return
    index.pop("notes", None)

    load_push()
    if TEST_NOTIFICATION:
        sent = notify("Podskip", "Notifications are on. You'll get one each time an episode's ads are removed.", "./#settings", "test")
        log(f"Test notification sent to {sent} device(s)")
    run_started = int(time.time())
    write_status(state="running", started=run_started, current=None, stage=None, progress=None, done=0, queue=None, queue_ids=[], error=None,
                 event={"ev": "start", "why": os.environ.get("GITHUB_EVENT_NAME", "")})
    refresh_feeds(subs, index)
    index["updated"] = int(time.time())
    write_enc("index.enc", index)
    queue = build_queue(subs, index)
    problems = sum(1 for f in index["feeds"].values() if f.get("error"))
    write_status(queue=len(queue), queue_ids=[q[1]["id"] for q in queue][:25],
                 event={"ev": "feeds", "shows": len(index["feeds"]), "queue": len(queue), "problems": problems})
    commit("Refresh feeds")
    failed_count = 0

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
        now_ts = int(time.time())
        write_status(current=ep["id"], queue=len(queue) + 1, queue_ids=[q[1]["id"] for q in queue][:25], stage="downloading", stage_at=now_ts,
                     ep_started=now_ts, progress=None, got=0, total=0, audio=ep.get("dur") or 0, speed=None)
        _last_stage.update(name="downloading", at=time.time(), since=now_ts)
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
            failed_count += 1
            write_status(event={"ev": "failed", "id": ep["id"], "err": str(e)[:160]})
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
        write_status(done=done, current=None, stage=None, progress=None, queue=len(queue), queue_ids=[q[1]["id"] for q in queue][:25])
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
    if not queue:
        try:
            if recheck_openings(index):
                write_enc("index.enc", index)
                commit("Check episode openings for ads")
        except Exception as e:
            log(f"Opening re-check stopped: {e}")
        try:
            if backfill_prints(index, workdir):
                write_enc("index.enc", index)
                commit("Add audio fingerprints")
        except Exception as e:
            log(f"Fingerprint backfill stopped: {e}")
    prune(index)
    write_enc("index.enc", index)
    finished = int(time.time())
    write_status(state="idle", current=None, stage=None, progress=None, finished=finished, done=done, queue=len(queue), queue_ids=[],
                 event={"ev": "finish", "done": done, "failed": failed_count, "left": len(queue)},
                 run={"started": run_started, "finished": finished, "done": done, "failed": failed_count, "left": len(queue)})
    commit("Scan finished")
    log(f"Done: scanned {done} episode(s).")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if e.code and not isinstance(e.code, int):
            write_status(state="error", error=str(e.code), current=None, stage=None, event={"ev": "error", "err": str(e.code)[:200]})
            commit("Scan error")
            print(e.code, file=sys.stderr)
            sys.exit(1)
        raise
