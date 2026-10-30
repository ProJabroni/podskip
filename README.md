# Podskip

A free podcast player for your iPhone that finds the ads in each episode and skips them while you listen. It also gives you a summary, chapters, and a searchable transcript.

Everything runs on free services:

- **The app** is a web page on GitHub Pages. You add it to your Home Screen.
- **The scanner** is a GitHub Actions job (`.github/workflows/scan.yml`). It transcribes new episodes with [faster-whisper](https://github.com/SYSTRAN/faster-whisper), then asks Google's Gemini (free tier) where the ads are. Without a Gemini key it falls back to simple keyword rules.
- **Your data** (shows, transcripts, ad timings) lives on this repo's `data` branch, encrypted with your `PODSKIP_KEY` secret. The repo is public, so the encryption is what keeps it private.

The phone streams each episode straight from the podcast's own server and jumps over the ad timings the scanner found. Podskip never copies or re-hosts the audio.

## Setup (all on your phone)

1. **Turn on Pages:** repo **Settings → Pages**. Under *Build and deployment*, choose **Deploy from a branch**, branch **main**, folder **/ (root)**, then **Save**. Wait about a minute.
2. **Install the app:** open `https://<your-username>.github.io/podskip/` in Safari, tap **Share → Add to Home Screen**.
3. **Open Podskip from your Home Screen** and follow its three setup steps: a GitHub token, an optional free Gemini key, and one secret to paste into GitHub.

## Good to know

- New episodes are scanned every 3 hours, and whenever you open the app after a while. A one-hour episode takes about 5 minutes to scan.
- Some shows insert different ads for different listeners. If the episode you stream doesn't match the copy that was scanned, Podskip turns automatic skipping off for that episode and tells you, rather than cutting into the show.
- Transcription is set up for English. For other languages, add a repository variable named `WHISPER_MODEL` with the value `base` (Settings → Secrets and variables → Actions → Variables).
- Skipping works by jumping ahead while the episode plays. If iOS pauses the app in the background, a skip can be missed; opening the app catches up.
