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
- Some shows insert different ads for different listeners, so your copy of an episode can have different ads, at different lengths, than the copy that was scanned. The scanner saves a loudness fingerprint of its copy (one value per 0.1 s). The app decodes a few seconds of your copy at a time and finds where they fit in that fingerprint, which tells it exactly how your copy lines up with the transcript and ad times, and where your copy has ads the scanner never heard (those get skipped too). This works for MP3s with a constant bitrate, which is what shows with inserted ads use. A downloaded episode is matched in the background as soon as it finishes downloading, on the phone with no data use, so it plays in sync from the first second; a streamed one is matched when you open it and reads about a tenth of the file. If matching isn't possible, you can line things up by hand with **Fix sync** in the Transcript tab.
- **The first 75 seconds get extra care.** When you start an episode near the top, the sound stays off for the moment it takes to check the opening: the scan's ad times are loaded and your copy's first half minute is compared with the scanned copy. Then Podskip jumps past any opening ad (including one stitched into only your copy) or goes back to where you started, so you never hear the start of an ad. On the scanner side, Gemini takes a second, dedicated look at each episode's first 3 minutes, with keyword rules as a backup, and any ad in the first 3 seconds is stretched to start at 0:00.
- **Report ad** runs a spot check. The phone first checks the audio around that moment: if the ad is one only your copy has, it finds exactly where the show comes back and skips there; otherwise it uses the transcript to find the ad's end. Then the scanner has Gemini re-read 5 minutes either side, marks every ad it finds there (including ones the full scan missed), and sends you a notification with what it found.
- Transcription is set up for English. For other languages, add a repository variable named `WHISPER_MODEL` with the value `base` (Settings → Secrets and variables → Actions → Variables).
- Skipping works by jumping ahead while the episode plays. If iOS pauses the app in the background, a skip can be missed; opening the app catches up.
