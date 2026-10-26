# Backend setup (step by step)

This is a Flask API meant to be deployed on Vercel, backed by a Postgres database.
Nothing in this code holds real credentials — everything secret lives in environment
variables you set in the Vercel dashboard.

## 1. Push this to GitHub
Create a new repo, put this `backend/` folder's contents in the repo root, push it.

## 2. Create a Postgres database
In your Vercel project: **Storage → Create Database → Postgres** (free tier is fine).
Vercel will automatically add a `DATABASE_URL` (or `POSTGRES_URL`) env var for you.

Then run `schema.sql` against that database once. Easiest way: open the database's
"Query" tab in the Vercel dashboard and paste the contents of `schema.sql` in, or
connect with `psql "<your-connection-string>" -f schema.sql`.

## 3. Deploy to Vercel
Import the GitHub repo in Vercel as a new project. It will detect `vercel.json` and
deploy `api/index.py` as a Python serverless function automatically.

## 4. Set environment variables (Vercel → Project → Settings → Environment Variables)
| Variable | What it's for |
|---|---|
| `JWT_SECRET` | any long random string — signs login sessions |
| `SETUP_SECRET` | any long random string — protects the one-time owner setup endpoint |
| `DISCORD_WEBHOOK_URL` | your webhook URL, for signup notifications (username+email only) |
| `FRONTEND_URL` | the URL of your actual website once it's hosted |
| `FRONTEND_ORIGIN` | same as above, used for CORS |
| `RESEND_API_KEY` | from resend.com (free tier) — sends real verification code emails |
| `RESEND_FROM` | an email address you've verified with Resend |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | from Google Cloud Console (see below) |
| `GOOGLE_REDIRECT_URI` | `https://<your-backend>.vercel.app/api/auth/google/callback` |

Without `RESEND_API_KEY` set, verification codes just get printed to the Vercel
function logs instead of emailed — fine for testing, not for real users.

## 5. Set up Google OAuth (for the "Sign in with Google" button)
1. Go to console.cloud.google.com → create a project.
2. "APIs & Services" → "OAuth consent screen" → fill in basic info.
3. "Credentials" → "Create Credentials" → "OAuth client ID" → type "Web application".
4. Under "Authorized redirect URIs" add exactly your `GOOGLE_REDIRECT_URI` value above.
5. Copy the generated Client ID and Client Secret into Vercel's env vars.

This is real OAuth — your site never sees or stores anyone's Google password.

## 6. Create your own owner account (do this once, after deploying)
Run this from your terminal (replace values with whatever you actually want to log
in with — don't put your real password in any file you share with anyone):

```bash
curl -X POST https://<your-backend>.vercel.app/api/setup/seed-owner \
  -H "X-Setup-Secret: <the SETUP_SECRET you set in Vercel>" \
  -H "Content-Type: application/json" \
  -d '{"username":"yourname","email":"you@example.com","password":"your-real-password"}'
```

That account gets `is_owner = true` forever, which is what makes the owner panel
and the RGB "OWNER" tag show up for it on the frontend.

## 7. Send me the deployed URL
Once it's live (e.g. `https://your-project.vercel.app`), send me that link and I'll
build the actual website (login/signup pages, email code entry, Google button,
owner panel, DMs, profiles with bios + background audio, user directory, and the
Discord icon/link) wired up to call these endpoints.

## What this backend already does
- Password-based signup + login, passwords hashed with bcrypt (never stored or sent in plaintext anywhere)
- Email verification codes (real ones, sent via Resend) required before first login
- Real Google OAuth sign-in (no password collection — ever)
- Signup notifications posted to your Discord webhook (username + email only)
- User directory, profile bios, profile background-audio upload/playback
- Direct messages between users
- Owner-only settings endpoint (for things like the Discord invite link) and a safe one-time way to make your own account the owner — no credentials hardcoded in source
