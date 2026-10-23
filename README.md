# NexGuard – Intelligent Phishing & Malicious URL Detection Platform

**Tagline:** Detect. Analyze. Protect.

The complete application is located in the [`nexguard`](./nexguard/) folder.

## Quick Start (PowerShell)

```powershell
Set-Location C:\Users\apoor\Downloads\nexguard\nexguard
npm install
npm test
npm run typecheck
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

The app uses its existing SQLite database at `nexguard\prisma\dev.db`. Do not run `npx prisma db push` as a setup step; see the app README for environment setup and safe database backup/restore instructions.

## SOC Color Codes & Documentation

See [`nexguard/docs/COLOR_CODES.md`](./nexguard/docs/COLOR_CODES.md) and [`nexguard/README.md`](./nexguard/README.md) for full architecture and scoring documentation.
