# DNS Migration: Netlify → Cloudflare

## Why
- Enables `api.theken.uk` custom domain on the Cloudflare Worker (SSL auto-provisions)
- Faster DNS propagation (Cloudflare edge network)
- DDoS protection, analytics, caching
- Everything in one dashboard (Workers + DNS + R2)

## Current Setup
- Domain registrar: (check your domain registrar for theken.uk)
- Nameservers: Netlify (dns1.p01.nsone.net, etc.)
- DNS records managed via Netlify API

## Steps

### 1. Add domain to Cloudflare
- Log into Cloudflare dashboard → Add a Site → enter `theken.uk`
- Select Free plan
- Cloudflare will scan existing DNS records automatically

### 2. Verify all records imported
Ensure these records exist:
- A/CNAME for `theken.uk` → Netlify (for website)
- A/CNAME for `www` → Netlify
- MX records → Google Workspace (5 records, already set)
- TXT: `resend._domainkey` → DKIM key (starts with `p=MIGf...`)
- MX: `send` → `feedback-smtp.eu-west-1.amazonses.com`
- TXT: `send` → `v=spf1 include:amazonses.com ~all`
- TXT: Google site verification
- Any other existing records

### 3. Change nameservers at registrar
- Go to your domain registrar for theken.uk
- Replace Netlify nameservers with Cloudflare's (shown in Cloudflare dashboard)
- Propagation: 1-48 hours

### 4. Add Worker custom domain
- Cloudflare dashboard → Workers → ken-api → Settings → Domains & Routes
- Add `api.theken.uk`
- SSL auto-provisions within minutes

### 5. Update API URLs
- Worker: update ALLOWED_ORIGINS to prioritise `https://api.theken.uk`
- Portal: update API constant to `https://api.theken.uk`
- Device: update config.json cloudApi to `https://api.theken.uk`

### 6. Keep Netlify for hosting
- Netlify still hosts the website via CNAME, no change needed
- Just the DNS management moves to Cloudflare

## Risk
- Low. DNS migration is seamless if all records are imported correctly.
- Website, email, and API continue working during propagation (Cloudflare proxies).
- Rollback: change nameservers back to Netlify.
