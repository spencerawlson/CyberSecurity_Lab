# site/ — the spencerlab.tech page for CyberSecurity_Lab

A static, self-contained web page that publishes the labs at
**https://spencerlab.tech/labs/**. It is version-controlled here, next to the
labs it documents; deploy is a manual copy to the web VM (see below).

```
site/
└─ labs/
   ├─ index.html   the write-up page (four labs, safety model, how to run)
   └─ styles.css   all styling (external — see the CSP note)
```

## ⚠️ CSP note (why the CSS is a separate file)

The site's nginx config sets `Content-Security-Policy: default-src 'self'`.
With no `style-src 'unsafe-inline'`, that **blocks inline `<style>` blocks,
`style="..."` attributes, inline `<script>`, and any CDN/web-font**. So this page:

- keeps all CSS in `styles.css` (same-origin — allowed by `default-src 'self'`);
- uses **no JavaScript** and **no `style=` attributes**;
- uses **system fonts** and an **inline SVG** logo (no external requests).

If you change the page, keep it that way, or the page renders unstyled under the
live CSP. (It looks fine locally because a `file://` open has no CSP — always
test against the deployed URL.)

## Deploy (copy to the web VM)

The site is served from `/var/www/spencerlab.tech/html` on the UbuntuServ VM.
From a machine that can reach it over ZeroTier/LAN:

```bash
# from the repo root
scp -r site/labs <user>@<ubuntuserv-zt-ip>:/tmp/labs
# then on the VM:
sudo mkdir -p /var/www/spencerlab.tech/html/labs
sudo cp /tmp/labs/index.html /tmp/labs/styles.css /var/www/spencerlab.tech/html/labs/
sudo chown -R www-data:www-data /var/www/spencerlab.tech/html/labs
```

No nginx change is needed — `try_files $uri $uri/` + `index index.html` already
serves `/labs/` from that directory.

### Verify

```bash
curl -sI  https://spencerlab.tech/labs/            # expect HTTP/2 200
curl -s   https://spencerlab.tech/labs/styles.css | head -1   # expect the CSS header
```

Open https://spencerlab.tech/labs/ and confirm it is **styled** (proves the CSP
is happy with the external stylesheet) and that the GitHub links work.

## Link it from the homepage

I don't have the current homepage `index.html`, so here are drop-in snippets.
Both are CSP-safe (plain markup, no inline styles). Style them with your existing
homepage classes, or they degrade gracefully unstyled.

**Nav link** — add to the homepage's `<nav>`:

```html
<a href="/labs/">Labs</a>
```

**Promo card** — drop into the homepage body where projects are listed:

```html
<a href="/labs/" class="card">
  <h3>CyberSecurity_Lab →</h3>
  <p>Safe, self-contained simulations that reproduce the traces of common
     attacks — so defenders can practise detecting them with Sysmon, EDR, and
     Wireshark. Gift-card IR, DDoS, UDP amplification, and web-attack labs.</p>
</a>
```

> Send me your homepage `index.html` and I'll integrate the link using its own
> markup and classes so it matches the rest of the page exactly.
