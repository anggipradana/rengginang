# ReNgGinaNg

**ReNgGinaNg is a self-hosted reconnaissance and attack-surface platform for security teams.** It
maps what an organisation has exposed to the internet — domains, subdomains, hosts, services — then
tells you what is worth worrying about: known vulnerabilities, leaked credentials, and threat
intelligence about the actors currently exploiting them.

It is built for red teams that need to start from a complete picture, blue teams that need to know
what their own estate looks like from the outside, and consultancies that deliver this work as a
service. Everything runs on your own infrastructure; no target data leaves it.

ReNgGinaNg v1.0 is an enhanced edition of the open-source [reNgine](https://github.com/yogeshojha/rengine)
2.2.0 reconnaissance framework, extended with threat intelligence, breach monitoring and
professional reporting.

## What it adds to reNgine

- **Threat intelligence** — OTX AlienVault and LeakCheck data alongside your own findings, with a
  single risk score so a stakeholder sees one number rather than five feeds.
- **Breach monitoring** — per-domain credential leak checking, with the results tracked and triaged
  rather than dumped in a spreadsheet.
- **Professional reporting** — bilingual (English / Bahasa Indonesia) vulnerability-assessment PDFs
  with your logo, document numbering, an executive summary and an approval sheet, ready to hand to
  a client.
- **Operational hardening** — WordPress scanning improvements, scan-scope fixes, and a smaller
  container footprint for long-running deployments.

## Getting started

Requirements: a Linux host with Docker and Docker Compose, 4 GB RAM and 2 CPU cores.

```bash
git clone https://github.com/anggipradana/rengginang.git
cd rengginang
./install.sh
```

Full instructions — manual installation, configuration, upgrade, and troubleshooting — are in
[`INSTALL.md`](INSTALL.md). Day-to-day usage, workflow and the API reference are documented under
[`docs/`](docs/).

## A note on responsible use

Reconnaissance reaches out to systems you do not own. Only run it against domains you are
authorised to assess, and keep the scope rules configured — ReNgGinaNg enforces them by default.

## Credits

ReNgGinaNg is built on [reNgine](https://github.com/yogeshojha/rengine) by Yogesh Ojha and its
contributors. Our thanks to them and to the wider open-source security community whose tools this
project orchestrates.

## Licence

GNU General Public License v3.0. See [LICENSE](LICENSE).
