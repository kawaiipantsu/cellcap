# cellcap Field Guide

`manual.pdf` — a comprehensive training manual for passive cellular (GSM/GPRS/LTE/3G/5G)
capture and analysis with cellcap, an SDR and Wireshark, for beginners, intermediate and
professionals. 56 pages: foundations, the toolchain, every cellcap mode, packet dissection,
flow chains, Wireshark, security/privacy/law, beyond-GSM, and a glossary + references.

## Rebuild

The PDF is generated from `manual.html` with [WeasyPrint](https://weasyprint.org) (CSS paged
media — page numbers, bookmarks, a real TOC). Screenshots come from `../img/`.

```bash
sudo apt install weasyprint          # once
cd docs/manual
python3 -c "from weasyprint import HTML; HTML('manual.html').write_pdf('manual.pdf')"
```

Edit `manual.html` (plain HTML + inline SVG diagrams) and re-run to regenerate.

— THUGSred · https://thugs.red
