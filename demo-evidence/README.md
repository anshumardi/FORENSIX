# FORENSIX synthetic demo evidence

Every file in this folder is synthetic training data. It is not a real incident,
does not identify a real person, and must not be treated as forensic evidence.

Suggested workflow:

1. Open the seeded `[DEMO] Suspicious workstation activity` case in FORENSIX.
2. Upload `workstation-triage.txt`, `browser-artifacts.json`, and
   `network-observations.log` as evidence.
3. Use **Safe preview** and **Verify integrity** on each uploaded item.
4. Import `timeline.csv` from the Timeline page.
5. Create a finding that references the uploaded evidence.
6. Generate a PDF report from the Reports page.

The text, JSON, CSV, and log files are safe synthetic examples for demonstrating
the case-management workflow. They are not real PCAP, disk-image, or memory-dump
files, so they will not provide meaningful analysis with TShark, The Sleuth Kit,
or Volatility 3.
