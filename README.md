# SENTINEL-X (SIH26149)

**Secure Erasure | Advanced Recovery | Verifiable Evidence**

SENTINEL-X is an integrated cybersecurity and digital-forensics platform designed for SIH26149 (**"Design and Development of an Integrated Secure Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data Sanitization"**).

---

## Key Features

1. **NIST SP 800-88 Rev. 2 Drive Sanitizer**
   - Policy Engine evaluating media types (HDD, SATA SSD, NVMe SSD, USB Flash, SD Card) to determine appropriate techniques (Clear, Purge, Cryptographic Erase, Destroy).
   - Double confirmation safety controls (`ERASE <DEVICE_ID>`).
   - Verifiable PDF Sanitization Certificates.

2. **Secure File & Folder Eraser**
   - Single & batch file/directory erasure with zero-fill, 3-pass random, and Gutmann simulation passes.
   - Pre-operation inventory inspection & metadata extraction.
   - Modern filesystem limitation breakdown (journaling, TRIM, SSD wear leveling, volume shadow copies).

3. **Multi-Method Forensic Recovery Engine**
   - **Read-Only Streaming Architecture**: Chunked evidence reader (`StreamingImageReader`) preventing RAM exhaustion on large forensic images while maintaining 100% read-only evidence isolation (`source_hash_before == source_hash_after`).
   - **Beginner-Friendly Recovery Modes**:
     - **Quick Recovery**: Fast metadata-based recovery (NTFS MFT records & directory entries recovering original filenames/paths).
     - **Deep Recovery**: Metadata + unallocated space scanning + raw signature carving + structure validation.
     - **Maximum Recovery**: All available safe recovery vectors including fragment reconstruction and artifact fusion.
   - **Partition & Filesystem Awareness**: Read-only MBR & GPT partition detection and NTFS, FAT32, exFAT, and ext2/3/4 filesystem inspection.
   - **Structure Validation & 0–100 Confidence Scoring**: Format-specific structure parsers (JPEG, PNG, PDF, DOCX, ZIP, MP4, WAV, MP3, GIF, BMP, TXT) with analytical confidence rating.
   - **Artifact Fusion & Deduplication**: Merges duplicate candidates across metadata and carving scans while preserving original filenames.
   - **Cryptographic Evidence Chain**: Automatic PDF report generation, Audit event logging, and direct anchor to the **Immutable Ledger**.

4. **Cryptographic Tamper-Evident Audit Chain**
   - Hash-chained event log: `event_hash = SHA256(event_data + previous_event_hash)`.
   - Visual Audit Integrity verification (`GREEN - Integrity Verified` or `RED - Tampering Detected`).
   - Interactive Tamper Detection Demo.

5. **Immutable Ledger Adapter**
   - Decoupled `LedgerAdapter` interface supporting `LocalImmutableLedger` and simulated `BlockchainLedgerAdapter` (Ethereum / Hyperledger smart contracts).

6. **Professional SOC Dark Dashboard**
   - Responsive dark navy UI built with Django templates + HTMX + Tailwind CSS.

---

## Architecture Overview

```
                SENTINEL-X (Control Plane - Django)
                                 |
        +------------------------+------------------------+
        |                        |                        |
 REST API & Web UI       Case & Evidence DB        Immutable Ledger
   (Dark SOC Theme)       (SHA-256 Hashed)         (Hash Chaining)
        |                        |                        |
        +------------------------+------------------------+
                                 |
                   Privileged Worker Abstraction
                (Device / Sanitization / Carving)
                                 |
        +------------------------+------------------------+
        |                        |                        |
 Sanitization Engine      File Erasure Engine     Carving & Recovery
(NIST SP 800-88 Rev 2)   (Safe & Multi-pass)    (Signature + Fragment)
        |                        |                        |
        +------------------------+------------------------+
                                 |
                        Verification Engine
                                 |
                       PDF / HTML Report Engine
```

> **IMPORTANT:** Django functions strictly as the CONTROL PLANE. Privileged disk operations are executed through worker abstractions supporting **DEMO MODE**, **SAFE TEST MODE**, and **REAL MODE**.

---

## Quick Setup & Demo Instructions

### 1. Requirements & Prerequisites
- Python 3.12+
- Django 6.0+

### 2. One-command Startup
```bash
./run.sh
```

On Windows PowerShell, run the PowerShell launcher from the repository folder:

```powershell
cd .\data-cleaning
.\run.ps1
```

The launcher creates or reuses a local virtual environment, installs dependencies, runs migrations, creates the demo environment, seeds the admin user (`admin` / `admin123`), and launches the dashboard at [http://127.0.0.1:8000](http://127.0.0.1:8000). Optional server arguments are forwarded, for example `./run.sh --port 8080`.

### 3. Run Automated Test Suite
```bash
python manage.py test tests
```

---

## SIH Presentation & Demonstration Workflow

Follow these steps for a complete SIH demonstration:

1. **Log in to SENTINEL-X Dashboard**: Navigate to `/auth/login/` and log in as `admin`.
2. **Inspect Discovered Devices**: Go to **Storage Devices** (`/devices/`). View the Samsung NVMe SSD, Kingston USB, and synthetic test drive image (`test_drive.img`).
3. **NIST Policy Engine Evaluation**: Click on any device to view the NIST SP 800-88 policy recommendation card (Clear vs Purge vs Cryptographic Erase).
4. **Perform Drive Sanitization (Demo Mode)**: Go to **Sanitize Drive** (`/sanitization/`), select `test_drive.img`, review the warning card, check the acknowledgment box, and click **Begin Sanitization Workflow**.
5. **View PDF Certificate**: Download the generated NIST SP 800-88 Sanitization Certificate PDF.
6. **Case & Evidence Registry**: Go to **Cases & Evidence** (`/cases/`). Inspect `CASE-2026-001` and registered evidence `EVIDENCE-001` (`test_drive.img`) with pre-calculated SHA-256 hash.
7. **Execute Read-Only Forensic Carving**: Go to **Forensic Recovery** (`/recovery/`), select `EVIDENCE-001`, check target signature filters (JPEG, PNG, PDF, DOCX, ZIP, TXT), and launch the scanner.
8. **Inspect Carved Artifacts & Confidence Scores**: View the extracted files grid with 0–100% confidence scores, structure validation indicators (`VALID`, `PARTIALLY_VALID`), and sector offsets. Extract any carved file.
9. **Inspect Cryptographic Audit Chain**: Go to **Audit Chain Integrity** (`/audit/`). Observe the green banner `AUDIT CHAIN INTEGRITY: GREEN`.
10. **Demonstrate Tamper Detection**: Click **Trigger Tamper Demo**. The system corrupts a hash link in the database.
11. **Run Integrity Verification**: Click **Run Integrity Verification**. The banner immediately turns **RED — TAMPERING DETECTED!**, demonstrating SENTINEL-X's cryptographic tamper-evident capability.
12. **Immutable Ledger**: View **Immutable Ledger** (`/ledger/`) to show recorded smart contract / local immutable transaction logs.

---

## Security & Safety Safeguards
- No arbitrary shell commands executed (`os.system` / `subprocess shell=True` strictly forbidden).
- Read-only forensic scanner ensures original evidence images are never modified.
- Double confirmation required for real destructive operations (`ERASE <DEVICE_ID>`).
