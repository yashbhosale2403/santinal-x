# SIH26149 SENTINEL-X Demonstration Guide

## Demonstration Overview

SENTINEL-X provides a complete, working prototype designed to demonstrate both **Secure Data Erasure** (NIST SP 800-88 Rev. 2) and **Advanced Forensic Recovery** without endangering the evaluator's computer.

---

## Step-by-Step SIH Demo Script

### Step 1: Initialize Demo Data
Run:
```bash
python manage.py create_demo_environment
```
This builds `demo_data/test_drive.img` containing embedded test files (JPEG, PDF, DOCX, TXT) and initializes Case `CASE-2026-001`.

### Step 2: Launch Dashboard
Run:
```bash
python manage.py runserver 8000
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and login as `admin` / `admin123`.

### Step 3: Demonstrate Forensic Recovery & Carving
1. Navigate to **Forensic Recovery** (`/recovery/`).
2. Select Evidence Image `EVIDENCE-001` (`test_drive.img`).
3. Select extensions: JPEG, PNG, PDF, DOCX, TXT.
4. Click **Start Read-Only Forensic Scan & Carving Pipeline**.
5. Observe carved results:
   - Recovered JPEGs, PDFs, DOCX files with confidence scores (0-100%).
   - Validation status (`VALID`, `PARTIALLY_VALID`).
   - Sector offsets and SHA-256 hashes.
6. Click **Extract** on any carved file to download the recovered artifact.

### Step 4: Demonstrate NIST SP 800-88 Drive Sanitizer
1. Navigate to **Storage Devices** (`/devices/`).
2. Click **Details & Policy** on `test_drive.img` or `DEV_DEMO_NVME_002`.
3. Observe the **NIST SP 800-88 Rev. 2 Policy Engine Card**:
   - HDD -> NIST Clear (Pattern Overwrite)
   - NVMe / SATA SSD -> Purge (Format NVM / ATA Secure Erase) / Cryptographic Erase
   - USB Flash -> Logical Overwrite + Wear Leveling Limitation Warning
4. Click **Initiate NIST Sanitization**.
5. Select `DEMO_MODE`, check the acknowledgment checkbox, and click **Begin Drive Sanitization Workflow**.
6. View the completed result and click **Download PDF Certificate**.

### Step 5: Demonstrate Cryptographic Tamper-Evident Audit Chain
1. Navigate to **Audit Chain Integrity** (`/audit/`).
2. Observe the green banner: `AUDIT CHAIN INTEGRITY: GREEN`.
3. Click **Trigger Tamper Demo**. The system modifies an audit record hash.
4. Click **Run Integrity Verification**.
5. Observe the red banner: `AUDIT CHAIN INTEGRITY: RED — TAMPERING DETECTED!`.
6. Explain to evaluators how hash chaining (`hash = SHA256(data + prev_hash)`) detects unauthorized database modifications immediately.
