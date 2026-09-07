# SENTINEL-X Technical Architecture & Sanitization Methodology

**Document Metadata:**
- **Project Name:** SENTINEL-X (SIH26149)
- **Target Organization / Platform:** NTRO / Digital Forensics & Storage Sanitization
- **Theme:** Blockchain & Cybersecurity
- **Version:** SENTINEL-X v1.0
- **Primary Standard Reference:** NIST SP 800-88 Rev. 2 Guidelines for Media Sanitization

---

## 01. Platform Overview

SENTINEL-X is an integrated cybersecurity and digital forensics engineering platform designed for verifiable storage drive sanitization, targeted file cluster erasure, signature-based read-only evidence carving, tamper-evident audit log verification, and immutable ledger recording.

Unlike traditional software tools that rely on generic UI buttons or simulated progress timers, SENTINEL-X implements a real hardware-aware decision engine, low-level binary sector overwriting (os.fsync), sector zero-sampling verification, read-only bit-stream carving, and cryptographic SHA-256 hash chaining.

---

## 02. Sanitization Decision Engine Architecture

The SENTINEL-X Sanitization Decision Engine evaluates target storage devices dynamically before recommending or executing sanitization workflows.

`
STORAGE DEVICE -> DEVICE DETECTION -> MEDIA & CAPABILITY CHECK -> SANITIZATION POLICY ENGINE -> [HDD / SATA SSD / NVME] -> VERIFICATION -> AUDIT & REPORT -> IMMUTABLE INTEGRITY RECORD
`

### Execution Flow:
1. **Device Discovery:** Queries physical drives via Windows WMI (Win32_DiskDrive) and system mount points (psutil).
2. **Capability Assessment:** Inspects device media type, controller interface (SATA, NVMe, USB), self-encrypting drive (SED) capabilities, and hardware sanitize flags.
3. **Policy Evaluation:** Maps findings against NIST SP 800-88 Rev. 2 guidance (Clear, Purge, Cryptographic Erase, Destroy).
4. **Targeted Execution:** Spawns asynchronous worker threads to execute sector zeroing or hardware commands.
5. **Post-Op Sampling Verification:** Samples raw binary sectors at 0%, 25%, 50%, 75%, and 100% offsets to verify zero non-zero bytes remain (
on_zero_bytes == 0).
6. **Certificate & Ledger Generation:** Computes SHA-256 operation hash, appends entry to immutable ledger, and builds signed PDF certificate.

---

## 03. Magnetic Hard Disk Drive (HDD) Sanitization

### Storage Architecture:
Magnetic Hard Disk Drives store data as magnetic domain alignments on spinning platters divided into tracks and logical block addresses (LBAs).

### Recommended Sanitization Method:
- **NIST Category:** CLEAR (or PURGE via ATA SECURE ERASE).
- **Technique:** Single-pass or multi-pass pattern/zero overwriting across all user-addressable logical sectors.
- **Command Set:** Direct raw binary block overwriting (open(drive_path, 'r+b')) + os.fsync() cache flushing, or ATA SECURE ERASE controller pulse.
- **Verification Strategy:** Sector sampling readback across addressable disk surface.
- **Remanence Limitations:** Logical overwriting does not clear bad or reallocated sectors marked as unreadable by drive firmware unless hardware ATA SECURE ERASE is executed.

---

## 04. SATA Solid State Drive (SATA SSD) Sanitization

### Storage Architecture:
SATA SSDs use NAND flash memory blocks managed by an internal Flash Translation Layer (FTL). The FTL performs aggressive Wear Leveling, Garbage Collection, and Over-provisioning, dynamically mapping Logical Block Addresses (LBAs) to physical NAND locations.

### Critical Engineering Reality:
Ordinary logical sector overwriting **is not automatically equivalent to physical NAND sanitization** on SSDs. Overwriting an LBA logically causes the FTL to re-map the address to a new physical block, potentially leaving historical data intact in retired or unmapped physical NAND blocks.

### Recommended Sanitization Method:
- **NIST Category:** PURGE (or CRYPTOGRAPHIC ERASE for SED drives).
- **Technique:** ATA Sanitize / ATA Secure Erase or Block Erase.
- **Execution Flow:**
`
ATA Sanitize -> Internal Block-Erase Voltage Pulse -> All Flash Blocks Reset (Including Wear-Leveling Pools)
`
- **Verification Strategy:** Query SATA controller execution log and sample random address sectors.

---

## 05. NVMe Solid State Drive (NVMe SSD) Sanitization

### Storage Architecture:
NVMe SSDs communicate directly over the PCIe bus using high-speed multi-queue NVM Express controller specifications.

### Recommended Sanitization Method:
- **NIST Category:** PURGE / CRYPTOGRAPHIC ERASE.
- **Technique:** NVMe Sanitize Command or Format NVM with User Data Erase (UserData = 1).
- **Execution Flow:**
`
NVMe SSD -> Controller Capability Detection -> Supported Method -> Format NVM / Cryptographic Erase -> Sector Verification
`
- **Verification Strategy:** Check NVMe Controller Sanitize Status Log and perform sector readback scan.

---

## 06. USB Flash Storage & SD / microSD Media Considerations

### Storage Architecture:
USB flash drives and SD cards combine a USB/SD controller interface with raw NAND flash blocks. Most generic flash memory cards use lightweight FTL firmware without standardized ATA or NVMe admin command sets.

### Capability & Risk Assessment:
- **Generic Limitation:** Generic USB storage devices do not guarantee a universal hardware sanitization command.
- **SENTINEL-X Approach:** The platform detects available hardware capability flags. For generic USB/SD media, multi-pass logical overwriting clears accessible user space.
- **High-Confidentiality Warning:** For confidential data on removable flash media, NIST SP 800-88 Rev. 2 specifies physical destruction (shredding/incineration) if FTL wear-leveling pools cannot be purged via controller hardware commands.

---

## 07. Cryptographic Erase (CE / SED Key Destruction)

### Storage Architecture:
Self-Encrypting Drives (SEDs) automatically encrypt all written media using a hardware Media Encryption Key (MEK) built into the drive controller.

### Execution Flow:
`
Plaintext -> Hardware Encryption (MEK) -> Ciphertext stored on NAND -> Key Destruction -> Ciphertext Instantly Unrecoverable
`

### Sanitization Action:
Cryptographic Erase purges or overwrites the Media Encryption Key (MEK) in controller NVRAM. Without the key, all stored ciphertext across all physical flash channels becomes mathematically unrecoverable instantaneously.

### Usage Limitation:
Cryptographic Erase is **only valid** when verified SED hardware encryption has been continuously enabled throughout the media lifecycle.

---

## 08. Distinguishing Erasure Techniques from Cryptographic Hashing

A critical distinction in digital forensics and storage sanitization is the difference between data destruction and data fingerprinting:

| Category | Algorithm / Technique | Primary Purpose | Does it Erase Disk Bytes? |
| :--- | :--- | :--- | :--- |
| **Sanitization** | Zero-Fill, ATA Sanitize, NVMe Format, CE | Overwrites or purges raw physical storage blocks | **YES** (Overwrites / Purges) |
| **Cryptographic Hashing** | SHA-256 | Computes a unique 256-bit digital fingerprint of data | **NO** (Read-only hash calculation) |
| **Immutable Ledger** | Cryptographic Hash Chain | Records SHA-256 digests in append-only storage | **NO** (Tamper-evident verification) |

> **Key Takeaway:** SHA-256 and AES are **not** sanitization erasure algorithms. SHA-256 provides integrity verification, while sanitization requires device-specific block purging or overwriting.

---

## 09. Tamper-Evident SHA-256 Audit Chain & Verification Engine

SENTINEL-X logs every platform operation into a cryptographic hash chain:

Hash 1 = SHA256(Event 1)
Hash 2 = SHA256(Event 2 + Hash 1)
Hash 3 = SHA256(Event 3 + Hash 2)

### Tamper Detection Mechanism:
If an unauthorized actor modifies Event 2 in the database, its recalculated hash Hash 2' will change, causing a cascade mismatch in all subsequent event hashes (Hash 3 != Hash 3'). The verification engine detects this break instantly and flags RED: Tamper Detected.

---

## 10. Immutable Cryptographic Ledger & Blockchain Adapters

SENTINEL-X implements an append-only immutable ledger.

### Data Privacy Guarantee:
SENTINEL-X **never stores sensitive evidence files or recovered user data on the ledger or blockchain**. Only non-sensitive cryptographic integrity metadata is recorded:
- Operation UUID
- Cryptographic Event SHA-256 Hash
- Report Certificate SHA-256 Hash
- UTC Timestamp
- Transaction Reference ID

`
PDF Report Certificate -> SHA-256 Hash -> Immutable Ledger -> Later Verification (MATCH / MISMATCH)
`

---

## 11. Advanced Digital Forensics Read-Only File Carving Pipeline

The SENTINEL-X recovery engine uses signature-based structure carving to reconstruct deleted artifacts from raw binary disk images.

### Pipeline Stages:
`
FORENSIC IMAGE -> SHA-256 HASH -> READ-ONLY SCANNING -> SIGNATURE DETECTION -> STRUCTURE VALIDATION -> FRAGMENT ANALYSIS -> FILE RECONSTRUCTION -> FILE VALIDATION -> CLASSIFICATION -> CONFIDENCE SCORE -> RECOVERED ARTIFACT -> FORENSIC REPORT
`

### Supported File Formats:
- **JPEG:** Header FF D8 FF E0/E1 | Trailer FF D9 | Decodability check via PIL
- **PNG:** Header 89 50 4E 47 0D 0A 1A 0A | Chunk CRC32 validation
- **PDF:** Header %PDF-1. | Trailer %%EOF | Structure xref table check
- **DOCX / ZIP:** Header 50 4B 03 04 | Central directory parsing
- **MP3 / MP4 / WAV:** Audio/Video container atom parsing
- **TXT:** UTF-8 / ASCII entropy analysis

### Confidence Scoring Model:
Carved artifacts are assigned an analytical confidence score (0-100%) based on signature completeness and structural decode validation.
> *Note: Confidence scoring is an analytical estimate of structural integrity and is not legal proof of original file authenticity.*

---

## 12. NIST SP 800-88 Rev. 2 Policy Reference Framework

SENTINEL-X categorizes sanitization options into four NIST reference tiers:

1. **CLEAR:** Overwrites logical user-addressable storage locations.
2. **PURGE:** Executes hardware controller block-erase routines reaching retired/hidden blocks.
3. **CRYPTOGRAPHIC ERASE:** Sanitizes media encryption keys on SED hardware.
4. **DESTROY:** Physical destruction (shredding/incineration) for damaged media.

---

## 13. Complete SENTINEL-X System Architecture

`
                  SENTINEL-X PLATFORM
                           |
                    Django Web UI
                           |
                      REST API
                           |
             Operation Orchestrator
                           |
        +------------------+------------------+
        |                  |                  |
   Sanitization       File Eraser          Recovery
      Worker             Worker             Worker
        +------------------+------------------+
                           |
                  Verification Engine
                           |
                  Evidence Manager
                           |
                   SHA-256 Engine
                           |
                    Audit Chain
                           |
                   Immutable Ledger
                           |
                     PDF Reports
`

---
*Reference: NIST SP 800-88 Rev. 2 Guidelines for Media Sanitization. This document describes platform technical implementation and does not imply official government agency endorsement.*
