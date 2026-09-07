from typing import Dict, Any

class SanitizationPolicyEngine:
    """
    NIST SP 800-88 Rev. 2 Compliant Sanitization Policy Engine.
    Determines recommended sanitization techniques, risk levels, verification strategy,
    and assurance claims based on media type, interface, and device capabilities.
    """

    @staticmethod
    def evaluate_policy(media_type: str, interface_type: str, capabilities: Dict[str, Any], is_encrypted: bool = False) -> Dict[str, Any]:
        
        # Default policy recommendation
        policy = {
            'recommended_method': 'NIST_CLEAR',
            'method_name': 'NIST SP 800-88 Rev. 2 Clear (Logical Overwrite)',
            'assurance_level': 'CLEAR',
            'risk_level': 'LOW',
            'verification_strategy': 'Full surface verification + sampling zero-check',
            'required_privileges': 'Administrator / Root Privileges',
            'nist_category': 'Clear',
            'is_supported': True,
            'explanation': '',
            'limitations': []
        }

        if media_type == 'HDD':
            policy.update({
                'recommended_method': 'NIST_CLEAR',
                'method_name': 'NIST SP 800-88 Rev. 2 Clear (Pattern Overwrite)',
                'assurance_level': 'CLEAR',
                'risk_level': 'LOW',
                'verification_strategy': 'Random sector block reading to verify overwrite completeness.',
                'explanation': 'For magnetic hard disk drives (HDD), a single complete overwrite pass (writing fixed patterns or zeros across all logical block addresses) effectively clears logical data recovery possibilities under NIST SP 800-88 Rev. 2 guidelines.',
                'limitations': [
                    'Does not purge remanent data in bad/reallocated sectors unless hardware ATA SECURE ERASE command is issued.'
                ]
            })

        elif media_type == 'SATA_SSD':
            if capabilities.get('cryptographic_erase') and is_encrypted:
                policy.update({
                    'recommended_method': 'CRYPTOGRAPHIC_ERASE',
                    'method_name': 'Cryptographic Erase (CE)',
                    'assurance_level': 'PURGE',
                    'risk_level': 'VERY_LOW',
                    'verification_strategy': 'Verify MEK key sanitization & verify block unreadability',
                    'explanation': 'Cryptographic Erase sanitizes media by destroying or sanitizing the Media Encryption Key (MEK), rendering all stored ciphertext unrecoverable instantly across all flash blocks.',
                    'limitations': ['Requires verified self-encrypting drive (SED) hardware encryption.']
                })
            else:
                policy.update({
                    'recommended_method': 'NIST_PURGE',
                    'method_name': 'NIST SP 800-88 Rev. 2 Purge (SATA Sanitize / ATA Secure Erase)',
                    'assurance_level': 'PURGE',
                    'risk_level': 'VERY_LOW',
                    'verification_strategy': 'Query SATA controller execution log and verify random address sectors',
                    'explanation': 'For SATA SSDs, Purge via ATA Secure Erase or SATA Sanitize command issues a internal block-erase voltage pulse to all flash memory blocks (including wear-leveling pools and over-provisioned areas).',
                    'limitations': ['Requires motherboard BIOS/SATA controller support without drive freeze locks.']
                })

        elif media_type == 'NVME_SSD':
            if is_encrypted or capabilities.get('cryptographic_erase'):
                policy.update({
                    'recommended_method': 'CRYPTOGRAPHIC_ERASE',
                    'method_name': 'NVMe Cryptographic Erase / Sanitize',
                    'assurance_level': 'PURGE',
                    'risk_level': 'VERY_LOW',
                    'verification_strategy': 'NVMe Sanitize Status Log verification & sector readout check',
                    'explanation': 'NVMe Cryptographic Erase purges the encryption key in self-encrypting NVMe drives, rendering data instantly unrecoverable across all NAND channels.',
                    'limitations': ['Requires drive hardware key management support.']
                })
            else:
                policy.update({
                    'recommended_method': 'NIST_PURGE',
                    'method_name': 'NVMe Format NVM / User Data Erase (Purge)',
                    'assurance_level': 'PURGE',
                    'risk_level': 'VERY_LOW',
                    'verification_strategy': 'Check NVMe Command Log & perform verification read scan',
                    'explanation': 'NVMe Purge uses low-level controller commands (NVMe Sanitize or Format NVM with User Data Erase = 1) to clear all physical NAND blocks including retired blocks and user data areas.',
                    'limitations': ['Requires NVMe controller admin command privileges.']
                })

        elif media_type in ['USB_FLASH', 'SD_CARD']:
            policy.update({
                'recommended_method': 'NIST_CLEAR',
                'method_name': 'NIST SP 800-88 Rev. 2 Clear (Multi-Pass Overwrite)',
                'assurance_level': 'CLEAR',
                'risk_level': 'MEDIUM',
                'verification_strategy': 'Logical sector readback verification',
                'explanation': 'USB Flash drives and SD cards use internal flash translation layers (FTL) with aggressive wear-leveling. Logical overwriting clears accessible sector space, but cannot guarantee sanitization of unmapped or retired physical NAND blocks.',
                'limitations': [
                    'FTL Wear-leveling may retain hidden physical data fragments in unmapped flash blocks.',
                    'For HIGH-CONFIDENTIALITY data on USB/SD media, NIST SP 800-88 recommends physical destruction (shredding/incineration).'
                ]
            })

        elif media_type == 'TEST_IMAGE':
            policy.update({
                'recommended_method': 'NIST_CLEAR',
                'method_name': 'SENTINEL-X Synthetic Image Sanitization (Demo Mode)',
                'assurance_level': 'CLEAR / PURGE (Simulated)',
                'risk_level': 'NONE (Synthetic Test Image)',
                'verification_strategy': 'Full raw byte verification scan of synthetic test image file.',
                'explanation': 'Safe execution mode operating on synthetic test image (test_drive.img). Overwrites image file bytes with zero/pattern passes without risking real host drives.',
                'limitations': ['Operates on synthetic test media file.']
            })

        return policy
