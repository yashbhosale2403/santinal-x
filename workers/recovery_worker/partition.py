import struct
from typing import List, Dict, Any
from workers.recovery_worker.image_reader import StreamingImageReader

class PartitionDetector:
    """
    Read-only MBR & GPT Partition Detector.
    Scans Master Boot Record (MBR) and GUID Partition Table (GPT) in read-only mode to locate
    partition boundaries, partition types, and filesystem candidates without modifying source media.
    """

    PARTITION_TYPES = {
        0x07: "NTFS / exFAT",
        0x0B: "FAT32 (CHS)",
        0x0C: "FAT32 (LBA)",
        0x0E: "FAT16 (LBA)",
        0x83: "Linux (ext2/3/4)",
        0xEE: "GPT Protective MBR",
        0xEF: "EFI System Partition"
    }

    @classmethod
    def detect_partitions(cls, image_path: str) -> List[Dict[str, Any]]:
        """
        Detects MBR and GPT partitions from evidence image.
        Returns list of detected partition dictionaries.
        """
        partitions = []
        sector_0 = StreamingImageReader.read_exact_bytes(image_path, 0, 512)
        if len(sector_0) < 512:
            return partitions

        # Check MBR boot signature 0x55AA
        if sector_0[510:512] == b'\x55\xAA':
            # Check 4 partition entries at offset 446 (0x1BE)
            is_gpt = False
            for i in range(4):
                entry_offset = 446 + (i * 16)
                part_entry = sector_0[entry_offset : entry_offset + 16]
                if len(part_entry) < 16:
                    continue
                boot_flag, start_chs, p_type, end_chs, start_lba, size_sectors = struct.unpack('<B3sB3sII', part_entry)
                
                if p_type == 0xEE:
                    is_gpt = True
                    break
                
                if p_type != 0x00 and size_sectors > 0:
                    partitions.append({
                        'index': i + 1,
                        'scheme': 'MBR',
                        'type_code': hex(p_type),
                        'type_name': cls.PARTITION_TYPES.get(p_type, 'Unknown / Custom Partition'),
                        'start_lba': start_lba,
                        'start_byte': start_lba * 512,
                        'size_sectors': size_sectors,
                        'size_bytes': size_sectors * 512,
                        'status': 'Active' if boot_flag == 0x80 else 'Existing'
                    })

            # If GPT protective MBR is detected, parse GPT Header at sector 1
            if is_gpt:
                gpt_parts = cls._parse_gpt(image_path)
                if gpt_parts:
                    return gpt_parts

        if not partitions:
            # Fallback for raw volume / unpartitioned image
            file_size = StreamingImageReader.read_exact_bytes(image_path, 0, 0) # returns b''
            import os
            total_size = os.path.getsize(image_path) if os.path.exists(image_path) else 0
            partitions.append({
                'index': 1,
                'scheme': 'Raw Image / Unpartitioned Volume',
                'type_code': '0x00',
                'type_name': 'Direct Volume Image',
                'start_lba': 0,
                'start_byte': 0,
                'size_sectors': total_size // 512,
                'size_bytes': total_size,
                'status': 'Existing'
            })

        return partitions

    @classmethod
    def _parse_gpt(cls, image_path: str) -> List[Dict[str, Any]]:
        sector_1 = StreamingImageReader.read_exact_bytes(image_path, 512, 512)
        if len(sector_1) < 512 or not sector_1.startswith(b'EFI PART'):
            return []

        # Parse GPT Header (sector 1)
        part_entry_lba, num_entries, entry_size = struct.unpack('<QII', sector_1[72:88])
        partitions = []
        
        entries_offset = part_entry_lba * 512
        entries_data = StreamingImageReader.read_exact_bytes(image_path, entries_offset, num_entries * entry_size)

        for i in range(min(num_entries, 32)):
            offset = i * entry_size
            entry_bytes = entries_data[offset : offset + entry_size]
            if len(entry_bytes) < 128:
                break
            
            type_guid = entry_bytes[0:16]
            if type_guid == b'\x00' * 16:
                continue

            first_lba, last_lba, flags = struct.unpack('<QQQ', entry_bytes[32:56])
            name_bytes = entry_bytes[56:128]
            name = name_bytes.decode('utf-16le', errors='ignore').rstrip('\x00')

            size_sectors = (last_lba - first_lba) + 1
            if size_sectors > 0:
                partitions.append({
                    'index': i + 1,
                    'scheme': 'GPT',
                    'name': name if name else f"GPT Partition {i+1}",
                    'type_code': 'GPT',
                    'type_name': 'GUID Partition Entry',
                    'start_lba': first_lba,
                    'start_byte': first_lba * 512,
                    'size_sectors': size_sectors,
                    'size_bytes': size_sectors * 512,
                    'status': 'Existing'
                })

        return partitions
