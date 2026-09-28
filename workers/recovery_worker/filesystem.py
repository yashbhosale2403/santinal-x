from typing import Dict, Any
from workers.recovery_worker.image_reader import StreamingImageReader

class FilesystemDetector:
    """
    Read-only Filesystem Identification Engine.
    Inspects volume boot records, superblocks, and metadata structures across partition offsets
    to determine primary filesystem type (NTFS, FAT32, exFAT, ext2/3/4) and detection confidence.
    """

    @classmethod
    def detect_filesystem(cls, image_path: str, offset: int = 0) -> Dict[str, Any]:
        """
        Inspects boot sector / superblock at offset.
        Returns dict with filesystem type, confidence, cluster size, and metadata parameters.
        """
        boot_sector = StreamingImageReader.read_exact_bytes(image_path, offset, 4096)
        if len(boot_sector) < 512:
            return {
                'filesystem': 'Unknown / Corrupted',
                'confidence': 'Low',
                'cluster_size': 4096,
                'details': 'Image offset too short to read boot sector.'
            }

        # 1. Check NTFS (OemName at offset 3: "NTFS    ")
        if boot_sector[3:11] == b'NTFS    ':
            bytes_per_sec = int.from_bytes(boot_sector[11:13], 'little') or 512
            sec_per_cluster = boot_sector[13] or 8
            cluster_size = bytes_per_sec * sec_per_cluster
            mft_cluster = int.from_bytes(boot_sector[48:56], 'little')
            return {
                'filesystem': 'NTFS',
                'confidence': 'High',
                'cluster_size': cluster_size,
                'sector_size': bytes_per_sec,
                'mft_offset': offset + (mft_cluster * cluster_size),
                'details': f"NTFS Volume identified. Cluster size: {cluster_size} bytes. MFT Cluster: {mft_cluster}."
            }

        # 2. Check FAT32 / exFAT
        if boot_sector[3:11] == b'EXFAT   ':
            sec_per_cluster_shift = boot_sector[109]
            bytes_per_sec_shift = boot_sector[108]
            cluster_size = (1 << sec_per_cluster_shift) * (1 << bytes_per_sec_shift) if sec_per_cluster_shift < 32 else 4096
            return {
                'filesystem': 'exFAT',
                'confidence': 'High',
                'cluster_size': cluster_size,
                'sector_size': 512,
                'details': f"exFAT Volume identified. Cluster size: {cluster_size} bytes."
            }

        if b'FAT32   ' in boot_sector[0x52:0x5A] or b'MSDOS5.0' in boot_sector[3:11]:
            bytes_per_sec = int.from_bytes(boot_sector[11:13], 'little') or 512
            sec_per_cluster = boot_sector[13] or 8
            cluster_size = bytes_per_sec * sec_per_cluster
            return {
                'filesystem': 'FAT32',
                'confidence': 'High',
                'cluster_size': cluster_size,
                'sector_size': bytes_per_sec,
                'details': f"FAT32 Volume identified. Cluster size: {cluster_size} bytes."
            }

        # 3. Check ext2/ext3/ext4 (Superblock magic 0xEF53 at offset 1024 + 0x38 = 1080)
        superblock = StreamingImageReader.read_exact_bytes(image_path, offset + 1024, 1024)
        if len(superblock) >= 60 and superblock[0x38:0x3A] == b'\x53\xEF':
            s_log_block_size = int.from_bytes(superblock[24:28], 'little')
            block_size = 1024 << s_log_block_size
            return {
                'filesystem': 'ext4',
                'confidence': 'High',
                'cluster_size': block_size,
                'sector_size': 512,
                'details': f"Linux ext2/3/4 Superblock verified. Block size: {block_size} bytes."
            }

        # Scan for NTFS FILE records anywhere in first 2MB to handle raw offset images
        sample_data = StreamingImageReader.read_exact_bytes(image_path, offset, 2 * 1024 * 1024)
        if b'FILE' in sample_data and b'$MFT' in sample_data:
            return {
                'filesystem': 'NTFS',
                'confidence': 'Medium',
                'cluster_size': 4096,
                'sector_size': 512,
                'details': 'NTFS MFT record signatures located in volume image.'
            }

        return {
            'filesystem': 'Unknown / Corrupted',
            'confidence': 'Low',
            'cluster_size': 4096,
            'sector_size': 512,
            'details': 'Filesystem boot signatures not detected. Raw signature carving recommended.'
        }
