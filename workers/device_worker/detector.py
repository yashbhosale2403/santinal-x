import os
import sys
import platform
import psutil
from typing import List, Dict, Any

class DeviceDetector:
    """
    Real Hardware and Physical Device Detection Engine.
    Discovers physical hard drives, NVMe/SATA SSDs, USB flash drives, and mounted volumes.
    """

    @staticmethod
    def detect_all_devices() -> List[Dict[str, Any]]:
        devices = []
        seen_serials = set()
        seen_mounts = set()

        drive_letter_to_parent = {}

        # 1. Windows WMI Detection (Primary for Windows Physical & USB Drives)
        if platform.system() == 'Windows':
            try:
                import wmi
                c = wmi.WMI()
                
                # Query physical disk drives
                for idx, disk in enumerate(c.Win32_DiskDrive()):
                    model = (disk.Model or "Physical Storage Drive").strip()
                    caption = (disk.Caption or model).strip()
                    interface = disk.InterfaceType or "SATA"
                    if "NVMe" in model.upper() or "NVME" in model.upper() or "SN7" in model.upper() or "PC SN" in model.upper() or "PCIE" in model.upper():
                        interface = "NVME"
                        media_type = "NVME_SSD"
                    elif interface.upper() == "USB" or "USB" in model.upper() or disk.MediaType == "Removable Media":
                        interface = "USB"
                        media_type = "USB_FLASH"
                    elif "SSD" in model.upper():
                        media_type = "SATA_SSD"
                    else:
                        media_type = "HDD"

                    size = int(disk.Size) if disk.Size else 0
                    serial = (disk.SerialNumber or f"SN-PHYS-{idx+1:04d}").strip()
                    mount_point = disk.DeviceID or f"\\\\.\\PhysicalDrive{idx}"

                    # Try to map drive letters (e.g. C:, P:, V:) attached to this physical disk
                    drive_letters = []
                    try:
                        for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                                if logical_disk.DeviceID:
                                    dl = logical_disk.DeviceID.strip().upper().rstrip('\\')
                                    drive_letters.append(dl)
                                    seen_mounts.add(dl)
                                    drive_letter_to_parent[dl] = {
                                        'interface_type': interface,
                                        'media_type': media_type,
                                        'model': model,
                                        'parent_name': caption,
                                        'physical_device_id': mount_point
                                    }
                    except Exception:
                        pass

                    display_mount = ", ".join(drive_letters) if drive_letters else mount_point

                    device_id = f"DEV_PHYS_{idx+1}_{serial.replace(' ', '_').replace(':', '')}"
                    seen_serials.add(serial)

                    devices.append({
                        'device_id': device_id,
                        'name': f"{caption} [{display_mount}]" if drive_letters else caption,
                        'model': model,
                        'manufacturer': (disk.Manufacturer or "Standard Controller").strip(),
                        'serial_number': serial,
                        'capacity_bytes': size,
                        'interface_type': interface,
                        'media_type': media_type,
                        'filesystem': 'NTFS/exFAT/FAT32',
                        'removable': interface == 'USB' or disk.MediaType == "Removable Media",
                        'readonly': False,
                        'mount_point': mount_point,
                        'detected_capabilities': DeviceDetector._assess_capabilities(media_type, interface),
                        'health_status': (disk.Status or 'HEALTHY').upper(),
                        'is_demo_device': False
                    })
            except Exception as e:
                sys.stderr.write(f"Windows WMI detection error: {e}\n")

        # 2. System Partitions & Mounted Drives via psutil (Fallback & Cross-Platform)
        try:
            partitions = psutil.disk_partitions(all=False)
            for idx, p in enumerate(partitions):
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    total_bytes = usage.total
                except Exception:
                    total_bytes = 0

                mount = p.mountpoint
                opts = p.opts.lower()
                fstype = p.fstype or 'NTFS/FAT32'
                is_removable = 'removable' in opts or 'cdrom' in opts or 'usb' in opts
                serial_fallback = f"SN-PART-{hash(p.device) % 100000:05d}"

                p_clean = p.device.strip().upper().rstrip('\\')
                parent_info = drive_letter_to_parent.get(p_clean) or drive_letter_to_parent.get(mount.strip().upper().rstrip('\\'))

                if parent_info:
                    interface = parent_info['interface_type']
                    media_type = parent_info['media_type']
                    model_desc = f"NVMe Storage Volume ({fstype})" if media_type == 'NVME_SSD' else f"Storage Volume ({fstype})"
                elif 'usb' in mount.lower() or is_removable or 'usb' in p.device.lower():
                    interface = 'USB'
                    media_type = 'USB_FLASH'
                    model_desc = f"Storage Volume ({fstype})"
                elif 'nvme' in p.device.lower():
                    interface = 'NVME'
                    media_type = 'NVME_SSD'
                    model_desc = f"NVMe Storage Volume ({fstype})"
                elif 'ssd' in p.device.lower():
                    interface = 'SATA'
                    media_type = 'SATA_SSD'
                    model_desc = f"SSD Storage Volume ({fstype})"
                else:
                    matched = False
                    for parent_letter, p_info in drive_letter_to_parent.items():
                        if parent_letter in p_clean:
                            interface = p_info['interface_type']
                            media_type = p_info['media_type']
                            model_desc = f"NVMe Storage Volume ({fstype})" if media_type == 'NVME_SSD' else f"Storage Volume ({fstype})"
                            matched = True
                            break
                    if not matched:
                        interface = 'SATA'
                        media_type = 'HDD'
                        model_desc = f"Storage Volume ({fstype})"

                device_id = f"DEV_VOL_{idx+1}_{p.device.replace(':', '').replace('/', '_').replace('\\', '_')}"
                
                devices.append({
                    'device_id': device_id,
                    'name': f"Logical Volume ({p.device})",
                    'model': model_desc,
                    'manufacturer': "System Storage Controller",
                    'serial_number': serial_fallback,
                    'capacity_bytes': total_bytes,
                    'interface_type': interface,
                    'media_type': media_type,
                    'filesystem': fstype,
                    'removable': is_removable,
                    'readonly': 'ro' in opts,
                    'mount_point': p.mountpoint,
                    'detected_capabilities': DeviceDetector._assess_capabilities(media_type, interface),
                    'health_status': 'HEALTHY',
                    'is_demo_device': False
                })
        except Exception as e:
            sys.stderr.write(f"Partition detection error: {e}\n")

        return devices

    @staticmethod
    def _assess_capabilities(media_type: str, interface_type: str) -> Dict[str, Any]:
        caps = {
            'logical_overwrite': True,
            'nist_clear': True,
            'smart_health': 'HEALTHY'
        }
        if media_type in ['NVME_SSD', 'SATA_SSD']:
            caps['hardware_purge_supported'] = True
            caps['cryptographic_erase'] = True
            caps['trim_support'] = True
        elif media_type == 'HDD':
            caps['hardware_purge_supported'] = True
            caps['defrag_erase'] = True
            caps['magnetic_overwrite'] = True
        elif media_type in ['USB_FLASH', 'SD_CARD']:
            caps['hardware_purge_supported'] = False
            caps['nand_wear_leveling_warning'] = True
            caps['note'] = "Physical NAND sanitization depends on flash controller firmware."
        return caps
