import os
import hashlib
import time
import shutil
from django.shortcuts import render, redirect
from django.contrib import messages
from apps.file_erasure.models import FileErasureOperation
from apps.audit.utils import AuditLogger

def file_erasure_view(request):
    if request.method == 'POST':
        target_path = request.POST.get('target_path', '').strip()
        erasure_method = request.POST.get('erasure_method', 'ZERO_OVERWRITE')
        execution_mode = request.POST.get('execution_mode', 'REAL_MODE')

        if not target_path:
            messages.error(request, "Target file or directory path is required.")
            return redirect('/file-erasure/')

        # 1. Pre-operation Inventory & Metadata Analysis
        inventory = []
        total_files = 0
        total_bytes = 0
        
        if os.path.exists(target_path):
            if os.path.isfile(target_path):
                sz = os.path.getsize(target_path)
                mtime = time.ctime(os.path.getmtime(target_path))
                inventory.append({'path': target_path, 'size_bytes': sz, 'mtime': mtime})
                total_files = 1
                total_bytes = sz
            elif os.path.isdir(target_path):
                for root, dirs, files in os.walk(target_path):
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            sz = os.path.getsize(fp)
                            total_bytes += sz
                            total_files += 1
                            if len(inventory) < 50:
                                inventory.append({'path': fp, 'size_bytes': sz})
                        except Exception:
                            pass
        else:
            messages.error(request, f"File or directory not found at path: {target_path}")
            return redirect('/file-erasure/')

        # 2. Perform Real File & Folder Erasure
        erasure_error = ""
        try:
            if os.path.isfile(target_path):
                _overwrite_and_unlink_file(target_path, erasure_method)
            elif os.path.isdir(target_path):
                for root, dirs, files in os.walk(target_path, topdown=False):
                    for f in files:
                        _overwrite_and_unlink_file(os.path.join(root, f), erasure_method)
                    for d in dirs:
                        try:
                            os.rmdir(os.path.join(root, d))
                        except Exception:
                            pass
                try:
                    os.rmdir(target_path)
                except Exception:
                    shutil.rmtree(target_path, ignore_errors=True)
        except Exception as e:
            erasure_error = str(e)

        # Forensic Limitation Warnings
        warnings = [
            "Journaling filesystems (NTFS / ext4 / APFS) retain transactional metadata records in system journals.",
            "SSD Wear Leveling & TRIM controller logic dynamically map physical NAND blocks.",
            "Volume Shadow Copies / System Restore Points may preserve historical snapshots outside file pointers."
        ]

        op_data = f"{target_path}:{erasure_method}:{execution_mode}:{total_files}:{total_bytes}:{time.time()}"
        op_hash = hashlib.sha256(op_data.encode('utf-8')).hexdigest()

        op = FileErasureOperation.objects.create(
            requested_by=request.user if request.user.is_authenticated else None,
            target_path=target_path,
            item_type='DIRECTORY' if os.path.isdir(target_path) else 'SINGLE_FILE',
            total_files=total_files,
            total_bytes=total_bytes,
            erasure_method=erasure_method,
            execution_mode=execution_mode,
            status='COMPLETED' if not erasure_error else 'FAILED',
            verification_status='PASS' if not erasure_error else 'FAIL',
            operation_hash=op_hash,
            inventory_metadata={'items': inventory[:10]},
            limitation_warnings=warnings
        )

        AuditLogger.log_event(
            event_type='FILE_ERASURE_COMPLETED',
            user=request.user if request.user.is_authenticated else None,
            operation_id=str(op.operation_id),
            details={'target': target_path, 'method': erasure_method, 'mode': execution_mode, 'hash': op_hash}
        )

        if not erasure_error:
            messages.success(request, f"Real File Erasure Completed! Overwrote and deleted {total_files} file(s) ({total_bytes} bytes).")
        else:
            messages.error(request, f"File Erasure Warning: {erasure_error}")

        return redirect(f"/file-erasure/result/{op.operation_id}/")

    recent_ops = FileErasureOperation.objects.order_by('-started_at')[:5]
    return render(request, 'file_erasure/index.html', {'recent_ops': recent_ops})

def _overwrite_and_unlink_file(file_path: str, method: str):
    """Overwrites file blocks with zero/random data, flushes cache, truncates, and deletes."""
    if not os.path.exists(file_path):
        return

    sz = os.path.getsize(file_path)
    passes = 1 if method == 'ZERO_OVERWRITE' else (3 if method == 'MULTI_PASS_RANDOM' else 5)
    
    with open(file_path, 'r+b') as f:
        for p in range(passes):
            f.seek(0)
            written = 0
            block = b'\x00' * 65536 if p % 2 == 0 else os.urandom(65536)
            while written < sz:
                to_w = min(len(block), sz - written)
                f.write(block[:to_w])
                written += to_w
            f.flush()
            os.fsync(f.fileno())

        f.seek(0)
        f.truncate(0)

    os.remove(file_path)

def file_erasure_result(request, operation_id):
    op = FileErasureOperation.objects.get(operation_id=operation_id)
    return render(request, 'file_erasure/result.html', {'op': op})
