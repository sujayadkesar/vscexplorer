#!/usr/bin/env python3
"""
VSCExplorer v2.10
v2.10 adds: split raw / VHD / VHDX / VMDK / physical drives, NTFS alternate data
streams (browse, preview, export, Mark-of-the-Web), hex go-to / search / entropy,
UTF-16 text preview, snapshot-wide index search, file version history across
snapshots, bookmarks / tags / notes and HTML + PDF case reports.
Architecture & Features:
- Persistent SQLite3 WAL Disk Cache (~/.vscexplorer/index_cache/): Zero re-scanning across app restarts
- Thread-Local WAL Read Connections + Registry-Locked Shutdown + Atomic Batch Writer
- 1-to-1 Partition Slot Indexing with TSK_VS_PART_FLAG_META Filtering & Single-Volume Fallback
- Custom Python ForensicSortFilterProxyModel (True 64-bit integer & tuple sorting across Qt5/Qt6)
- Windows FILETIME (64-bit 100ns) & Unix Epoch Timestamp Converter with Year-3000 Overflow Guard
- Sequence-Guarded Async Image Open, Directory Navigation & Metadata Previews
- 3-Pane Splitter: Left Directory Tree + Center Virtual File Table + Right Optional Inspectors
- 64-Bit Virtual Hex Viewer (>32 GB support), Cycle-Safe & Collision-Safe Recursive Export
- Built-in Automated Forensic Self-Test Suite (Help -> Run Automated Self-Test Suite or --self-test)
"""

import sys
import os
import re
import csv
import json
import time
import shutil
import sqlite3
import tempfile
import hashlib
import logging
import posixpath
import datetime
import threading
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple, Any, Set

try:
    from zoneinfo import ZoneInfo, available_timezones
    ZONEINFO_AVAILABLE = True
except ImportError:
    ZoneInfo = None
    available_timezones = lambda: set()
    ZONEINFO_AVAILABLE = False

# Configure Logging
# FIX (2026-11-02, issue 1): the old code created FileHandler("forensic_explorer.log")
# unconditionally at import time, so starting the tool from a read-only
# directory crashed before any GUI appeared. Now the file handler is
# best-effort: ~/.vscexplorer/ first, then CWD, then stdout only.
# Logging must never prevent the tool from starting.
# FIX (2026-11-03): ~/.vscexplorer/ is tried before CWD. The tool is often
# launched from the evidence folder, and writing a log there alters it.
def _build_log_handlers():
    handlers = [logging.StreamHandler(sys.stdout)]
    for candidate in (
        os.path.join(os.path.expanduser("~"), ".vscexplorer", "forensic_explorer.log"),
        os.path.join(os.getcwd(), "forensic_explorer.log"),
    ):
        try:
            os.makedirs(os.path.dirname(candidate), exist_ok=True)
            handlers.append(logging.FileHandler(candidate, encoding="utf-8"))
            break
        except Exception:
            continue
    return handlers


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(threadName)s) %(name)s: %(message)s",
    handlers=_build_log_handlers(),
)
logger = logging.getLogger("VSCExplorer")

# Clean Qt Binding Selection (PySide6 prioritized, PyQt5 fallback)
# FIX (2026-11-02, issue 2): the old code let a bare ImportError escape when
# neither binding was installed, so `import vscexplorer_v2` died with a
# cryptic traceback naming only the last missing module. Now the failure
# is a single actionable RuntimeError naming both bindings and the exact
# install command. QT_AVAILABLE/QT_VER are set on success so callers
# (and the --self-test / dependency dialog) can check without importing Qt.
QT_AVAILABLE = False
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTreeWidget, QTreeWidgetItem, QTableView, QSplitter, QMenuBar,
        QMenu, QFileDialog, QMessageBox, QComboBox, QLabel, QPushButton,
        QProgressBar, QStatusBar, QHeaderView, QAbstractItemView,
        QGroupBox, QTextEdit, QLineEdit, QDialog, QDialogButtonBox,
        QTabWidget, QCheckBox, QRadioButton, QFormLayout, QAbstractScrollArea,
        QStyleFactory, QListWidget, QTableWidget, QTableWidgetItem
    )
    from PySide6.QtCore import (
        Qt, Signal, QModelIndex, QAbstractTableModel,
        QSortFilterProxyModel, QThreadPool, QRunnable, QObject
    )
    from PySide6.QtGui import QAction, QActionGroup, QFont, QColor, QPainter, QKeySequence, QIcon, QFontMetrics, QTextDocument, QPdfWriter, QPageSize, QFontDatabase
    QT_VER = 6
    QT_AVAILABLE = True
except ImportError as _qt6_err:
    try:
        from PyQt5.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QTreeWidget, QTreeWidgetItem, QTableView, QSplitter, QMenuBar,
            QMenu, QAction, QActionGroup, QFileDialog, QMessageBox, QComboBox,
            QLabel, QPushButton, QProgressBar, QStatusBar, QHeaderView,
            QAbstractItemView, QGroupBox, QTextEdit, QLineEdit, QDialog,
            QDialogButtonBox, QTabWidget, QCheckBox, QRadioButton, QFormLayout,
            QAbstractScrollArea, QStyleFactory, QListWidget, QTableWidget, QTableWidgetItem
        )
        from PyQt5.QtCore import (
            Qt, pyqtSignal as Signal, QModelIndex, QAbstractTableModel,
            QSortFilterProxyModel, QThreadPool, QRunnable, QObject
        )
        from PyQt5.QtGui import QFont, QColor, QPainter, QKeySequence, QIcon, QFontMetrics, QTextDocument, QPdfWriter, QPageSize, QFontDatabase
        QT_VER = 5
        QT_AVAILABLE = True
    except ImportError as _qt5_err:
        raise RuntimeError(
            "VSCExplorer needs a Qt binding, but neither PySide6 nor PyQt5 could be imported. "
            "Install one with: pip install PySide6   (preferred, Qt6)  "
            "or: pip install PyQt5. "
            "If PySide6 IS installed and the error names a missing .so (e.g. libEGL.so.1), "
            "install the Qt system libraries instead, e.g. apt install libegl1 libgl1 libxkbcommon0 libdbus-1-3. "
            f"PySide6 error: {_qt6_err}; PyQt5 error: {_qt5_err}"
        ) from _qt5_err

# Cross-Version Qt5 / Qt6 Enum Compatibility Layer
ALIGN_CENTER = Qt.AlignmentFlag.AlignCenter if hasattr(Qt, "AlignmentFlag") else Qt.AlignCenter
ALIGN_RIGHT = Qt.AlignmentFlag.AlignRight if hasattr(Qt, "AlignmentFlag") else Qt.AlignRight
ALIGN_VCENTER = Qt.AlignmentFlag.AlignVCenter if hasattr(Qt, "AlignmentFlag") else Qt.AlignVCenter
ROLE_DISPLAY = Qt.ItemDataRole.DisplayRole if hasattr(Qt, "ItemDataRole") else Qt.DisplayRole
ROLE_USER = Qt.ItemDataRole.UserRole if hasattr(Qt, "ItemDataRole") else Qt.UserRole
ROLE_TOOLTIP = Qt.ItemDataRole.ToolTipRole if hasattr(Qt, "ItemDataRole") else Qt.ToolTipRole
ROLE_FOREGROUND = Qt.ItemDataRole.ForegroundRole if hasattr(Qt, "ItemDataRole") else Qt.ForegroundRole
ROLE_TEXT_ALIGN = Qt.ItemDataRole.TextAlignmentRole if hasattr(Qt, "ItemDataRole") else Qt.TextAlignmentRole
ORIENT_HORIZONTAL = Qt.Orientation.Horizontal if hasattr(Qt, "Orientation") else Qt.Horizontal
CASE_INSENSITIVE = Qt.CaseSensitivity.CaseInsensitive if hasattr(Qt, "CaseSensitivity") else Qt.CaseInsensitive
CTX_CUSTOM = Qt.ContextMenuPolicy.CustomContextMenu if hasattr(Qt, "ContextMenuPolicy") else Qt.CustomContextMenu
DLG_ACCEPTED = QDialog.DialogCode.Accepted if hasattr(QDialog, "DialogCode") else QDialog.Accepted
ECHO_PASSWORD = QLineEdit.EchoMode.Password if hasattr(QLineEdit, "EchoMode") else QLineEdit.Password
SEL_ROWS = QAbstractItemView.SelectionBehavior.SelectRows if hasattr(QAbstractItemView, "SelectionBehavior") else QAbstractItemView.SelectRows
SEL_EXTENDED = QAbstractItemView.SelectionMode.ExtendedSelection if hasattr(QAbstractItemView, "SelectionMode") else QAbstractItemView.ExtendedSelection
RESIZE_STRETCH = QHeaderView.ResizeMode.Stretch if hasattr(QHeaderView, "ResizeMode") else QHeaderView.Stretch
RESIZE_CONTENTS = QHeaderView.ResizeMode.ResizeToContents if hasattr(QHeaderView, "ResizeMode") else QHeaderView.ResizeToContents
RESIZE_INTERACTIVE = QHeaderView.ResizeMode.Interactive if hasattr(QHeaderView, "ResizeMode") else QHeaderView.Interactive
FONT_MONOSPACE = QFont.StyleHint.Monospace if hasattr(QFont, "StyleHint") else QFont.Monospace
SORT_ASCENDING = Qt.SortOrder.AscendingOrder if hasattr(Qt, "SortOrder") else Qt.AscendingOrder
TEXT_PLAIN = Qt.TextFormat.PlainText if hasattr(Qt, "TextFormat") else Qt.PlainText
BTN_OK_CANCEL = (
    (QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    if hasattr(QDialogButtonBox, "StandardButton")
    else (QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
)

# Forensic & OS C-Extensions
try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    pytsk3 = None
    TSK_AVAILABLE = False

try:
    import pyewf
    EWF_AVAILABLE = True
except ImportError:
    pyewf = None
    EWF_AVAILABLE = False

try:
    import pyvshadow
    PYVSHADOW_AVAILABLE = True
except ImportError:
    pyvshadow = None
    PYVSHADOW_AVAILABLE = False

try:
    import pybde
    BITLOCKER_AVAILABLE = True
except ImportError:
    pybde = None
    BITLOCKER_AVAILABLE = False

try:
    import pyvhdi
    VHDI_AVAILABLE = True
except ImportError:
    pyvhdi = None
    VHDI_AVAILABLE = False

try:
    import pyvmdk
    VMDK_AVAILABLE = True
except ImportError:
    pyvmdk = None
    VMDK_AVAILABLE = False

try:
    import win32api
    import win32file
    import win32con
    import pywintypes
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False


# ============================================================================
# Section 1: Path Normalization, File Icons & Timezone Utilities
# ============================================================================

WINDOWS_TICK = 10_000_000
SEC_TO_UNIX_EPOCH = 11_644_473_600
MAX_SAFE_EPOCH = 32_503_680_000  # 3000-01-01 00:00:00 UTC


def normalize_forensic_path(path: str) -> str:
    """Normalize a POSIX forensic path and collapse any double leading slashes ('//').

    FIX (2026-11-03): backslashes are no longer turned into '/'. TSK paths are
    always '/'-separated, and '\\' is a legal filename character on ext*/HFS+
    and in NTFS's POSIX namespace. The old conversion let a crafted name such
    as '..\\..' collapse to '/', so one folder displayed and exported another
    folder's contents.
    """
    if not path:
        return "/"
    norm = posixpath.normpath(path)
    norm = re.sub(r"^/+", "/", norm)
    return norm if norm.startswith("/") else "/" + norm


_EPOCH_UTC = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def coerce_forensic_epoch(raw_val: Any) -> Optional[int]:
    """
    Convert a datetime object, Unix epoch, or 64-bit Windows FILETIME integer
    (returned by pyvshadow / pybde) into a safe UTC Unix epoch integer in [0, MAX_SAFE_EPOCH].

    FIX (2026-11-02, issue 3): the old code treated EVERY integer above
    100_000_000_000 as FILETIME. A millisecond Unix epoch for 2026 is
    ~1_767_312_000_000, so it was run through the FILETIME formula and
    produced a negative value, silently returning None. The new code
    disambiguates by magnitude band, in order:
      * < 1e11            -> seconds (unchanged; values above MAX clamp)
      * 1e11 .. <1e14     -> milliseconds (val // 1000)
      * 1e14 .. <1e16     -> microseconds (val // 1_000_000)
      * >= 1e16           -> FILETIME first, if the result lands in
                             [0, MAX_SAFE_EPOCH]; otherwise nanoseconds
                             (val // 1_000_000_000) if that lands in range.
    FILETIME for 1970-3000 spans ~1.16e17..4.41e17, which sits inside the
    >=1e16 band and does not collide with the ms/us bands above.
    Ambiguity note: a pre-1970 FILETIME (<1.16e17) cannot be told apart
    from a large microsecond value by magnitude alone; FILETIME is tried
    first there, matching the previous behaviour for pyvshadow/pybde data.

    FIX (2026-11-03): datetimes are no longer clamped to [1970, 3000], and a
    seconds value is returned as-is instead of being capped to 3000-01-01.
    Clamping turned real (if odd) values into fabricated dates.
    """
    if raw_val is None:
        return None
    if isinstance(raw_val, datetime.datetime):
        if raw_val.tzinfo is None:
            raw_val = raw_val.replace(tzinfo=datetime.timezone.utc)
        try:
            return int((raw_val.astimezone(datetime.timezone.utc) - _EPOCH_UTC) // datetime.timedelta(seconds=1))
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(raw_val, (int, float)):
        try:
            val = int(raw_val)
        except (ValueError, OverflowError):
            return None
        if val < 0:
            return None
        if val == 0:
            return 0
        if val < 100_000_000_000:
            return val
        if val < 100_000_000_000_000:
            # Milliseconds: 1e11 ms = 1973, 1e14 ms = 5138, so any
            # realistic ms epoch for forensic data lands here.
            return min(val // 1_000, MAX_SAFE_EPOCH)
        if val < 10_000_000_000_000_000:
            # Microseconds: 2026 is ~1.767e15.
            return min(val // 1_000_000, MAX_SAFE_EPOCH)
        # >= 1e16: FILETIME first, nanoseconds as fallback.
        unix_ts = (val // WINDOWS_TICK) - SEC_TO_UNIX_EPOCH
        if 0 <= unix_ts <= MAX_SAFE_EPOCH:
            return unix_ts
        ns_ts = val // 1_000_000_000
        if 0 <= ns_ts <= MAX_SAFE_EPOCH:
            return ns_ts
        return None
    return None


def coerce_tsk_epoch(raw_val: Any) -> Optional[int]:
    """TSK reports 0 for timestamps a filesystem does not record (e.g. crtime on ext2/3,
    ctime on FAT). Showing that as 1970-01-01 is misleading, so 0 becomes None ("—").

    FIX (2026-11-03): TSK always reports whole seconds, so no unit guessing is
    applied any more. coerce_forensic_epoch() treats anything >= 1e11 as
    milliseconds, so a file timestomped to the year 6000 showed as 1974-01-11
    and 9999 as 1978-01-11; pre-1970 values (e.g. stomped to 1601) became "—".
    Both are classic anti-forensics tells and are now shown as recorded.
    """
    if raw_val is None:
        return None
    if isinstance(raw_val, datetime.datetime):
        return coerce_forensic_epoch(raw_val) or None
    try:
        val = int(raw_val)
    except (TypeError, ValueError, OverflowError):
        return None
    return None if val == 0 else val


def tsk_fs_type_name(ftype: Any) -> str:
    """Human-readable filesystem name for a pytsk3 TSK_FS_TYPE_* value (covers exFAT, APFS, FFS, ...)."""
    if not TSK_AVAILABLE:
        return "Unrecognized"
    for attr in dir(pytsk3):
        if not attr.startswith("TSK_FS_TYPE_"):
            continue
        suffix = attr[len("TSK_FS_TYPE_"):]
        if suffix.endswith("_DETECT") or suffix in ("DETECT", "ENUM", "UNSUPP"):
            continue
        if getattr(pytsk3, attr, None) == ftype:
            return suffix
    return "Unrecognized"


# ----------------------------------------------------------------------------
# FEATURE (2026-11-04): NTFS alternate data streams (ADS)
# ----------------------------------------------------------------------------
ADS_BADGE = "📎"
NTFS_DATA_ATTR_TYPE = 128  # TSK_FS_ATTR_TYPE_NTFS_DATA
# Streams that are listed but never exported: $BadClus:$Bad reports the full volume size
# (a sparse placeholder), so exporting it would write a volume-sized file of zeros.
ADS_EXPORT_SKIP = {("$BadClus", "$Bad")}

ZONE_ID_NAMES = {
    "0": "Local machine", "1": "Local intranet", "2": "Trusted sites",
    "3": "Internet", "4": "Restricted sites",
}


def ads_streams(entry: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The entry's named data streams as [{name, size, id}]. Accepts the legacy
    "Name (N B)" string form too."""
    out: List[Dict[str, Any]] = []
    for item in (entry or {}).get("ads") or []:
        if isinstance(item, dict) and item.get("name"):
            out.append({"name": str(item["name"]), "size": max(0, int(item.get("size") or 0)), "id": item.get("id")})
        elif isinstance(item, str):
            m = re.match(r"^(.*?)\s*\((\d+)\s*B\)\s*$", item)
            out.append({"name": m.group(1) if m else item, "size": int(m.group(2)) if m else 0, "id": None})
    return out


def make_ads_entry(host: Dict[str, Any], stream: Dict[str, Any]) -> Dict[str, Any]:
    """A virtual file entry for one stream of host ('host:stream'). Reads go to the
    stream's $DATA attribute; timestamps are the host's (streams have none of their own)."""
    entry = dict(host)
    entry.update({
        "name": f"{host['name']}:{stream['name']}",
        "path": f"{host['path']}:{stream['name']}",
        "is_dir": False,
        "size": int(stream.get("size") or 0),
        "ads": [],
        "ads_stream": stream["name"],
        "ads_attr_id": stream.get("id"),
        "ads_host": host["name"],
        "ads_host_path": host["path"],
        "ads_host_is_dir": bool(host.get("is_dir")),
    })
    return entry


def ads_export_skipped(entry: Dict[str, Any]) -> bool:
    # AUDIT FIX (2026-11-04): match the NTFS metadata file at the volume root only, not any
    # user file that happens to be called $BadClus with a stream named $Bad.
    return (entry.get("ads_host_path") == "/$BadClus"
            and (entry.get("ads_host"), entry.get("ads_stream")) in ADS_EXPORT_SKIP)


def decode_text_bytes(data: bytes) -> Tuple[str, str]:
    """FEATURE (2026-11-04): decode a text preview, detecting UTF-16 (BOM, or the
    zero-byte pattern of mostly-ASCII UTF-16 text) before falling back to UTF-8.
    Returns (text, encoding label)."""
    if not data:
        return "", "empty"
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace"), "UTF-8 (BOM)"
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace"), "UTF-16LE (BOM)"
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace"), "UTF-16BE (BOM)"
    sample = data[:4096]
    if len(sample) >= 8:
        even_zero = sum(1 for b in sample[0::2] if b == 0) / max(1, len(sample[0::2]))
        odd_zero = sum(1 for b in sample[1::2] if b == 0) / max(1, len(sample[1::2]))
        usable = data[: len(data) - (len(data) % 2)]
        if odd_zero > 0.6 and even_zero < 0.1:
            return usable.decode("utf-16-le", errors="replace"), "UTF-16LE (detected)"
        if even_zero > 0.6 and odd_zero < 0.1:
            return usable.decode("utf-16-be", errors="replace"), "UTF-16BE (detected)"
    return data.decode("utf-8", errors="replace"), "UTF-8 / ASCII"


def shannon_entropy(data: Optional[bytes]) -> float:
    """Shannon entropy in bits per byte (0 = constant, 8 = random/encrypted)."""
    if not data:
        return 0.0
    import math
    from collections import Counter
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def parse_hex_pattern(text: str) -> bytes:
    """'4D 5A', '4d5a', '0x4D,0x5A' or '\\x4d\\x5a' -> bytes."""
    cleaned = re.sub(r"(0x|\\x|[\s,;:-])", "", text.strip(), flags=re.IGNORECASE)
    if not cleaned or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise ValueError("Hex pattern must be pairs of hex digits, e.g. '4D 5A 90 00'")
    return bytes.fromhex(cleaned)


def parse_offset(text: str) -> int:
    """'0x1F40', '1F40h' (hex) or '8000' (decimal)."""
    t = text.strip().replace("_", "").replace(",", "")
    if t.lower().startswith("0x"):
        return int(t[2:], 16)
    if t.lower().endswith("h"):
        return int(t[:-1], 16)
    return int(t, 10)


def parse_zone_identifier(data: bytes) -> Dict[str, str]:
    """Parse a Zone.Identifier (Mark-of-the-Web) stream into its key/value pairs."""
    text, _enc = decode_text_bytes(data)
    out: Dict[str, str] = {}
    for line in text.replace("\x00", "").splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("["):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


class FileIconProvider:
    """Provides extension-aware icons for the Directory Tree and File Table."""
    ICON_MAP = {
        ".txt": "📄", ".doc": "📝", ".docx": "📝", ".pdf": "📋",
        ".rtf": "📝", ".odt": "📝", ".pages": "📝",
        ".xls": "📊", ".xlsx": "📊", ".csv": "📊", ".ods": "📊",
        ".ppt": "📊", ".pptx": "📊", ".odp": "📊", ".key": "📊",
        ".jpg": "🖼️", ".jpeg": "🖼️", ".png": "🖼️", ".gif": "🖼️",
        ".bmp": "🖼️", ".tiff": "🖼️", ".tif": "🖼️", ".ico": "🖼️",
        ".svg": "🖼️", ".webp": "🖼️",
        ".mp4": "🎬", ".avi": "🎬", ".mov": "🎬", ".wmv": "🎬",
        ".flv": "🎬", ".mkv": "🎬", ".webm": "🎬", ".m4v": "🎬",
        ".mp3": "🎵", ".wav": "🎵", ".flac": "🎵", ".aac": "🎵",
        ".ogg": "🎵", ".wma": "🎵", ".m4a": "🎵",
        ".zip": "📦", ".rar": "📦", ".7z": "📦", ".tar": "📦",
        ".gz": "📦", ".bz2": "📦", ".xz": "📦",
        ".py": "🐍", ".js": "📜", ".ps1": "📜", ".html": "🌐", ".css": "🎨",
        ".cpp": "⚙️", ".c": "⚙️", ".java": "☕", ".php": "🐘",
        ".exe": "⚙️", ".msi": "📦", ".deb": "📦", ".rpm": "📦",
        ".dmg": "💿", ".app": "📱",
        ".dll": "🔧", ".sys": "🔧", ".ini": "⚙️", ".cfg": "⚙️",
        ".reg": "📋", ".dat": "📋", ".log": "📊",
    }

    @classmethod
    def get_file_icon(cls, filename: str, is_directory: bool, is_deleted: bool = False) -> str:
        if is_deleted:
            return "🗑️"
        if is_directory:
            return "📁"
        ext = os.path.splitext(filename.lower())[1]
        return cls.ICON_MAP.get(ext, "📄")


COMMON_TIMEZONES = [
    ("UTC", 0),
    ("Asia/Kolkata", 19800),
    ("America/New_York", -18000),
    ("America/Chicago", -21600),
    ("America/Denver", -25200),
    ("America/Los_Angeles", -28800),
    ("Europe/London", 0),
    ("Europe/Paris", 3600),
    ("Europe/Berlin", 3600),
    ("Asia/Dubai", 14400),
    ("Asia/Singapore", 28800),
    ("Asia/Tokyo", 32400),
    ("Australia/Sydney", 36000),
]


_TZ_FALLBACK_WARNED: Set[str] = set()
_NO_DST_ZONES = {"UTC", "Asia/Kolkata", "Asia/Dubai", "Asia/Singapore", "Asia/Tokyo"}


def resolve_tzinfo(tz_name: str) -> datetime.tzinfo:
    if tz_name == "UTC" or not tz_name:
        return datetime.timezone.utc
    if ZONEINFO_AVAILABLE:
        try:
            return ZoneInfo(tz_name)
        except Exception:
            pass
    for name, offset_sec in COMMON_TIMEZONES:
        if name == tz_name:
            # Fixed-offset fallback: NO daylight-saving changes. Timestamps for
            # zones that observe DST will be off by an hour for part of the year.
            if tz_name not in _NO_DST_ZONES and tz_name not in _TZ_FALLBACK_WARNED:
                _TZ_FALLBACK_WARNED.add(tz_name)
                logger.warning(
                    f"IANA time zone data for '{tz_name}' is unavailable (install the 'tzdata' package); "
                    "using a fixed UTC offset WITHOUT daylight-saving rules. Displayed times may be off by 1 hour in DST."
                )
            return datetime.timezone(datetime.timedelta(seconds=offset_sec), name=name)
    logger.warning(f"Unknown time zone '{tz_name}'; falling back to UTC.")
    return datetime.timezone.utc


def format_epoch_tz(epoch: Optional[int], tz_info: datetime.tzinfo, include_tz_label: bool = False) -> str:
    """FIX (2026-11-03): renders the full range a datetime can hold (years 1-9999),
    including pre-1970 values. Epoch + timedelta is used instead of fromtimestamp()
    because fromtimestamp() rejects negative values on Windows. Values outside
    that range are shown with their raw number rather than hidden as "—"."""
    if epoch is None:
        return "—"
    try:
        dt = (_EPOCH_UTC + datetime.timedelta(seconds=int(epoch))).astimezone(tz_info)
        stamp = f"{dt.year:04d}-{dt.strftime('%m-%d %H:%M:%S')}"
        if include_tz_label:
            tz_abbr = dt.strftime("%Z") or "UTC"
            return f"{stamp} {tz_abbr}"
        return stamp
    except (OSError, OverflowError, ValueError, TypeError):
        return f"Out of range (raw {epoch})"


def format_size_human(size: int) -> str:
    if size >= 1024 ** 3:
        return f"{size / (1024 ** 3):.2f} GB"
    elif size >= 1024 ** 2:
        return f"{size / (1024 ** 2):.2f} MB"
    elif size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} bytes"


# ============================================================================
# Section 2: Persistent SQLite3 WAL Indexing Engine (SnapshotIndexDB)
# ============================================================================

class SnapshotIndexDB:
    """
    Persistent SQLite3 WAL Index Cache for Multi-Million-File Forensic Images.
    - Registry-locked thread-local read connections prevent post-close connection leaks.
    - Atomic explicit `.execute()` statements inside `with self._write_conn:`.
    """
    # FIX (2026-11-03): the schema is versioned. CREATE TABLE IF NOT EXISTS
    # never adds columns to an existing cache, so a schema change is applied by
    # dropping and rebuilding the cache tables (it is only a cache).
    # v3 adds fs_entries.meta_realloc (deleted name whose inode was reused).
    # v4 (2026-11-04): ads_json holds real NTFS stream records [{name, size, id}].
    SCHEMA_VERSION = "4"
    SCHEMA_STATEMENTS = [
        """
        CREATE TABLE IF NOT EXISTS session_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS snapshot_state (
            part_idx      INTEGER NOT NULL,
            snap_id       TEXT NOT NULL,
            fully_indexed INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (part_idx, snap_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS cached_dirs (
            part_idx        INTEGER NOT NULL,
            snap_id         TEXT NOT NULL,
            dir_path        TEXT NOT NULL,
            child_dir_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (part_idx, snap_id, dir_path)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS fs_entries (
            part_idx    INTEGER NOT NULL,
            snap_id     TEXT NOT NULL,
            path        TEXT NOT NULL,
            parent_path TEXT NOT NULL,
            name        TEXT NOT NULL,
            inode       INTEGER NOT NULL DEFAULT 0,
            is_dir      INTEGER NOT NULL DEFAULT 0,
            is_deleted  INTEGER NOT NULL DEFAULT 0,
            size        INTEGER NOT NULL DEFAULT 0,
            mtime       INTEGER,
            ctime       INTEGER,
            crtime      INTEGER,
            atime       INTEGER,
            ads_json    TEXT NOT NULL DEFAULT '[]',
            meta_realloc INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (part_idx, snap_id, path, inode, is_deleted)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_fs_browse
            ON fs_entries (part_idx, snap_id, parent_path, is_dir DESC, name COLLATE NOCASE ASC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_fs_diff
            ON fs_entries (part_idx, snap_id, is_deleted, path)
        """,
    ]

    def __init__(
        self, image_path: str, media_size: int, is_demo: bool = False, custom_db_path: Optional[str] = None,
        segment_paths: Optional[List[str]] = None, ephemeral: bool = False,
    ):
        self.image_path = image_path
        self._segment_paths_override = list(segment_paths) if segment_paths else None
        self.media_size = media_size
        self.is_demo = is_demo
        self._write_lock = threading.RLock()
        self._conn_registry_lock = threading.Lock()
        self._local = threading.local()
        self._reader_conns: List[sqlite3.Connection] = []
        self._temp_dir: Optional[str] = None
        self._closed = False

        if custom_db_path:
            self.db_path = custom_db_path
        elif is_demo or ephemeral:
            self._temp_dir = tempfile.mkdtemp(prefix="vscexplorer_demo_wal_")
            self.db_path = os.path.join(self._temp_dir, "demo_case.vscindex.sqlite")
        else:
            cache_root = os.path.join(os.path.expanduser("~"), ".vscexplorer", "index_cache")
            try:
                os.makedirs(cache_root, exist_ok=True)
            except Exception:
                cache_root = self._private_temp_cache_root()

            path_hash = hashlib.sha256(os.path.abspath(image_path).encode("utf-8")).hexdigest()[:20]
            base_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", os.path.basename(image_path))
            self.db_path = os.path.join(cache_root, f"{base_name}_{path_hash}.vscindex.sqlite")

        try:
            self._open_initialized_connection()
        except sqlite3.DatabaseError as db_err:
            # Only confirmed corruption justifies deleting a cache. Disk-full,
            # permissions, busy/locked and I/O failures must preserve it.
            code = getattr(db_err, "sqlite_errorcode", 0) & 0xFF
            if code not in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB):
                raise
            logger.warning(f"Index cache {self.db_path} is unusable ({db_err}); recreating it.")
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(self.db_path + suffix)
                except OSError:
                    pass
            self._open_initialized_connection()

    def _open_initialized_connection(self):
        self._write_conn = self._create_connection()
        try:
            self._init_schema_and_validate()
        except Exception:
            self._write_conn.close()
            raise

    @staticmethod
    def _private_temp_cache_root() -> str:
        """FIX (2026-11-03): the old fallback was a fixed, shared folder in the
        system temp directory. On a multi-user host another account could create
        it first and plant a cache database, poisoning listings and diffs. The
        fallback is now per-user, created 0700, and rejected if it is owned by
        someone else or writable by group/others."""
        base = tempfile.gettempdir()
        uid = os.getuid() if hasattr(os, "getuid") else None
        candidate = os.path.join(base, f"vscexplorer_index_cache_{uid if uid is not None else os.getpid()}")
        try:
            os.makedirs(candidate, mode=0o700, exist_ok=True)
            st = os.stat(candidate)
            if uid is None or (st.st_uid == uid and not (st.st_mode & 0o022)):
                return candidate
        except OSError:
            pass
        return tempfile.mkdtemp(prefix="vscexplorer_index_cache_")

    def _create_connection(self, cache_kib: int = 64000) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA temp_store = MEMORY;")
            conn.execute(f"PRAGMA cache_size = -{int(cache_kib)};")
            conn.execute("PRAGMA busy_timeout = 10000;")
        except Exception:
            conn.close()
            raise
        return conn

    def _get_read_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None and not self._closed:
            return conn
        with self._conn_registry_lock:
            if self._closed:
                raise sqlite3.OperationalError("SnapshotIndexDB is closed")
            conn = getattr(self._local, "conn", None)
            if conn is None:
                # Readers get a smaller page cache: one reader exists per pool thread.
                conn = self._create_connection(cache_kib=16000)
                self._local.conn = conn
                self._reader_conns.append(conn)
            return conn

    def _image_segment_paths(self) -> List[str]:
        """All on-disk files making up this image.

        FIX (2026-11-02, issue 5, part 1): for a split EWF/E01 image the
        old fingerprint stat()ed only the first segment, so replacing
        segment 2+ (same first-segment size/mtime) silently reused a
        stale index. Prefer pyewf.glob() when available; otherwise scan
        the directory for sibling segments (.E01/.E02/.../.Ex01).
        """
        if self._segment_paths_override:
            return self._segment_paths_override
        path = self.image_path
        if ForensicSession._is_ewf_path(path):
            return ewf_segment_paths(path)
        elif SPLIT_RAW_RE.match(os.path.basename(path)):
            try:
                segs = split_raw_segments(path)
                if segs:
                    return segs
            except Exception:
                pass
        return [path]

    def _compute_fingerprint(self) -> str:
        if self.is_demo or not os.path.exists(self.image_path):
            return f"demo:{self.media_size}"
        try:
            parts = []
            for seg in self._image_segment_paths():
                try:
                    st = os.stat(seg)
                    parts.append(
                        f"{os.path.basename(seg)}:{st.st_size}:{st.st_mtime_ns}:{st.st_ino}"
                    )
                except Exception:
                    parts.append(f"{os.path.basename(seg)}:missing")
            # FIX (2026-11-02, issue 5, part 2): fingerprint now covers
            # every segment (name+size+mtime_ns+inode) plus media_size,
            # so a swapped/replaced segment invalidates the cache.
            # NOTE: this intentionally changes the fingerprint format,
            # so existing caches rebuild once on first run after upgrade.
            return f"media_size={self.media_size}|" + "|".join(parts)
        except Exception:
            return f"size={self.media_size}"

    def _init_schema_and_validate(self):
        fingerprint = self._compute_fingerprint()
        with self._write_lock:
            with self._write_conn:
                self._write_conn.execute(self.SCHEMA_STATEMENTS[0])  # session_meta
                ver_row = self._write_conn.execute(
                    "SELECT value FROM session_meta WHERE key = 'schema_version'"
                ).fetchone()
                if ver_row is None or ver_row["value"] != self.SCHEMA_VERSION:
                    for table in ("fs_entries", "cached_dirs", "snapshot_state"):
                        self._write_conn.execute(f"DROP TABLE IF EXISTS {table}")
                    self._write_conn.execute("DELETE FROM session_meta")
                for stmt in self.SCHEMA_STATEMENTS:
                    self._write_conn.execute(stmt)
                self._write_conn.execute(
                    "INSERT OR REPLACE INTO session_meta (key, value) VALUES ('schema_version', ?)",
                    (self.SCHEMA_VERSION,),
                )

                row = self._write_conn.execute(
                    "SELECT value FROM session_meta WHERE key = 'fingerprint'"
                ).fetchone()
                if row and row["value"] != fingerprint:
                    logger.info("Image fingerprint changed; rebuilding persistent SQLite index.")
                    self._write_conn.execute("DELETE FROM fs_entries")
                    self._write_conn.execute("DELETE FROM cached_dirs")
                    self._write_conn.execute("DELETE FROM snapshot_state")
                self._write_conn.execute(
                    "INSERT OR REPLACE INTO session_meta (key, value) VALUES ('fingerprint', ?)",
                    (fingerprint,),
                )

    def is_directory_cached(self, part_idx: int, snap_id: str, dir_path: str) -> bool:
        if self._closed:
            return False
        try:
            conn = self._get_read_conn()
            row = conn.execute(
                "SELECT 1 FROM cached_dirs WHERE part_idx = ? AND snap_id = ? AND dir_path = ?",
                (part_idx, snap_id, dir_path),
            ).fetchone()
            return row is not None
        except sqlite3.Error:  # FIX (2026-11-03): also ProgrammingError on a reader closed mid-query
            return False

    def get_cached_child_dir_count(self, part_idx: int, snap_id: str, dir_path: str) -> Optional[int]:
        if self._closed:
            return None
        try:
            conn = self._get_read_conn()
            row = conn.execute(
                "SELECT child_dir_count FROM cached_dirs WHERE part_idx = ? AND snap_id = ? AND dir_path = ?",
                (part_idx, snap_id, dir_path),
            ).fetchone()
            return int(row["child_dir_count"]) if row is not None else None
        except sqlite3.Error:  # FIX (2026-11-03): also ProgrammingError on a reader closed mid-query
            return None

    def get_directory_children(self, part_idx: int, snap_id: str, parent_path: str) -> Optional[List[Dict[str, Any]]]:
        """Returns None (NOT []) when the cache cannot be read, so callers fall back to the real
        filesystem instead of caching/displaying a bogus empty folder."""
        if self._closed:
            return None
        try:
            conn = self._get_read_conn()
            rows = conn.execute(
                """
                SELECT name, path, is_dir, is_deleted, size, mtime, ctime, crtime, atime, inode, ads_json, meta_realloc
                FROM fs_entries
                WHERE part_idx = ? AND snap_id = ? AND parent_path = ?
                ORDER BY is_dir DESC, name COLLATE NOCASE ASC
                """,
                (part_idx, snap_id, parent_path),
            ).fetchall()
        except sqlite3.Error as e:
            logger.warning(f"Index cache read failed for {parent_path}: {e}")
            return None

        results: List[Dict[str, Any]] = []
        for r in rows:
            try:
                ads_list = json.loads(r["ads_json"]) if r["ads_json"] else []
            except Exception:
                ads_list = []
            results.append({
                "name": r["name"],
                "path": r["path"],
                "is_dir": bool(r["is_dir"]),
                "is_deleted": bool(r["is_deleted"]),
                "size": max(0, int(r["size"])),
                "mtime": r["mtime"],
                "ctime": r["ctime"],
                "crtime": r["crtime"],
                "atime": r["atime"],
                "inode": int(r["inode"]),
                "ads": ads_list,
                "meta_realloc": bool(r["meta_realloc"]),
            })
        return results

    def insert_directory_batch(
        self, part_idx: int, snap_id: str, parent_path: str, entries: List[Dict[str, Any]]
    ):
        if self._closed:
            return
        dir_count = sum(1 for e in entries if e.get("is_dir"))
        params = [
            (
                part_idx,
                snap_id,
                e["path"],
                parent_path,
                e["name"],
                int(e.get("inode", 0)),
                1 if e.get("is_dir") else 0,
                1 if e.get("is_deleted") else 0,
                max(0, int(e.get("size", 0))),
                e.get("mtime"),
                e.get("ctime"),
                e.get("crtime"),
                e.get("atime"),
                json.dumps(e.get("ads", [])),
                1 if e.get("meta_realloc") else 0,
            )
            for e in entries
        ]
        with self._write_lock:
            if self._closed:
                return
            with self._write_conn:
                self._write_conn.execute(
                    "DELETE FROM fs_entries WHERE part_idx = ? AND snap_id = ? AND parent_path = ?",
                    (part_idx, snap_id, parent_path),
                )
                if params:
                    self._write_conn.executemany(
                        """
                        INSERT OR REPLACE INTO fs_entries (
                            part_idx, snap_id, path, parent_path, name,
                            inode, is_dir, is_deleted, size,
                            mtime, ctime, crtime, atime, ads_json, meta_realloc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        params,
                    )
                self._write_conn.execute(
                    """
                    INSERT OR REPLACE INTO cached_dirs (part_idx, snap_id, dir_path, child_dir_count)
                    VALUES (?, ?, ?, ?)
                    """,
                    (part_idx, snap_id, parent_path, dir_count),
                )

    def invalidate_directory(self, part_idx: int, snap_id: str, dir_path: str):
        if self._closed:
            return
        with self._write_lock:
            if self._closed:
                return
            with self._write_conn:
                self._write_conn.execute(
                    "DELETE FROM cached_dirs WHERE part_idx = ? AND snap_id = ? AND dir_path = ?",
                    (part_idx, snap_id, dir_path),
                )
                self._write_conn.execute(
                    "DELETE FROM fs_entries WHERE part_idx = ? AND snap_id = ? AND parent_path = ?",
                    (part_idx, snap_id, dir_path),
                )
                self._write_conn.execute(
                    "UPDATE snapshot_state SET fully_indexed = 0 WHERE part_idx = ? AND snap_id = ?",
                    (part_idx, snap_id),
                )

    def is_snapshot_fully_indexed(self, part_idx: int, snap_id: str) -> bool:
        if self._closed:
            return False
        try:
            conn = self._get_read_conn()
            row = conn.execute(
                "SELECT fully_indexed FROM snapshot_state WHERE part_idx = ? AND snap_id = ?",
                (part_idx, snap_id),
            ).fetchone()
            return bool(row and row["fully_indexed"])
        except sqlite3.Error:  # FIX (2026-11-03): also ProgrammingError on a reader closed mid-query
            return False

    def mark_snapshot_fully_indexed(self, part_idx: int, snap_id: str):
        if self._closed:
            return
        with self._write_lock:
            if self._closed:
                return
            with self._write_conn:
                self._write_conn.execute(
                    "INSERT OR REPLACE INTO snapshot_state (part_idx, snap_id, fully_indexed) VALUES (?, ?, 1)",
                    (part_idx, snap_id),
                )

    def compute_snapshot_diff(self, part_idx: int, snap_a: str, snap_b: str) -> List[Dict[str, Any]]:
        """Fixed P1-03: Includes `OR a.inode != b.inode` to detect deleted-and-recreated files.
        Raises on database errors: returning [] would present a failed query as "no differences"."""
        if self._closed:
            raise sqlite3.OperationalError("SnapshotIndexDB is closed")
        sql = """
            SELECT
                CASE
                    WHEN b.path IS NULL THEN 'DELETED'
                    ELSE 'MODIFIED'
                END AS delta,
                a.name AS name_a, b.name AS name_b,
                a.path AS path,
                a.is_dir AS is_dir_a, b.is_dir AS is_dir_b,
                a.size AS old_size, COALESCE(b.size, 0) AS new_size,
                a.mtime AS mtime_a, b.mtime AS mtime_b,
                a.ctime AS ctime_a, b.ctime AS ctime_b,
                a.crtime AS crtime_a, b.crtime AS crtime_b,
                a.atime AS atime_a, b.atime AS atime_b,
                a.inode AS inode_a, b.inode AS inode_b,
                a.ads_json AS ads_a, b.ads_json AS ads_b
            FROM fs_entries a
            LEFT JOIN fs_entries b
                ON b.part_idx = a.part_idx
               AND b.snap_id = ?
               AND b.path = a.path
               AND b.is_deleted = 0
            WHERE a.part_idx = ?
              AND a.snap_id = ?
              AND a.is_deleted = 0
              AND (
                  b.path IS NULL
                  OR a.size != b.size
                  OR a.is_dir != b.is_dir
                  OR a.inode != b.inode
                  OR a.mtime IS NOT b.mtime
                  OR a.ctime IS NOT b.ctime
                  OR a.crtime IS NOT b.crtime
                  OR a.atime IS NOT b.atime
                  OR a.ads_json IS NOT b.ads_json
              )
              -- FIX (2026-11-03): null-safe IS NOT instead of COALESCE(x, -1).
              -- Pre-1970 timestamps are now kept, and -1 (1969-12-31 23:59:59)
              -- is a real value that the old sentinel treated as "missing".
              -- FIX (2026-11-02, issue 4): previously only size/is_dir/
              -- inode/mtime were compared, so a file whose content and
              -- mtime were untouched but whose ctime/atime/crtime changed
              -- (e.g. permission change, access, or re-creation with the
              -- same mtime) was invisible in the diff.

            UNION ALL

            SELECT
                'CREATED' AS delta,
                NULL AS name_a, b.name AS name_b,
                b.path AS path,
                0 AS is_dir_a, b.is_dir AS is_dir_b,
                0 AS old_size, b.size AS new_size,
                NULL AS mtime_a, b.mtime AS mtime_b,
                NULL AS ctime_a, b.ctime AS ctime_b,
                NULL AS crtime_a, b.crtime AS crtime_b,
                NULL AS atime_a, b.atime AS atime_b,
                0 AS inode_a, b.inode AS inode_b,
                '[]' AS ads_a, b.ads_json AS ads_b
            FROM fs_entries b
            LEFT JOIN fs_entries a
                ON a.part_idx = b.part_idx
               AND a.snap_id = ?
               AND a.path = b.path
               AND a.is_deleted = 0
            WHERE b.part_idx = ?
              AND b.snap_id = ?
              AND b.is_deleted = 0
              AND a.path IS NULL
            ORDER BY path COLLATE NOCASE ASC;
        """
        try:
            conn = self._get_read_conn()
            rows = conn.execute(
                sql, (snap_b, part_idx, snap_a, snap_a, part_idx, snap_b)
            ).fetchall()
        except sqlite3.Error as e:
            logger.error(f"Snapshot diff query failed: {e}")
            raise

        def _streams(raw: Optional[str]) -> List[Dict[str, Any]]:
            try:
                return ads_streams({"ads": json.loads(raw) if raw else []})
            except Exception:
                return []

        diffs: List[Dict[str, Any]] = []
        for r in rows:
            delta = r["delta"]
            use_a = (delta == "DELETED")
            old_sz = max(0, int(r["old_size"] or 0))
            new_sz = max(0, int(r["new_size"] or 0))
            # AUDIT FIX (2026-11-04): streams are compared by name and size (attribute ids can
            # differ without any change). A stream added/removed/resized between snapshots,
            # e.g. a hidden payload, is now a MODIFIED row; rows also carry their streams so
            # exporting from the diff includes them.
            st_a, st_b = _streams(r["ads_a"]), _streams(r["ads_b"])
            map_a = {x["name"]: x["size"] for x in st_a}
            map_b = {x["name"]: x["size"] for x in st_b}
            ads_change = ""
            if delta == "MODIFIED":
                names_a, names_b = set(map_a), set(map_b)
                bits = [f"+{n}" for n in sorted(names_b - names_a)] + [f"-{n}" for n in sorted(names_a - names_b)]
                bits += [f"~{n}" for n in sorted(names_a & names_b) if map_a[n] != map_b[n]]
                ads_change = " ".join(bits)
                other_changed = (
                    old_sz != new_sz or r["is_dir_a"] != r["is_dir_b"] or r["inode_a"] != r["inode_b"]
                    or any(r[f"{t}_a"] != r[f"{t}_b"] for t in ("mtime", "ctime", "crtime", "atime"))
                )
                if not other_changed and not ads_change:
                    continue  # only attribute ids differed
            diffs.append({
                "delta": delta,
                "name": r["name_a"] if use_a else r["name_b"],
                "path": r["path"],
                "is_dir": bool(r["is_dir_a"] if use_a else r["is_dir_b"]),
                "size": old_sz if use_a else new_sz,
                "old_size": old_sz,
                "new_size": new_sz,
                "size_delta": new_sz - old_sz,
                "mtime": r["mtime_a"] if use_a else r["mtime_b"],
                "ctime": r["ctime_a"] if use_a else r["ctime_b"],
                "crtime": r["crtime_a"] if use_a else r["crtime_b"],
                "atime": r["atime_a"] if use_a else r["atime_b"],
                "inode": int(r["inode_a"] if use_a else r["inode_b"]),
                "source_snap": snap_a if use_a else snap_b,
                "ads": st_a if use_a else st_b,
                "ads_change": ads_change,
            })
        return diffs

    # ---- FEATURE (2026-11-04): snapshot-wide name search -------------------------
    SEARCH_COLUMNS = (
        "snap_id, name, path, is_dir, is_deleted, size, mtime, ctime, crtime, atime, inode, ads_json, meta_realloc"
    )

    @staticmethod
    def _row_to_entry(r) -> Dict[str, Any]:
        try:
            ads_list = json.loads(r["ads_json"]) if r["ads_json"] else []
        except Exception:
            ads_list = []
        return {
            "name": r["name"], "path": r["path"],
            "is_dir": bool(r["is_dir"]), "is_deleted": bool(r["is_deleted"]),
            "size": max(0, int(r["size"])),
            "mtime": r["mtime"], "ctime": r["ctime"], "crtime": r["crtime"], "atime": r["atime"],
            "inode": int(r["inode"]), "ads": ads_list, "meta_realloc": bool(r["meta_realloc"]),
        }

    @staticmethod
    def build_name_matcher(query: str, mode: str):
        """(sql_fragment_builder, python_predicate) for 'contains' / 'wildcard' / 'regex'."""
        if mode == "regex":
            rx = re.compile(query, re.IGNORECASE)
            return ("REGEXP", query), (lambda text: bool(rx.search(text or "")))
        esc = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        if mode == "wildcard":
            like = esc.replace("*", "%").replace("?", "_")
            rx = re.compile(r"\A" + re.escape(query).replace("\\*", ".*").replace("\\?", ".") + r"\Z",
                            re.IGNORECASE | re.DOTALL)
        else:
            like = f"%{esc}%"
            rx = re.compile(re.escape(query), re.IGNORECASE)
        return ("LIKE", like), (lambda text: bool(rx.search(text or "")))

    def index_coverage(self, part_idx: int, snap_id: str) -> Tuple[int, bool]:
        """(number of folders in the index, fully indexed?) for one snapshot."""
        if self._closed:
            return 0, False
        try:
            conn = self._get_read_conn()
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM cached_dirs WHERE part_idx = ? AND snap_id = ?", (part_idx, snap_id)
            ).fetchone()
            return int(row["c"]), self.is_snapshot_fully_indexed(part_idx, snap_id)
        except sqlite3.Error:
            return 0, False

    def search_entries(
        self, part_idx: int, snap_ids: List[str], query: str, mode: str = "contains",
        include_deleted: bool = True, match_path: bool = False, kind: str = "all",
        include_ads: bool = False, limit: int = 5000,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """Search names (or full paths) in the index. Returns (rows, truncated). Each row is
        an entry dict plus 'source_snap'. With include_ads, matching stream names are
        returned as stream entries too."""
        if self._closed:
            raise sqlite3.OperationalError("SnapshotIndexDB is closed")
        if not snap_ids:
            return [], False
        (op, arg), predicate = self.build_name_matcher(query, mode)
        conn = self._get_read_conn()
        if op == "REGEXP" or not query.isascii():
            # AUDIT FIX (2026-11-04): SQLite LIKE folds case for ASCII only, so 'пароли'
            # did not find 'Пароли.txt'. Non-ASCII queries use the Unicode-aware matcher.
            conn.create_function("REGEXP", 2, lambda _p, v: 1 if v is not None and predicate(v) else 0)
            op = "REGEXP"
        column = "path" if match_path else "name"
        where = ["part_idx = ?", f"snap_id IN ({','.join('?' * len(snap_ids))})"]
        params: List[Any] = [part_idx, *snap_ids]
        if not include_deleted:
            where.append("is_deleted = 0")
        if kind == "files":
            where.append("is_dir = 0")
        elif kind == "dirs":
            where.append("is_dir = 1")
        name_clause = f"{column} LIKE ? ESCAPE '\\'" if op == "LIKE" else f"{column} REGEXP ?"
        sql = (f"SELECT {self.SEARCH_COLUMNS} FROM fs_entries WHERE {' AND '.join(where)} AND {name_clause} "
               f"ORDER BY snap_id, path COLLATE NOCASE LIMIT ?")
        rows = conn.execute(sql, (*params, arg, limit + 1)).fetchall()
        results: List[Dict[str, Any]] = []
        for r_ in rows:
            e = self._row_to_entry(r_)
            e["source_snap"] = r_["snap_id"]
            results.append(e)
        if include_ads and kind != "dirs" and len(results) <= limit:
            ads_sql = (f"SELECT {self.SEARCH_COLUMNS} FROM fs_entries WHERE {' AND '.join(where).replace('is_dir = 0', '1=1')} "
                       f"AND ads_json != '[]' AND meta_realloc = 0 ORDER BY snap_id, path COLLATE NOCASE")
            for r_ in conn.execute(ads_sql, params):
                host = self._row_to_entry(r_)
                if host.get("meta_realloc"):
                    continue
                for st in ads_streams(host):
                    matched = (
                        predicate(f"{host['path']}:{st['name']}")
                        if match_path
                        else (predicate(st["name"]) or predicate(f"{host['name']}:{st['name']}"))
                    )
                    if matched:
                        st_entry = make_ads_entry(host, st)
                        st_entry["source_snap"] = r_["snap_id"]
                        results.append(st_entry)
                        if len(results) > limit:
                            break
                if len(results) > limit:
                    break
        return results[:limit], len(results) > limit

    def get_total_indexed_entries(self) -> int:
        if self._closed:
            return 0
        try:
            conn = self._get_read_conn()
            row = conn.execute("SELECT COUNT(*) AS cnt FROM fs_entries").fetchone()
            return int(row["cnt"]) if row else 0
        except sqlite3.Error:  # FIX (2026-11-03): also ProgrammingError on a reader closed mid-query
            return 0

    def clear_all(self):
        if self._closed:
            return
        with self._write_lock:
            if self._closed:
                return
            with self._write_conn:
                self._write_conn.execute("DELETE FROM fs_entries")
                self._write_conn.execute("DELETE FROM cached_dirs")
                self._write_conn.execute("DELETE FROM snapshot_state")

    def close(self):
        with self._conn_registry_lock:
            if self._closed:
                return
            self._closed = True
            for c in self._reader_conns:
                try:
                    c.close()
                except Exception:
                    pass
            self._reader_conns.clear()
            self._local = threading.local()

        with self._write_lock:
            try:
                self._write_conn.close()
            except Exception:
                pass

        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)


# ============================================================================
# Section 3: BitLocker Data Structures, Analyzer & Dialogs
# ============================================================================

# Demo-case secrets for the locked "Encrypted Data Vault" partition (P1).
DEMO_BITLOCKER_PASSWORD = "demo"
DEMO_BITLOCKER_RECOVERY_KEY = "000000-000000-000000-000000-000000-000000-000000-000000"


class KeyProtectorInfo:
    def __init__(self, index: int, protector_type: str, type_code: Optional[int], guid: str):
        self.index = index
        self.protector_type = protector_type
        self.type_code = type_code
        self.guid = guid


class BitLockerInfo:
    def __init__(self):
        self.is_encrypted: bool = False
        self.volume_id: str = ""
        self.encryption_method: int = 0
        self.encryption_method_name: str = ""
        self.volume_label: str = ""
        self.creation_time: str = ""
        self.description: str = ""
        self.key_protectors: List[KeyProtectorInfo] = []
        self.is_unlocked: bool = False
        self.bde_volume: Any = None
        self.bde_stream: Any = None
        self.bde_lock: threading.RLock = threading.RLock()
        self.volume_size: int = 0


class SlicedStreamAdapter:
    """Thread-safe file-like wrapper over a partition slice for pybde and pyvshadow."""
    def __init__(self, read_fn, base_offset: int, size: int):
        self._read_fn = read_fn
        self._base = base_offset
        self._size = size
        self._pos = 0
        self._lock = threading.RLock()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        with self._lock:
            if whence == os.SEEK_SET:
                position = offset
            elif whence == os.SEEK_CUR:
                position = self._pos + offset
            elif whence == os.SEEK_END:
                position = self._size + offset
            else:
                raise ValueError(f"Invalid seek whence: {whence}")
            if position < 0:
                raise ValueError("Negative seek position")
            # Seeking beyond EOF is valid; subsequent relative seeks must use
            # the requested position, not a silently clamped end-of-volume.
            self._pos = position
            return self._pos

    def tell(self) -> int:
        return self._pos

    def get_size(self) -> int:
        return self._size

    def read(self, size: int = -1) -> bytes:
        with self._lock:
            if size < 0 or (self._pos + size) > self._size:
                size = self._size - self._pos
            if size <= 0:
                return b""
            data = self._read_fn(self._base + self._pos, size)
            self._pos += len(data)
            return data

    def close(self):
        pass


class BitLockerAnalyzer:
    # FIX (2026-11-03): both tables now match libbde's include/libbde/definitions.h
    # (LIBBDE_ENCRYPTION_METHOD_* / LIBBDE_KEY_PROTECTION_TYPE_*). The old tables
    # labelled 0x8004 (XTS-AES-128, the Windows 10+ default) as "AES 256-bit XTS",
    # omitted 0x8005 (XTS-AES-256), and listed codes 6/7 that libbde never returns.
    # Protector types were shifted: 0x2000 (Password) was "TPM", 0x0200 (Startup
    # Key) was "Password", 0x0100 (TPM) was "Smart Card". The unlock dialog picks
    # its input fields from these names, so a password+recovery volume was offered
    # only the recovery-key field.
    ENCRYPTION_METHODS = {
        0x0000: "None",
        0x8000: "AES-CBC 128-bit with Diffuser",
        0x8001: "AES-CBC 256-bit with Diffuser",
        0x8002: "AES-CBC 128-bit",
        0x8003: "AES-CBC 256-bit",
        0x8004: "XTS-AES 128-bit",
        0x8005: "XTS-AES 256-bit",
    }

    PROTECTOR_TYPES = {
        0x0000: "Clear Key (protection suspended)",
        0x0100: "TPM",
        0x0200: "Startup Key (.BEK)",
        0x0500: "TPM + PIN",
        0x0800: "Recovery Password",
        0x2000: "Password",
    }

    @staticmethod
    def detect_bitlocker(read_fn, partition_offset: int) -> bool:
        try:
            boot_sector = read_fn(partition_offset, 512)
            return b"-FVE-FS-" in boot_sector
        except Exception:
            return False

    @staticmethod
    def format_recovery_key(recovery_key: str) -> str:
        clean_key = re.sub(r"[^0-9]", "", recovery_key)
        if len(clean_key) != 48:
            raise ValueError(f"Recovery key must be exactly 48 digits (got {len(clean_key)})")
        for idx in range(0, 48, 6):
            block_val = int(clean_key[idx:idx + 6])
            if block_val % 11 != 0 or block_val >= 720896:
                logger.warning(f"Recovery key block {idx // 6 + 1} failed Mod-11 check")
        return "-".join(clean_key[i:i + 6] for i in range(0, 48, 6))

    @classmethod
    def get_key_protector_type_name(cls, type_code: Optional[int]) -> str:
        if type_code in cls.PROTECTOR_TYPES:
            return cls.PROTECTOR_TYPES[type_code]
        return f"Unknown Type (Code: 0x{type_code:04X})" if isinstance(type_code, int) else "Unknown"

    @classmethod
    def analyze_bitlocker_volume(cls, read_fn, partition_offset: int, partition_size: int) -> BitLockerInfo:
        info = BitLockerInfo()
        info.is_encrypted = True
        info.volume_size = partition_size

        if not BITLOCKER_AVAILABLE:
            info.encryption_method_name = "BitLocker (pybde not installed)"
            return info

        try:
            bde_volume = pybde.volume()
            stream = SlicedStreamAdapter(read_fn, partition_offset, partition_size)
            bde_volume.open_file_object(stream)

            info.bde_volume = bde_volume
            info.bde_stream = stream
            info.is_unlocked = not bde_volume.is_locked()

            try:
                vol_id = bde_volume.get_volume_identifier()
                info.volume_id = str(vol_id) if vol_id else "Unknown"
            except Exception:
                info.volume_id = "Unknown"

            try:
                enc_code = bde_volume.get_encryption_method()
                info.encryption_method = enc_code
                info.encryption_method_name = cls.ENCRYPTION_METHODS.get(
                    enc_code, f"Unknown (Code: 0x{enc_code:04X})" if isinstance(enc_code, int) else "Unknown"
                )
            except Exception:
                info.encryption_method_name = "Unknown"

            try:
                desc = bde_volume.get_description()
                info.description = str(desc) if desc else "BitLocker Encrypted Volume"
            except Exception:
                info.description = "BitLocker Encrypted Volume"

            try:
                if hasattr(bde_volume, "get_creation_time_as_datetime"):
                    dt_val = bde_volume.get_creation_time_as_datetime()
                    epoch = coerce_forensic_epoch(dt_val)
                else:
                    epoch = coerce_forensic_epoch(bde_volume.get_creation_time())
                info.creation_time = format_epoch_tz(epoch, datetime.timezone.utc, True) if epoch else "Unknown"
            except Exception:
                info.creation_time = "Unknown"

            try:
                num_kp = bde_volume.get_number_of_key_protectors()
                for i in range(num_kp):
                    try:
                        kp = bde_volume.get_key_protector(i)
                        type_code = (
                            kp.get_type()
                            if hasattr(kp, "get_type")
                            else getattr(kp, "type", None)
                        )
                        type_desc = cls.get_key_protector_type_name(type_code)
                        guid = "N/A"
                        g_raw = (
                            kp.get_identifier()
                            if hasattr(kp, "get_identifier")
                            else getattr(kp, "identifier", None)
                        )
                        if g_raw:
                            guid = g_raw.decode("utf-8", errors="replace") if isinstance(g_raw, bytes) else str(g_raw)
                        info.key_protectors.append(KeyProtectorInfo(i, type_desc, type_code, guid))
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Error analyzing BitLocker volume: {e}")

        return info

    @staticmethod
    def _set_secret(setter, secret: str):
        """libbde's Python bindings (pybde set_password / set_recovery_password) expect a *str*.
        The previous revision passed bytes only, which raises TypeError on those builds and was
        swallowed, so every password unlock silently failed. Try str first, then bytes (zeroed
        afterwards) for bindings that want bytes."""
        try:
            setter(secret)
            return
        except TypeError:
            pass
        buf = bytearray(secret.encode("utf-8"))
        try:
            setter(bytes(buf))
        finally:
            for _i in range(len(buf)):
                buf[_i] = 0

    @classmethod
    def unlock_bitlocker_volume(
        cls, bitlocker_info: BitLockerInfo, password: Optional[str] = None, recovery_key: Optional[str] = None
    ) -> bool:
        if bitlocker_info.is_unlocked:
            return True

        if bitlocker_info.bde_volume is None and bitlocker_info.volume_id.startswith("{DEMO-"):
            # FIX (2026-11-03): the demo used to accept ANY password, so the self-test's
            # unlock check could never fail. It now checks fixed demo secrets, exactly
            # (no whitespace stripping), like a real volume would.
            if password is not None and password == DEMO_BITLOCKER_PASSWORD:
                bitlocker_info.is_unlocked = True
            elif recovery_key and re.sub(r"[^0-9]", "", recovery_key) == re.sub(r"[^0-9]", "", DEMO_BITLOCKER_RECOVERY_KEY):
                bitlocker_info.is_unlocked = True
            return bitlocker_info.is_unlocked

        if not bitlocker_info.bde_volume:
            return False

        with bitlocker_info.bde_lock:
            try:
                if not bitlocker_info.bde_volume.is_locked():
                    bitlocker_info.is_unlocked = True
                    return True

                if password:
                    # FIX (2026-11-02, issue 6): pass the secret through a
                    # mutable bytearray and zero it afterwards, instead of
                    # leaving an encoded bytes copy alive for the caller's
                    # lifetime. (Python str objects themselves cannot be
                    # reliably wiped -- see clear_credentials() note --
                    # so this shrinks the window, it does not erase every
                    # copy the interpreter may have made.)
                    try:
                        cls._set_secret(bitlocker_info.bde_volume.set_password, password)
                        bitlocker_info.bde_volume.unlock()
                        if not bitlocker_info.bde_volume.is_locked():
                            bitlocker_info.is_unlocked = True
                            return True
                    except Exception as e:
                        logger.debug(f"BitLocker password attempt failed: {type(e).__name__}")

                if recovery_key:
                    try:
                        formatted_key = cls.format_recovery_key(recovery_key)
                        for key_candidate in (formatted_key, recovery_key, re.sub(r"[^0-9]", "", recovery_key)):
                            try:
                                cls._set_secret(bitlocker_info.bde_volume.set_recovery_password, key_candidate)
                                bitlocker_info.bde_volume.unlock()
                                if not bitlocker_info.bde_volume.is_locked():
                                    bitlocker_info.is_unlocked = True
                                    return True
                            except Exception as e:
                                logger.debug(f"BitLocker recovery-key attempt failed: {type(e).__name__}")
                                continue
                    except Exception as e:
                        logger.error(f"Recovery key error: {e}")

                return False
            except Exception as e:
                logger.error(f"BitLocker unlock exception: {e}")
                return False


class BitLockerCredentialsDialog(QDialog):
    def __init__(self, bitlocker_info: BitLockerInfo, parent=None):
        super().__init__(parent)
        self.bitlocker_info = bitlocker_info
        self.password = ""
        self.recovery_key = ""
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("BitLocker Volume Unlock & Metadata")
        self.resize(580, 560)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        status_txt = (
            "🔓 BitLocker Volume (Unlocked)"
            if self.bitlocker_info.is_unlocked
            else "🔒 BitLocker Encrypted Volume (Locked)"
        )
        title = QLabel(status_txt)
        title.setStyleSheet(
            f"font-size: 18px; font-weight: bold; color: {'#2ea043' if self.bitlocker_info.is_unlocked else '#d32f2f'}; padding: 4px;"
        )
        title.setAlignment(ALIGN_CENTER)
        layout.addWidget(title)

        info_group = QGroupBox("Volume Information")
        info_layout = QFormLayout(info_group)
        info_layout.setSpacing(8)

        vol_id_lbl = QLabel(self.bitlocker_info.volume_id or "Unknown")
        vol_id_lbl.setFont(QFont("Consolas", 10))
        size_text = (
            f"{self.bitlocker_info.volume_size // (1024 * 1024):,} MB"
            if self.bitlocker_info.volume_size > 0
            else "Unknown"
        )
        size_lbl = QLabel(size_text)
        size_lbl.setStyleSheet("font-weight: bold; color: #2196F3;")

        enc_lbl = QLabel(self.bitlocker_info.encryption_method_name or "Unknown")
        enc_lbl.setStyleSheet("font-weight: bold; color: #ff9800;")

        created_lbl = QLabel(self.bitlocker_info.creation_time or "Unknown")
        created_lbl.setFont(QFont("Consolas", 10))

        desc_lbl = QLabel(self.bitlocker_info.description or "Unknown")
        # FIX (2026-11-03): these strings come from the (untrusted) image; render as plain text.
        for lbl in (vol_id_lbl, enc_lbl, created_lbl, desc_lbl):
            lbl.setTextFormat(TEXT_PLAIN)
        info_layout.addRow("Volume ID:", vol_id_lbl)
        info_layout.addRow("Volume Size:", size_lbl)
        info_layout.addRow("Encryption Cipher:", enc_lbl)
        info_layout.addRow("Creation Time:", created_lbl)
        info_layout.addRow("Description:", desc_lbl)
        layout.addWidget(info_group)

        if self.bitlocker_info.key_protectors:
            kp_group = QGroupBox("Available Key Protectors")
            kp_layout = QVBoxLayout(kp_group)
            kp_layout.setSpacing(6)

            for kp in self.bitlocker_info.key_protectors:
                kp_str = f"🔑 {kp.protector_type}"
                if kp.guid and kp.guid != "N/A":
                    kp_str += f"  (ID: {kp.guid})"
                kp_lbl = QLabel(kp_str)
                kp_lbl.setTextFormat(TEXT_PLAIN)
                kp_lbl.setStyleSheet(
                    "border: 1px solid #4CAF50; padding: 6px 10px; border-radius: 4px; font-weight: 600;"
                )
                kp_layout.addWidget(kp_lbl)
            layout.addWidget(kp_group)

        self.password_radio: Optional[QRadioButton] = None
        self.recovery_radio: Optional[QRadioButton] = None
        self.password_edit: Optional[QLineEdit] = None
        self.recovery_edit: Optional[QLineEdit] = None

        if not self.bitlocker_info.is_unlocked:
            cred_group = QGroupBox("Unlock Credentials")
            cred_layout = QVBoxLayout(cred_group)
            cred_layout.setSpacing(10)

            has_password = any(
                "Password" in kp.protector_type and "Recovery" not in kp.protector_type
                for kp in self.bitlocker_info.key_protectors
            )
            has_recovery = any("Recovery" in kp.protector_type for kp in self.bitlocker_info.key_protectors)

            if (has_password and has_recovery) or not (has_password or has_recovery):
                radio_layout = QHBoxLayout()
                self.password_radio = QRadioButton("🔑 Password")
                self.recovery_radio = QRadioButton("🔐 48-Digit Recovery Key")
                self.password_radio.setChecked(True)
                self.password_radio.toggled.connect(self.toggle_inputs)
                radio_layout.addWidget(self.password_radio)
                radio_layout.addWidget(self.recovery_radio)
                cred_layout.addLayout(radio_layout)
            elif has_password:
                cred_layout.addWidget(QLabel("🔑 Password Authentication"))
            elif has_recovery:
                cred_layout.addWidget(QLabel("🔐 48-Digit Recovery Key Authentication"))

            if has_password or not (has_password or has_recovery):
                self.password_edit = QLineEdit()
                self.password_edit.setEchoMode(ECHO_PASSWORD)
                self.password_edit.setPlaceholderText("Enter BitLocker passphrase (whitespace preserved)")
                cred_layout.addWidget(self.password_edit)

            if has_recovery or not (has_password or has_recovery):
                self.recovery_edit = QLineEdit()
                self.recovery_edit.setPlaceholderText(
                    "Enter 48-digit recovery key (######-######-######-######-######-######-######-######)"
                )
                cred_layout.addWidget(self.recovery_edit)

            if self.password_edit and self.recovery_edit:
                self.recovery_edit.hide()

            layout.addWidget(cred_group)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        if not self.bitlocker_info.is_unlocked:
            unlock_btn = QPushButton("🔓 Unlock Volume")
            unlock_btn.clicked.connect(self.accept)
            btn_layout.addWidget(unlock_btn)

        cancel_btn = QPushButton("Close" if self.bitlocker_info.is_unlocked else "Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def toggle_inputs(self):
        if self.password_radio and self.password_edit and self.recovery_edit:
            if self.password_radio.isChecked():
                self.password_edit.show()
                self.recovery_edit.hide()
                self.password_edit.setFocus()
            else:
                self.password_edit.hide()
                self.recovery_edit.show()
                self.recovery_edit.setFocus()

    def accept(self):
        if self.bitlocker_info.is_unlocked:
            super().accept()
            return
        if self.password_radio and self.password_radio.isChecked() and self.password_edit:
            self.password = self.password_edit.text()
            if not self.password:
                QMessageBox.warning(self, "Validation", "Please enter a BitLocker password.")
                return
        elif self.recovery_radio and self.recovery_radio.isChecked() and self.recovery_edit:
            self.recovery_key = self.recovery_edit.text().strip()
            if not self.recovery_key:
                QMessageBox.warning(self, "Validation", "Please enter a 48-digit recovery key.")
                return
        elif self.password_edit and self.password_edit.isVisible():
            self.password = self.password_edit.text()
            if not self.password:
                QMessageBox.warning(self, "Validation", "Please enter a BitLocker password.")
                return
        elif self.recovery_edit and self.recovery_edit.isVisible():
            self.recovery_key = self.recovery_edit.text().strip()
            if not self.recovery_key:
                QMessageBox.warning(self, "Validation", "Please enter a 48-digit recovery key.")
                return
        super().accept()

    def clear_credentials(self):
        """FIX (2026-11-02, issue 6): drop the dialog's copies of the
        passphrase / recovery key and blank the line edits, so the
        secret does not sit in the dialog object after unlock.

        Honest limit: Python strings are immutable and may have been
        copied/interned by the interpreter or by Qt, so clearing these
        references cannot guarantee every in-memory copy is erased.
        What this does guarantee is that the dialog, the main window
        and the unlock call site no longer retain the secret after the
        attempt, and the editable widgets no longer display it.
        Callers must call this in a finally: block after unlock.
        """
        self.password = ""
        self.recovery_key = ""
        try:
            if self.password_edit is not None:
                self.password_edit.clear()
            if self.recovery_edit is not None:
                self.recovery_edit.clear()
        except Exception:
            pass


class ExportOptionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.generate_csv: bool = True
        self.include_hashes: bool = False
        self.hash_types: List[str] = ["sha256"]
        self.include_ads: bool = True
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Forensic Export Configuration")
        self.resize(460, 420)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        title = QLabel("Export Configuration & Hash Verification")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #2196F3;")
        title.setAlignment(ALIGN_CENTER)
        layout.addWidget(title)

        csv_group = QGroupBox("Export Summary Report")
        csv_layout = QVBoxLayout(csv_group)
        self.csv_checkbox = QCheckBox("Generate CSV export summary report (export_summary.csv)")
        self.csv_checkbox.setChecked(True)
        self.csv_checkbox.toggled.connect(self.on_csv_toggled)
        csv_layout.addWidget(self.csv_checkbox)
        csv_info = QLabel("Includes full path, inode, MACB timestamps, and export verification status.")
        csv_info.setStyleSheet("color: #777; font-size: 11px; margin-left: 22px;")
        csv_layout.addWidget(csv_info)
        layout.addWidget(csv_group)

        self.hash_group = QGroupBox("Cryptographic File Hashing")
        hash_layout = QVBoxLayout(self.hash_group)
        self.hash_checkbox = QCheckBox("Calculate cryptographic hashes during 4 MB streaming export")
        self.hash_checkbox.setChecked(True)
        self.hash_checkbox.toggled.connect(self.on_hash_toggled)
        hash_layout.addWidget(self.hash_checkbox)

        self.hash_types_widget = QWidget()
        ht_layout = QVBoxLayout(self.hash_types_widget)
        ht_layout.setContentsMargins(24, 6, 0, 0)
        self.md5_checkbox = QCheckBox("MD5")
        self.sha1_checkbox = QCheckBox("SHA-1")
        self.sha256_checkbox = QCheckBox("SHA-256")
        self.sha256_checkbox.setChecked(True)
        ht_layout.addWidget(self.md5_checkbox)
        ht_layout.addWidget(self.sha1_checkbox)
        ht_layout.addWidget(self.sha256_checkbox)
        hash_layout.addWidget(self.hash_types_widget)
        layout.addWidget(self.hash_group)

        ads_group = QGroupBox("NTFS Alternate Data Streams")
        ads_layout = QVBoxLayout(ads_group)
        self.ads_checkbox = QCheckBox(f"Include alternate data streams ({ADS_BADGE}) next to each file")
        self.ads_checkbox.setChecked(True)
        ads_layout.addWidget(self.ads_checkbox)
        ads_info = QLabel("Saved as 'name_stream' (e.g. evil.exe_Zone.Identifier). $BadClus:$Bad is always skipped.")
        ads_info.setStyleSheet("color: #777; font-size: 11px; margin-left: 22px;")
        ads_layout.addWidget(ads_info)
        layout.addWidget(ads_group)

        if not PYWIN32_AVAILABLE and os.name == "nt":
            warn_lbl = QLabel("⚠️ pywin32 not installed — Windows Creation Time (SetFileTime) will fall back to os.utime.")
            warn_lbl.setStyleSheet("color: #d29922; font-size: 11px;")
            layout.addWidget(warn_lbl)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        start_btn = QPushButton("Start Forensic Export")
        start_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(start_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def on_csv_toggled(self, checked: bool):
        self.hash_group.setEnabled(checked)
        if not checked:
            self.hash_checkbox.setChecked(False)

    def on_hash_toggled(self, checked: bool):
        self.hash_types_widget.setEnabled(checked)

    def accept(self):
        self.include_ads = self.ads_checkbox.isChecked()
        self.generate_csv = self.csv_checkbox.isChecked()
        self.include_hashes = self.hash_checkbox.isChecked()
        self.hash_types = []
        if self.include_hashes:
            if self.md5_checkbox.isChecked():
                self.hash_types.append("md5")
            if self.sha1_checkbox.isChecked():
                self.hash_types.append("sha1")
            if self.sha256_checkbox.isChecked():
                self.hash_types.append("sha256")
            if not self.hash_types:
                QMessageBox.warning(self, "Validation", "Please select at least one hash algorithm.")
                return
        super().accept()


class TimeZoneSelectDialog(QDialog):
    def __init__(self, current_tz_name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Forensic Display Time Zone")
        self.resize(440, 480)
        self.selected_tz_name = current_tz_name

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        layout.addWidget(QLabel(
            "Select the time zone used across VSS Snapshot selectors,\n"
            "File Table MACB columns, Snapshot Diff, and Metadata Previews:"
        ))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter time zone (e.g., UTC, Kolkata, New_York, London)...")
        self.search_input.textChanged.connect(self._populate_list)
        layout.addWidget(self.search_input)

        self.tz_list_widget = QListWidget()
        self.tz_list_widget.itemDoubleClicked.connect(self.accept)
        layout.addWidget(self.tz_list_widget, 1)

        common_names = [name for name, _ in COMMON_TIMEZONES]
        all_zones = sorted(list(available_timezones())) if ZONEINFO_AVAILABLE else []
        self._all_tz_names = common_names + [z for z in all_zones if z not in common_names]
        self._populate_list("")

        btn_box = QDialogButtonBox(BTN_OK_CANCEL)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _populate_list(self, filter_text: str):
        self.tz_list_widget.clear()
        needle = filter_text.strip().lower()
        selected_row = 0
        row_idx = 0
        for tz_name in self._all_tz_names:
            if needle and needle not in tz_name.lower():
                continue
            self.tz_list_widget.addItem(tz_name)
            if tz_name == self.selected_tz_name:
                selected_row = row_idx
            row_idx += 1
        if self.tz_list_widget.count() > 0:
            self.tz_list_widget.setCurrentRow(selected_row)

    def accept(self):
        item = self.tz_list_widget.currentItem()
        if not item:
            QMessageBox.warning(self, "Validation", "Please select a valid time zone from the list.")
            return
        self.selected_tz_name = item.text()
        super().accept()


# ============================================================================
# Section 4: Thread-Safe Forensic Session (L1 RAM + L2 SQLite WAL Cache)
# ============================================================================

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *{f"COM{i}" for i in range(1, 10)},
    *{f"LPT{i}" for i in range(1, 10)},
}


MAX_EXPORT_NAME_BYTES = 240  # margin under the 255-byte name limit of ext4 / APFS / XFS


def _fit_export_name(stem: str, ext: str, tag: str = "") -> str:
    """Truncate stem (never tag/ext) so the UTF-8 name fits MAX_EXPORT_NAME_BYTES."""
    budget = MAX_EXPORT_NAME_BYTES - len((tag + ext).encode("utf-8"))
    if budget < 8:
        ext = ""
        budget = MAX_EXPORT_NAME_BYTES - len(tag.encode("utf-8"))
    raw = stem.encode("utf-8")
    if len(raw) > budget:
        stem = raw[:budget].decode("utf-8", errors="ignore").rstrip(" .") or "unnamed"
    return f"{stem}{tag}{ext}"


def sanitize_filename(name: str, inode: int, used_names: Set[str]) -> str:
    """FIX (2026-11-03):
    - Windows reserved names are matched on the part before the FIRST dot, so
      'CON.tar.gz' is caught too (Windows treats it as the CON device).
    - Names are truncated to fit 255-byte filesystem limits. A 255-character NTFS
      name in a non-Latin script is up to ~765 UTF-8 bytes and failed to export on
      Linux/macOS with 'File name too long'.
    """
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).rstrip(" .")
    if not cleaned:
        cleaned = f"unnamed_{inode}"
    if cleaned.split(".")[0].rstrip(" ").upper() in WINDOWS_RESERVED_NAMES:
        cleaned = f"_{cleaned}"
    stem, ext = os.path.splitext(cleaned)
    if len(ext.encode("utf-8")) > 32:  # not a real extension; keep it with the stem
        stem, ext = cleaned, ""
    candidate = _fit_export_name(stem, ext)
    if candidate.lower() in used_names:
        counter = 1
        while True:
            # Same name AND same inode (e.g. deleted + live entry) gets a counter.
            tag = f"_[inode_{inode}]" if counter == 1 else f"_[inode_{inode}_{counter}]"
            candidate = _fit_export_name(stem, ext, tag)
            if candidate.lower() not in used_names:
                break
            counter += 1
    used_names.add(candidate.lower())
    return candidate


if TSK_AVAILABLE:
    class ThreadSafeCallableImgInfo(pytsk3.Img_Info):
        def __init__(self, read_fn, size: int, keep_alive_refs: Optional[List[Any]] = None):
            self._read_fn = read_fn
            self._size = size
            self._keep_alive = keep_alive_refs or []
            self._lock = threading.RLock()
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset: int, size: int) -> bytes:
            with self._lock:
                return self._read_fn(offset, size)

        def get_size(self) -> int:
            return self._size

        def close(self):
            self._keep_alive.clear()


# ============================================================================
# Section 3b: Media Backends (raw, split raw, EWF, VHD/VHDX, VMDK, physical drive)
# ============================================================================
# FEATURE (2026-11-04): every container format is a small class with the same
# read(offset, size) / media_size / close() interface plus segment_paths (for the
# cache fingerprint), info (for the case report) and stored_hashes (E01 only).

SPLIT_RAW_RE = re.compile(r"^(?P<stem>.+)\.(?P<num>\d{3})$")
VHDI_EXTENSIONS = {".vhd", ".vhdx", ".avhd", ".avhdx"}
VMDK_EXTENSIONS = {".vmdk"}


def is_physical_device_path(path: str) -> bool:
    p = path.replace("/", "\\") if os.name == "nt" else path
    if os.name == "nt":
        return p.upper().startswith("\\\\.\\")
    return path.startswith("/dev/")


def detect_media_kind(path: str) -> str:
    if is_physical_device_path(path):
        return "device"
    ext = os.path.splitext(path)[1].lower()
    if ForensicSession._is_ewf_path(path):
        return "ewf"
    if ext in VHDI_EXTENSIONS:
        return "vhdi"
    if ext in VMDK_EXTENSIONS:
        return "vmdk"
    if SPLIT_RAW_RE.match(os.path.basename(path)):
        return "split_raw"
    return "raw"


def split_raw_segments(path: str) -> List[str]:
    """All numbered segments of a split raw image (name.000/.001, .002 ...), in order.
    Any segment may be selected; the set always starts from the lowest number present."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    m = SPLIT_RAW_RE.match(os.path.basename(path))
    if not m:
        return [path]
    stem = m.group("stem")
    width = len(m.group("num"))
    start = 0 if os.path.exists(os.path.join(directory, f"{stem}.{0:0{width}d}")) else 1
    segs: List[str] = []
    n = start
    while True:
        cand = os.path.join(directory, f"{stem}.{n:0{width}d}")
        if not os.path.isfile(cand):
            break
        segs.append(cand)
        n += 1
    # AUDIT FIX (2026-11-04): a missing middle segment used to end the set silently,
    # opening a truncated disk (e.g. 14 MB of a 27 MB image) with no warning.
    pat = re.compile(re.escape(stem) + r"\.(\d{" + str(width) + r"})$")
    try:
        later = sorted(int(m2.group(1)) for f in os.listdir(directory) if (m2 := pat.match(f)) and int(m2.group(1)) >= n)
    except OSError:
        later = []
    if later:
        missing = ", ".join(f"{stem}.{k:0{width}d}" for k in range(n, later[0]))
        raise RuntimeError(
            f"Split raw image is incomplete: segment(s) {missing} are missing, but later segments exist "
            f"(up to {stem}.{later[-1]:0{width}d}). Opening it would present a truncated disk."
        )
    return segs or [path]


EWF_SEG_EXT_RE = re.compile(r"\.(?:e\d\d|ex\d\d|s\d\d|l\d\d|lx\d\d|e[a-z]{2}|ewf)$", re.IGNORECASE)


def ewf_segment_paths(path: str) -> List[str]:
    """Locate all segments of an EWF/E01/Ex01/S01/L01 image set, preferring pyewf.glob()
    and falling back to a sibling directory scan when pyewf.glob is unavailable or fails."""
    try:
        if EWF_AVAILABLE and pyewf is not None and hasattr(pyewf, "glob"):
            segs = pyewf.glob(path)
            if segs:
                return list(segs)
    except Exception:
        pass
    try:
        directory = os.path.dirname(os.path.abspath(path)) or "."
        stem = os.path.splitext(os.path.basename(path))[0].lower()
        found = []
        for name in sorted(os.listdir(directory)):
            base, ext = os.path.splitext(name.lower())
            if base == stem and EWF_SEG_EXT_RE.fullmatch(ext):
                cand = os.path.join(directory, name)
                if os.path.isfile(cand):
                    found.append(cand)
        if found:
            return found
    except Exception:
        pass
    return [path]


def _resolve_parent_image(child_path: str, parent_name: Optional[str]) -> Optional[str]:
    """Differencing disks store the parent path as written on the acquisition host
    (often a Windows path). The parent is looked up by file name next to the child."""
    if not parent_name:
        return None
    # AUDIT FIX (2026-11-04): only the child's own folder is searched. Honouring the
    # stored absolute path let a crafted differencing disk pull in any VHD/VMDK on the
    # analysis host (e.g. another case's evidence) as its parent.
    import ntpath
    base = ntpath.basename(parent_name.replace("/", "\\"))
    if not base or base in (".", ".."):
        return None
    candidate = os.path.join(os.path.dirname(os.path.abspath(child_path)), base)
    return candidate if os.path.isfile(candidate) else None


class _MediaBackend:
    kind = "raw"
    label = "Raw (dd)"

    def __init__(self):
        self.media_size = 0
        self.segment_paths: List[str] = []
        self.info: Dict[str, str] = {}

    def read(self, offset: int, size: int) -> bytes:
        raise NotImplementedError

    def stored_hashes(self) -> Dict[str, str]:
        return {}

    def close(self):
        pass


class RawFileBackend(_MediaBackend):
    kind, label = "raw", "Raw (dd)"

    def __init__(self, path: str):
        super().__init__()
        self._fp = open(path, "rb")
        self._fp.seek(0, os.SEEK_END)
        self.media_size = self._fp.tell()
        self._fp.seek(0)
        self.segment_paths = [path]

    def read(self, offset, size):
        self._fp.seek(offset)
        return self._fp.read(size)

    def close(self):
        self._fp.close()


class SplitRawBackend(_MediaBackend):
    kind, label = "split_raw", "Split raw (.001, .002, ...)"

    def __init__(self, segments: List[str]):
        super().__init__()
        self._fps = []
        self._starts: List[int] = []
        pos = 0
        try:
            for seg in segments:
                fp = open(seg, "rb")
                fp.seek(0, os.SEEK_END)
                size = fp.tell()
                self._fps.append(fp)
                self._starts.append(pos)
                pos += size
        except Exception:
            self.close()
            raise
        self._sizes = [self._starts[i + 1] - self._starts[i] for i in range(len(self._starts) - 1)] + [pos - self._starts[-1]]
        self.media_size = pos
        self.segment_paths = list(segments)
        self.info = {"Segments": str(len(segments))}

    def read(self, offset, size):
        import bisect
        out = bytearray()
        idx = max(0, bisect.bisect_right(self._starts, offset) - 1)
        while size > 0 and idx < len(self._fps):
            rel = offset - self._starts[idx]
            if rel >= self._sizes[idx]:
                idx += 1
                continue
            take = min(size, self._sizes[idx] - rel)
            fp = self._fps[idx]
            fp.seek(rel)
            chunk = fp.read(take)
            out += chunk
            offset += len(chunk)
            size -= len(chunk)
            if len(chunk) < take:
                break  # short read: segment shrank or I/O error
        return bytes(out)

    def close(self):
        for fp in self._fps:
            try:
                fp.close()
            except Exception:
                pass
        self._fps = []


class EwfBackend(_MediaBackend):
    kind, label = "ewf", "EnCase / EWF (E01, Ex01)"

    def __init__(self, path: str):
        super().__init__()
        if not EWF_AVAILABLE:
            raise RuntimeError(
                f"Cannot open EWF/E01 image '{os.path.basename(path)}': libewf-python (pyewf) is not installed."
            )
        self.segment_paths = ewf_segment_paths(path)
        self.handle = pyewf.handle()
        try:
            self.handle.open(self.segment_paths)
            self.media_size = self.handle.get_media_size()
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise
        self.info = {"Segments": str(len(self.segment_paths))}
        try:
            for k, v in (self.handle.get_header_values() or {}).items():
                if v:
                    self.info[f"EWF header: {k}"] = str(v)
        except Exception:
            pass

    def read(self, offset, size):
        self.handle.seek(offset)
        return self.handle.read(size)

    def stored_hashes(self) -> Dict[str, str]:
        """Acquisition hashes recorded inside the E01 (e.g. MD5, SHA1)."""
        try:
            return {str(k).upper(): str(v).lower() for k, v in (self.handle.get_hash_values() or {}).items() if v}
        except Exception:
            return {}

    def close(self):
        self.handle.close()


class VhdiBackend(_MediaBackend):
    kind, label = "vhdi", "Hyper-V / Virtual PC (VHD, VHDX)"

    def __init__(self, path: str):
        super().__init__()
        if not VHDI_AVAILABLE:
            raise RuntimeError(f"Cannot open '{os.path.basename(path)}': libvhdi-python (pyvhdi) is not installed.")
        self._chain = []
        seen_chain = {os.path.normcase(os.path.abspath(path))}
        current = path
        try:
            while current:
                f = pyvhdi.file()
                self._chain.append(f)
                f.open(current)
                self.segment_paths.append(current)
                parent_name = f.get_parent_filename() if hasattr(f, "get_parent_filename") else None
                if not parent_name:
                    break
                parent = _resolve_parent_image(current, parent_name)
                if not parent:
                    raise RuntimeError(
                        f"Differencing disk '{os.path.basename(current)}' needs its parent "
                        f"'{parent_name}', which was not found next to it."
                    )
                norm_parent = os.path.normcase(os.path.abspath(parent))
                if norm_parent in seen_chain:
                    raise RuntimeError(
                        f"Cyclic parent reference in differencing-disk chain: '{os.path.basename(parent)}'."
                    )
                seen_chain.add(norm_parent)
                if len(self._chain) >= 64:
                    raise RuntimeError("Differencing-disk chain is longer than 64 levels.")
                current = parent
            for i in range(len(self._chain) - 2, -1, -1):
                self._chain[i].set_parent(self._chain[i + 1])
            self.media_size = self._chain[0].get_media_size()
        except Exception:
            self.close()
            raise
        self.info = {"Disk chain": " -> ".join(os.path.basename(p) for p in self.segment_paths)}

    def read(self, offset, size):
        f = self._chain[0]
        f.seek_offset(offset, os.SEEK_SET)
        return f.read_buffer(size)

    def close(self):
        for f in self._chain:
            try:
                f.close()
            except Exception:
                pass
        self._chain = []


class VmdkBackend(_MediaBackend):
    kind, label = "vmdk", "VMware (VMDK)"

    def __init__(self, path: str):
        super().__init__()
        if not VMDK_AVAILABLE:
            raise RuntimeError(f"Cannot open '{os.path.basename(path)}': libvmdk-python (pyvmdk) is not installed.")
        self._chain = []
        seen_chain = {os.path.normcase(os.path.abspath(path))}
        current = path
        try:
            while current:
                h = pyvmdk.handle()
                self._chain.append(h)
                h.open(current)
                h.open_extent_data_files()
                self.segment_paths.append(current)
                base_dir = os.path.dirname(os.path.abspath(current))
                try:
                    for i in range(h.get_number_of_extents()):
                        name = h.get_extent_descriptor(i).get_filename()
                        if name:
                            # libvmdk opens the extent's base name inside the descriptor's folder
                            # (directory parts are ignored), so record that file.
                            import ntpath
                            ext_path = os.path.join(base_dir, ntpath.basename(name.replace("/", "\\")))
                            if ext_path not in self.segment_paths:
                                self.segment_paths.append(ext_path)
                except Exception:
                    pass
                parent_name = h.get_parent_filename() if hasattr(h, "get_parent_filename") else None
                if not parent_name:
                    break
                parent = _resolve_parent_image(current, parent_name)
                if not parent:
                    raise RuntimeError(
                        f"Snapshot/delta disk '{os.path.basename(current)}' needs its parent "
                        f"'{parent_name}', which was not found next to it."
                    )
                norm_parent = os.path.normcase(os.path.abspath(parent))
                if norm_parent in seen_chain:
                    raise RuntimeError(
                        f"Cyclic parent reference in VMDK parent chain: '{os.path.basename(parent)}'."
                    )
                seen_chain.add(norm_parent)
                if len(self._chain) >= 64:
                    raise RuntimeError("VMDK parent chain is longer than 64 levels.")
                current = parent
            for i in range(len(self._chain) - 2, -1, -1):
                self._chain[i].set_parent(self._chain[i + 1])
            self.media_size = self._chain[0].get_media_size()
        except Exception:
            self.close()
            raise
        self.info = {"Extent/chain files": str(len(self.segment_paths))}

    def read(self, offset, size):
        h = self._chain[0]
        h.seek_offset(offset, os.SEEK_SET)
        return h.read_buffer(size)

    def close(self):
        for h in self._chain:
            try:
                h.close()
            except Exception:
                pass
        self._chain = []


def _device_size_bytes(fd: int, path: str) -> int:
    """Size of a block device. Linux supports SEEK_END; Windows and macOS need an ioctl."""
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
        handle = msvcrt.get_osfhandle(fd)
        length = ctypes.c_longlong(0)
        returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            wintypes.HANDLE(handle), IOCTL_DISK_GET_LENGTH_INFO, None, 0,
            ctypes.byref(length), ctypes.sizeof(length), ctypes.byref(returned), None,
        )
        if not ok:
            raise OSError(f"DeviceIoControl(IOCTL_DISK_GET_LENGTH_INFO) failed for {path}")
        return int(length.value)
    if sys.platform == "darwin":
        import fcntl
        import struct
        DKIOCGETBLOCKSIZE, DKIOCGETBLOCKCOUNT = 0x40046418, 0x40086419
        bsize = struct.unpack("I", fcntl.ioctl(fd, DKIOCGETBLOCKSIZE, b"\0" * 4))[0]
        bcount = struct.unpack("Q", fcntl.ioctl(fd, DKIOCGETBLOCKCOUNT, b"\0" * 8))[0]
        return int(bsize) * int(bcount)
    size = os.lseek(fd, 0, os.SEEK_END)
    os.lseek(fd, 0, os.SEEK_SET)
    return size


class PhysicalDeviceBackend(_MediaBackend):
    """Read-only access to a physical drive. Raw device reads on Windows/macOS must be
    sector-aligned, so every read is widened to ALIGN and then sliced."""
    kind, label = "device", "Physical drive (read-only)"
    ALIGN = 4096

    def __init__(self, path: str):
        super().__init__()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        try:
            self._fd = os.open(path, flags)
        except PermissionError as e:
            raise PermissionError(
                f"Access to {path} was denied. Reading a physical drive needs administrator/root rights."
            ) from e
        try:
            self.media_size = _device_size_bytes(self._fd, path)
        except Exception:
            os.close(self._fd)
            raise
        if self.media_size <= 0:
            os.close(self._fd)
            raise RuntimeError(f"{path} reports a size of 0 bytes (no media?).")
        self.segment_paths = [path]
        self.info = {"Device": path}

    def read(self, offset, size):
        if offset < 0 or size <= 0 or offset >= self.media_size:
            return b""
        size = min(size, self.media_size - offset)
        for a in (self.ALIGN, 512):
            start = (offset // a) * a
            # Alignment must never expand a request past the actual device.
            end = min(((offset + size + a - 1) // a) * a, self.media_size)
            try:
                os.lseek(self._fd, start, os.SEEK_SET)
                buf = bytearray()
                want = end - start
                while len(buf) < want:
                    chunk = os.read(self._fd, want - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                rel = offset - start
                return bytes(buf[rel:rel + size])
            except OSError:
                if a == 512:
                    raise
        return b""

    def close(self):
        try:
            os.close(self._fd)
        except Exception:
            pass


def open_media_backend(path: str) -> _MediaBackend:
    kind = detect_media_kind(path)
    if kind == "device":
        return PhysicalDeviceBackend(path)
    if kind == "ewf":
        return EwfBackend(path)
    if kind == "vhdi":
        return VhdiBackend(path)
    if kind == "vmdk":
        return VmdkBackend(path)
    if kind == "split_raw":
        segs = split_raw_segments(path)
        return SplitRawBackend(segs) if len(segs) > 1 else RawFileBackend(segs[0])
    return RawFileBackend(path)


def list_physical_drives() -> List[Dict[str, Any]]:
    """Best-effort list of physical drives: [{path, size, model}]."""
    drives: List[Dict[str, Any]] = []
    if os.name == "nt":
        for n in range(32):
            path = f"\\\\.\\PhysicalDrive{n}"
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            except OSError:
                continue
            try:
                drives.append({"path": path, "size": _device_size_bytes(fd, path), "model": ""})
            except Exception:
                drives.append({"path": path, "size": 0, "model": ""})
            finally:
                os.close(fd)
    elif sys.platform == "darwin":
        import glob
        for dev in sorted(glob.glob("/dev/rdisk[0-9]*")):
            if re.fullmatch(r"/dev/rdisk\d+", dev):
                drives.append({"path": dev, "size": 0, "model": ""})
    else:
        sys_block = "/sys/block"
        try:
            names = sorted(os.listdir(sys_block))
        except OSError:
            names = []
        for name in names:
            if re.match(r"^(loop|ram|zram|dm-|sr|fd)", name):
                continue
            try:
                with open(os.path.join(sys_block, name, "size")) as fh:
                    size = int(fh.read().strip()) * 512
            except Exception:
                size = 0
            if size <= 0:
                continue
            model = ""
            try:
                with open(os.path.join(sys_block, name, "device", "model")) as fh:
                    model = fh.read().strip()
            except Exception:
                pass
            drives.append({"path": f"/dev/{name}", "size": size, "model": model})
    return drives


# ============================================================================
# Section 3c: Case Store (bookmarks, tags, notes, export log, image hashes)
# ============================================================================

APP_VERSION = "2.10"
DEFAULT_TAGS = ["Evidence", "Suspicious", "Malware", "Exfiltration", "Persistence", "Credential Access", "Review"]


class CaseStore:
    """FEATURE (2026-11-04): per-image case data kept OUTSIDE the index cache, so clearing
    or rebuilding the cache never loses an examiner's bookmarks or notes.
    Location: ~/.vscexplorer/cases/<image>_<hash>.vsccase.sqlite (temp for the demo)."""

    SCHEMA = [
        "CREATE TABLE IF NOT EXISTS case_info (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        """CREATE TABLE IF NOT EXISTS bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            part_idx INTEGER NOT NULL, snap_id TEXT NOT NULL, path TEXT NOT NULL,
            inode INTEGER NOT NULL DEFAULT 0, ads_stream TEXT NOT NULL DEFAULT '',
            tag TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
            created_utc INTEGER NOT NULL, entry_json TEXT NOT NULL,
            UNIQUE (part_idx, snap_id, path, inode, ads_stream))""",
        """CREATE TABLE IF NOT EXISTS exports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, time_utc INTEGER NOT NULL,
            part_idx INTEGER, snap_id TEXT, dest_dir TEXT, manifest_path TEXT,
            manifest_sha256 TEXT, items_total INTEGER, items_success INTEGER, cancelled INTEGER)""",
        """CREATE TABLE IF NOT EXISTS image_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, time_utc INTEGER NOT NULL,
            md5 TEXT, sha1 TEXT, sha256 TEXT, bytes_hashed INTEGER, media_size INTEGER,
            stored_json TEXT, verification TEXT)""",
    ]

    def __init__(self, db_path: str, temp_dir: Optional[str] = None):
        self.db_path = db_path
        self._temp_dir = temp_dir
        self._lock = threading.RLock()
        self._closed = False
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=15.0)
        try:
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA busy_timeout = 10000;")
            with self.conn:
                for stmt in self.SCHEMA:
                    self.conn.execute(stmt)
            self._keys: Set[Tuple[int, str, str, int, str]] = set()
            self._reload_keys()
        except Exception:
            self.conn.close()
            raise

    @classmethod
    def for_session(cls, session: "ForensicSession") -> "CaseStore":
        if session.is_demo:
            tmp = tempfile.mkdtemp(prefix="vscexplorer_demo_case_")
            return cls(os.path.join(tmp, "demo.vsccase.sqlite"), temp_dir=tmp)
        root = os.path.join(os.path.expanduser("~"), ".vscexplorer", "cases")
        try:
            os.makedirs(root, exist_ok=True)
        except OSError:
            root = SnapshotIndexDB._private_temp_cache_root()
        img_ident = (
            session.image_path
            if is_physical_device_path(session.image_path)
            else os.path.abspath(session.image_path)
        )
        ident = f"{img_ident}|{session.media_size}"
        path_hash = hashlib.sha256(ident.encode("utf-8")).hexdigest()[:20]
        base = re.sub(r"[^a-zA-Z0-9_.-]", "_", os.path.basename(session.image_path) or "device")
        return cls(os.path.join(root, f"{base}_{path_hash}.vsccase.sqlite"))

    FINGERPRINT_KEY = "_image_fingerprint"

    def check_fingerprint(self, fingerprint: str) -> Optional[str]:
        """AUDIT FIX (2026-11-04): the case file is keyed by image path + size only. If a
        different image now sits at the same path (same size), its bookmarks would be
        presented as findings on this image. The first-seen fingerprint (segment names,
        sizes, mtimes, inodes) is recorded; returns the old value when it differs."""
        with self._lock:
            if self._closed:
                return None
            with self.conn:
                row = self.conn.execute(
                    "SELECT value FROM case_info WHERE key = ?", (self.FINGERPRINT_KEY,)
                ).fetchone()
                if row is None:
                    self.conn.execute("INSERT INTO case_info (key, value) VALUES (?, ?)", (self.FINGERPRINT_KEY, fingerprint))
                    return None
                return None if row["value"] == fingerprint else row["value"]

    def accept_fingerprint(self, fingerprint: str):
        with self._lock:
            if self._closed:
                return
            with self.conn:
                self.conn.execute("INSERT OR REPLACE INTO case_info (key, value) VALUES (?, ?)", (self.FINGERPRINT_KEY, fingerprint))

    @staticmethod
    def entry_key(part_idx: int, snap_id: str, e: Dict[str, Any]) -> Tuple[int, str, str, int, str]:
        return (int(part_idx), str(snap_id), e["path"], int(e.get("inode") or 0), e.get("ads_stream") or "")

    def _reload_keys(self):
        with self._lock:
            if self._closed:
                return
            rows = self.conn.execute("SELECT part_idx, snap_id, path, inode, ads_stream FROM bookmarks").fetchall()
            self._keys = {(r["part_idx"], r["snap_id"], r["path"], r["inode"], r["ads_stream"]) for r in rows}

    # -- case info -------------------------------------------------------------
    def get_info(self) -> Dict[str, str]:
        with self._lock:
            if self._closed:
                return {}
            return {r["key"]: r["value"] for r in self.conn.execute("SELECT key, value FROM case_info")}

    def set_info(self, info: Dict[str, str]):
        with self._lock:
            if self._closed:
                return
            with self.conn:
                for k, v in info.items():
                    self.conn.execute("INSERT OR REPLACE INTO case_info (key, value) VALUES (?, ?)", (k, v))

    # -- bookmarks -------------------------------------------------------------
    def is_bookmarked(self, part_idx: int, snap_id: str, e: Dict[str, Any]) -> bool:
        return self.entry_key(part_idx, snap_id, e) in self._keys

    def upsert_bookmark(self, part_idx: int, snap_id: str, e: Dict[str, Any], tag: str, note: str):
        key = self.entry_key(part_idx, snap_id, e)
        stored = {k: v for k, v in e.items() if k != "source_snap"}
        stored["source_snap"] = snap_id
        # AUDIT FIX (2026-11-04): plain UPDATE-then-INSERT instead of "ON CONFLICT ... DO
        # UPDATE", which needs SQLite >= 3.24 (older system SQLite, e.g. Ubuntu 18.04,
        # raised a syntax error on every bookmark).
        with self._lock:
            if self._closed:
                return
            with self.conn:
                cur = self.conn.execute(
                    """UPDATE bookmarks SET tag = ?, note = ?, entry_json = ?
                       WHERE part_idx = ? AND snap_id = ? AND path = ? AND inode = ? AND ads_stream = ?""",
                    (tag, note, json.dumps(stored), *key),
                )
                if cur.rowcount == 0:
                    self.conn.execute(
                        """INSERT INTO bookmarks (part_idx, snap_id, path, inode, ads_stream, tag, note, created_utc, entry_json)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (*key, tag, note, int(time.time()), json.dumps(stored)),
                    )
                self._keys.add(key)

    def remove_bookmark(self, bookmark_id: int):
        with self._lock:
            if self._closed:
                return
            with self.conn:
                self.conn.execute("DELETE FROM bookmarks WHERE id = ?", (bookmark_id,))
        self._reload_keys()

    def list_bookmarks(self, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if self._closed:
                return []
            sql = "SELECT * FROM bookmarks" + (" WHERE tag = ?" if tag else "") + " ORDER BY tag, snap_id, path"
            rows = self.conn.execute(sql, (tag,) if tag else ()).fetchall()
        out = []
        for r in rows:
            try:
                entry = json.loads(r["entry_json"])
            except Exception:
                entry = {
                    "name": posixpath.basename(r["path"]),
                    "path": r["path"],
                    "is_dir": False,
                    "inode": int(r["inode"] or 0),
                }
                if r["ads_stream"]:
                    entry["ads_stream"] = r["ads_stream"]
            entry["source_snap"] = r["snap_id"]
            out.append({"id": r["id"], "part_idx": r["part_idx"], "snap_id": r["snap_id"], "tag": r["tag"],
                        "note": r["note"], "created_utc": r["created_utc"], "entry": entry})
        return out

    def tags(self) -> List[str]:
        with self._lock:
            if self._closed:
                return sorted(DEFAULT_TAGS, key=str.lower)
            used = [r["tag"] for r in self.conn.execute("SELECT DISTINCT tag FROM bookmarks WHERE tag != ''")]
        return sorted(set(used) | set(DEFAULT_TAGS), key=str.lower)

    # -- export log & image hashes -------------------------------------------
    def log_export(self, part_idx: int, snap_id: str, dest_dir: str, manifest_path: str,
                   total: int, success: int, cancelled: bool):
        digest = ""
        if manifest_path and os.path.isfile(host_path(manifest_path)):
            digest = file_sha256(host_path(manifest_path))
        with self._lock:
            if self._closed:
                return
            with self.conn:
                self.conn.execute(
                    """INSERT INTO exports (time_utc, part_idx, snap_id, dest_dir, manifest_path, manifest_sha256,
                       items_total, items_success, cancelled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (int(time.time()), part_idx, snap_id, dest_dir, manifest_path, digest, total, success, int(cancelled)),
                )

    def list_exports(self) -> List[Dict[str, Any]]:
        with self._lock:
            if self._closed:
                return []
            return [dict(r) for r in self.conn.execute("SELECT * FROM exports ORDER BY time_utc")]

    def log_image_hash(self, result: Dict[str, Any]):
        with self._lock:
            if self._closed:
                return
            with self.conn:
                self.conn.execute(
                    """INSERT INTO image_hashes (time_utc, md5, sha1, sha256, bytes_hashed, media_size, stored_json, verification)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (int(time.time()), result.get("md5"), result.get("sha1"), result.get("sha256"),
                     result.get("bytes_hashed"), result.get("media_size"),
                     json.dumps(result.get("stored", {})), result.get("verification", "")),
                )

    def latest_image_hash(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if self._closed:
                return None
            r = self.conn.execute("SELECT * FROM image_hashes ORDER BY id DESC LIMIT 1").fetchone()
        return dict(r) if r else None

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self.conn.close()
            except Exception:
                pass
        if self._temp_dir:
            shutil.rmtree(self._temp_dir, ignore_errors=True)


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class PartitionModel:
    def __init__(self, index: int, description: str, start_offset: int, size: int, fs_type: str):
        self.index = index
        self.description = description
        self.start_offset = start_offset
        self.size = size
        self.fs_type = fs_type
        self.bitlocker_info = BitLockerInfo()
        self.snapshots: List[Dict[str, Any]] = []


class ForensicSession:
    """
    Two-Tier Cached Forensic Session:
    - L1 Cache: In-memory `self.directory_cache`
    - L2 Cache: Persistent disk-backed `self.index_db` (SQLite3 WAL)
    """
    _SESSION_COUNTER = 0
    _COUNTER_LOCK = threading.Lock()
    EWF_EXTENSIONS = {".e01", ".ex01", ".s01", ".l01"}

    def __init__(
        self,
        image_path: str,
        is_demo: bool = False,
        auto_scan: bool = True,
        custom_db_path: Optional[str] = None,
    ):
        with ForensicSession._COUNTER_LOCK:
            ForensicSession._SESSION_COUNTER += 1
            self.session_token: int = ForensicSession._SESSION_COUNTER

        self.image_path = image_path if (is_demo or is_physical_device_path(image_path)) else os.path.abspath(image_path)
        self.is_demo = is_demo
        self.custom_db_path = custom_db_path
        self._closed = False
        # FIX (2026-11-03): cooperative I/O abort. Once set, every image read returns
        # b"", so a long TSK call (e.g. a huge folder or $OrphanFiles) fails fast and
        # teardown/close no longer blocks the GUI until it finishes on its own.
        self._abort = False
        self._raw_lock = threading.RLock()
        self._cache_lock = threading.RLock()
        self._mount_lock = threading.RLock()

        self.media = None  # _MediaBackend (FEATURE 2026-11-04)
        self.media_size = 0
        self.partitions: List[PartitionModel] = []
        self.index_db: Optional[SnapshotIndexDB] = None

        self._vshadow_cache: Dict[int, Tuple[Any, Any, threading.RLock]] = {}
        self._fs_cache: Dict[Tuple[int, str], Tuple[Any, threading.RLock, Any]] = {}
        self.directory_cache: Dict[Tuple[int, str, str], List[Dict[str, Any]]] = {}
        self._demo_backing_store: Dict[Tuple[int, str, str], List[Dict[str, Any]]] = {}

        self._root_inode_cache: Dict[Tuple[int, str], Optional[int]] = {}

        if self.is_demo:
            self._init_demo_session()
        elif auto_scan:
            try:
                self.open_and_scan_real_image()
            except Exception:
                self.close()
                raise

    def request_abort(self):
        """Make all further image reads return b"" so in-flight workers stop quickly."""
        self._abort = True

    @property
    def is_aborting(self) -> bool:
        return self._abort or self._closed

    @staticmethod
    def _is_ewf_path(path: str) -> bool:
        ext = os.path.splitext(path)[1].lower()
        # Accept any numbered/lettered EWF segment (.E02, .Ex02, .S02, .L02, .EAA ...).
        return ext in ForensicSession.EWF_EXTENSIONS or EWF_SEG_EXT_RE.fullmatch(ext) is not None

    def _init_demo_session(self):
        self.media_size = 300 * 1024 * 1024 * 1024
        p0_size = 250 * 1024 * 1024 * 1024
        p1_size = 50 * 1024 * 1024 * 1024

        self.index_db = SnapshotIndexDB(
            self.image_path, self.media_size, is_demo=True, custom_db_path=self.custom_db_path
        )

        pm0 = PartitionModel(0, "OS Primary Volume (NTFS 4Kn)", 1048576, p0_size, "NTFS")
        pm0.bitlocker_info.is_encrypted = True
        pm0.bitlocker_info.is_unlocked = True
        pm0.bitlocker_info.volume_id = "{DEMO-8A4F-49B1-9C2E-7D01B4300E11}"
        pm0.bitlocker_info.encryption_method_name = "XTS-AES 128-bit"
        pm0.bitlocker_info.volume_size = pm0.size
        pm0.bitlocker_info.creation_time = "2026-01-15 08:30:00 UTC"
        pm0.bitlocker_info.description = "CORP-WKS-042 OS Volume"
        pm0.bitlocker_info.key_protectors = [
            KeyProtectorInfo(0, "TPM", 0x0100, "{42A1B300-11E9-4F00-8C12-00155D010203}"),
            KeyProtectorInfo(1, "Recovery Password", 0x0800, "{9F88C210-33A1-4D88-B901-00155D010204}"),
            KeyProtectorInfo(2, "Password", 0x2000, "{7C11D400-52B0-4E11-A442-00155D010205}"),
        ]

        pm1 = PartitionModel(1, "Encrypted Data Vault (NTFS)", p0_size + 1048576, p1_size, "NTFS")
        pm1.bitlocker_info.is_encrypted = True
        pm1.bitlocker_info.is_unlocked = False
        pm1.bitlocker_info.volume_id = "{DEMO-VAULT-77C2-41A0-B819-00155D998877}"
        pm1.bitlocker_info.encryption_method_name = "AES-CBC 256-bit with Diffuser"
        pm1.bitlocker_info.volume_size = pm1.size
        pm1.bitlocker_info.creation_time = "2026-02-10 14:12:00 UTC"
        pm1.bitlocker_info.description = "FINANCE-CONFIDENTIAL-VAULT"
        pm1.bitlocker_info.key_protectors = [
            KeyProtectorInfo(0, "Password", 0x2000, "{11223344-5566-7788-99AA-BBCCDDEEFF00}"),
            KeyProtectorInfo(1, "Recovery Password", 0x0800, "{AABBCCDD-EEFF-0011-2233-445566778899}"),
        ]

        base_utc = 1774864800  # 2026-03-30 10:00:00 UTC
        pm0.snapshots = [
            {"id": "Live", "vss_index": None, "creation_utc": None, "label": "Main Volume (Live State)"},
            {"id": "VSS_0", "vss_index": 0, "creation_utc": base_utc - 172800, "label": "VSS #1"},
            {"id": "VSS_1", "vss_index": 1, "creation_utc": base_utc - 86400, "label": "VSS #2"},
            {"id": "VSS_2", "vss_index": 2, "creation_utc": base_utc, "label": "VSS #3"},
        ]
        pm1.snapshots = [
            {"id": "Live", "vss_index": None, "creation_utc": None, "label": "Main Volume (Live State)"},
            {"id": "VSS_0", "vss_index": 0, "creation_utc": base_utc - 43200, "label": "VSS #1"},
        ]
        self.partitions = [pm0, pm1]
        self._build_demo_backing_store(base_utc)

        if not self.index_db.is_directory_cached(0, "Live", "/"):
            self._seed_demo_directories_to_sqlite()

    def _build_demo_backing_store(self, base_utc: int):
        t_offsets = {"VSS_0": -172800, "VSS_1": -86400, "VSS_2": -3600, "Live": 0}
        for snap in self.partitions[0].snapshots:
            sid = snap["id"]
            t_offset = t_offsets.get(sid, -172800)

            root_entries = [
                {"name": "Windows", "path": "/Windows", "is_dir": True, "is_deleted": False, "size": 0, "mtime": base_utc - 900000, "ctime": base_utc - 900000, "crtime": base_utc - 1800000, "atime": base_utc, "inode": 101, "ads": []},
                {"name": "Users", "path": "/Users", "is_dir": True, "is_deleted": False, "size": 0, "mtime": base_utc - 40000, "ctime": base_utc - 40000, "crtime": base_utc - 1800000, "atime": base_utc, "inode": 102, "ads": []},
                {"name": "Program Files", "path": "/Program Files", "is_dir": True, "is_deleted": False, "size": 0, "mtime": base_utc - 600000, "ctime": base_utc - 600000, "crtime": base_utc - 1800000, "atime": base_utc, "inode": 103, "ads": []},
                {"name": "$MFT", "path": "/$MFT", "is_dir": False, "is_deleted": False, "size": 268435456, "mtime": base_utc + t_offset, "ctime": base_utc + t_offset, "crtime": base_utc - 1800000, "atime": base_utc, "inode": 0, "ads": []},
                {"name": "hiberfil.sys", "path": "/hiberfil.sys", "is_dir": False, "is_deleted": False, "size": 40 * 1024 * 1024 * 1024, "mtime": base_utc + t_offset, "ctime": base_utc + t_offset, "crtime": base_utc - 86400, "atime": base_utc, "inode": 16, "ads": []},
            ]
            users_entries = [
                {"name": "Administrator", "path": "/Users/Administrator", "is_dir": True, "is_deleted": False, "size": 0, "mtime": base_utc - 120000, "ctime": base_utc - 120000, "crtime": base_utc - 1000000, "atime": base_utc, "inode": 201, "ads": []},
                {"name": "Analyst", "path": "/Users/Analyst", "is_dir": True, "is_deleted": False, "size": 0, "mtime": base_utc - 5000, "ctime": base_utc - 5000, "crtime": base_utc - 800000, "atime": base_utc, "inode": 202, "ads": []},
            ]
            analyst_entries = [
                {"name": "Documents", "path": "/Users/Analyst/Documents", "is_dir": True, "is_deleted": False, "size": 0, "mtime": base_utc - 3600, "ctime": base_utc - 3600, "crtime": base_utc - 700000, "atime": base_utc, "inode": 301, "ads": []},
                {"name": "NTUSER.DAT", "path": "/Users/Analyst/NTUSER.DAT", "is_dir": False, "is_deleted": False, "size": 2097152 + (0 if sid == "VSS_0" else 65536), "mtime": base_utc + t_offset, "ctime": base_utc + t_offset, "crtime": base_utc - 800000, "atime": base_utc, "inode": 306, "ads": []},
                {"name": "financial_audit_2026.xlsx", "path": "/Users/Analyst/financial_audit_2026.xlsx", "is_dir": False, "is_deleted": False, "size": 482900 if sid != "Live" else 519400, "mtime": base_utc + t_offset, "ctime": base_utc + t_offset, "crtime": base_utc - 400000, "atime": base_utc, "inode": 307, "ads": [{"name": "Zone.Identifier", "size": 142, "id": None}]},
            ]
            docs_entries = [
                {"name": "incident_notes.txt", "path": "/Users/Analyst/Documents/incident_notes.txt", "is_dir": False, "is_deleted": False, "size": 8192, "mtime": base_utc + t_offset, "ctime": base_utc + t_offset, "crtime": base_utc - 300000, "atime": base_utc, "inode": 350, "ads": []},
            ]
            if sid in ("VSS_2", "Live"):
                analyst_entries.append({
                    "name": "stage2_beacon.ps1",
                    "path": "/Users/Analyst/stage2_beacon.ps1",
                    "is_dir": False,
                    "is_deleted": False,
                    "size": 14208,
                    "mtime": base_utc - 999999,
                    "ctime": base_utc - 1200,
                    "crtime": base_utc - 999999,
                    "atime": base_utc,
                    "inode": 309,
                    "ads": [{"name": "Zone.Identifier", "size": 218, "id": None},
                            {"name": "hidden_config.bin", "size": 4096, "id": None}],
                })
            if sid == "VSS_0":
                analyst_entries.append({
                    "name": "exfil_staging.zip",
                    "path": "/Users/Analyst/exfil_staging.zip",
                    "is_dir": False,
                    "is_deleted": False,
                    "size": 18450944,
                    "mtime": base_utc - 175000,
                    "ctime": base_utc - 175000,
                    "crtime": base_utc - 180000,
                    "atime": base_utc - 175000,
                    "inode": 310,
                    "ads": [],
                })
            else:
                analyst_entries.append({
                    "name": "exfil_staging.zip",
                    "path": "/Users/Analyst/exfil_staging.zip",
                    "is_dir": False,
                    "is_deleted": True,
                    "size": 18450944,
                    "mtime": base_utc - 175000,
                    "ctime": base_utc - 150000,
                    "crtime": base_utc - 180000,
                    "atime": base_utc - 175000,
                    "inode": 310,
                    "ads": [],
                })

            win_entries = [
                {"name": "System32", "path": "/Windows/System32", "is_dir": True, "is_deleted": False, "size": 0, "mtime": base_utc - 500000, "ctime": base_utc - 500000, "crtime": base_utc - 1800000, "atime": base_utc, "inode": 401, "ads": []},
                {"name": "explorer.exe", "path": "/Windows/explorer.exe", "is_dir": False, "is_deleted": False, "size": 4892160, "mtime": base_utc - 500000, "ctime": base_utc - 500000, "crtime": base_utc - 1800000, "atime": base_utc, "inode": 402, "ads": []},
            ]

            for path_key, items in [
                ("/", root_entries),
                ("/Users", users_entries),
                ("/Users/Analyst", analyst_entries),
                ("/Users/Analyst/Documents", docs_entries),
                ("/Users/Administrator", []),
                ("/Windows", win_entries),
                ("/Windows/System32", []),
                ("/Program Files", []),
            ]:
                items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
                self._demo_backing_store[(0, sid, path_key)] = items

        for snap in self.partitions[1].snapshots:
            sid = snap["id"]
            vault_root = [
                {"name": "Executive_Board_Minutes", "path": "/Executive_Board_Minutes", "is_dir": True, "is_deleted": False, "size": 0, "mtime": base_utc - 20000, "ctime": base_utc - 20000, "crtime": base_utc - 500000, "atime": base_utc, "inode": 501, "ads": []},
                {"name": "M_and_A_Valuation_2026.pdf", "path": "/M_and_A_Valuation_2026.pdf", "is_dir": False, "is_deleted": False, "size": 6420480, "mtime": base_utc - 10000, "ctime": base_utc - 10000, "crtime": base_utc - 200000, "atime": base_utc, "inode": 502, "ads": []},
            ]
            self._demo_backing_store[(1, sid, "/")] = vault_root
            self._demo_backing_store[(1, sid, "/Executive_Board_Minutes")] = []

    def _seed_demo_directories_to_sqlite(self):
        if not self.index_db:
            return
        for (part_idx, sid, path_key), items in self._demo_backing_store.items():
            if 0 <= part_idx < len(self.partitions):
                pm = self.partitions[part_idx]
                if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
                    continue
            self.index_db.insert_directory_batch(part_idx, sid, path_key, items)

    def open_and_scan_real_image(self, status_cb=None, progress_cb=None):
        """Fixed P1-01: Raises an explicit RuntimeError if an E01/EWF file is opened without pyewf."""
        if not is_physical_device_path(self.image_path) and not os.path.exists(self.image_path):
            raise FileNotFoundError(f"Forensic image not found: {self.image_path}")

        if status_cb:
            status_cb("🔍 Opening forensic disk container...")

        with self._raw_lock:
            kind = detect_media_kind(self.image_path)
            if status_cb:
                status_cb(f"🔍 Opening {kind.replace('_', ' ')} container...")
            self.media = open_media_backend(self.image_path)
            self.media_size = self.media.media_size
            if status_cb and len(self.media.segment_paths) > 1:
                status_cb(f"🔍 Loaded {len(self.media.segment_paths)} image segment/chain file(s)...")

        # A physical drive (possibly a live system disk) can change under us, so its
        # listings are never kept in the persistent cache.
        self.index_db = SnapshotIndexDB(
            self.image_path, self.media_size, is_demo=False, custom_db_path=self.custom_db_path,
            segment_paths=self.media.segment_paths, ephemeral=(self.media.kind == "device"),
        )
        self._scan_partitions(status_cb=status_cb, progress_cb=progress_cb)

    def read_raw(self, offset: int, size: int) -> bytes:
        with self._raw_lock:
            if self._closed or self._abort or self.is_demo:
                return b""
            # TSK probes offsets past the end of the media; seeking there can raise in libewf.
            if offset < 0 or size <= 0 or offset >= self.media_size:
                return b""
            size = min(size, self.media_size - offset)
            if self.media is not None:
                return self.media.read(offset, size)
            return b""

    def _scan_partitions(self, status_cb=None, progress_cb=None):
        """
        Fixed P1-04, P2-02 & P3-01:
        - Skips TSK_VS_PART_FLAG_META table descriptors.
        - Assigns `slot_idx = len(discovered)` so `pm.index` always matches `self.partitions[slot_idx]` 1-to-1.
        - Falls back to single-partition probing whenever `discovered` is empty.
        """
        if not TSK_AVAILABLE:
            pm = PartitionModel(0, "Raw Disk Volume", 0, self.media_size, "RAW")
            pm.snapshots = [{"id": "Live", "vss_index": None, "creation_utc": None, "label": "Main Volume"}]
            self.partitions = [pm]
            return

        base_tsk_img = ThreadSafeCallableImgInfo(self.read_raw, self.media_size, [self])
        discovered: List[PartitionModel] = []
        meta_flag = getattr(pytsk3, "TSK_VS_PART_FLAG_META", 4)

        try:
            vol_info = pytsk3.Volume_Info(base_tsk_img)
            sector_size = getattr(vol_info.info, "block_size", 512) or 512
            parts_list = list(vol_info)
            total_parts = max(1, len(parts_list))
            for hw_idx, part in enumerate(parts_list):
                if self._abort:
                    raise InterruptedError("Image scan cancelled")
                if progress_cb:
                    progress_cb(hw_idx + 1, total_parts)
                p_flags = getattr(part, "flags", 0) or 0
                if p_flags & meta_flag:
                    continue
                start_offset = part.start * sector_size
                size_bytes = part.len * sector_size
                if size_bytes <= 0:
                    continue
                slot_idx = len(discovered)
                raw_desc = part.desc.decode("utf-8", errors="replace") if part.desc else f"Volume {hw_idx}"
                if status_cb:
                    status_cb(f"🔍 Inspecting Partition {slot_idx + 1}: {raw_desc}...")
                pm = self._inspect_partition_slice(slot_idx, raw_desc, start_offset, size_bytes, base_tsk_img, status_cb)
                discovered.append(pm)
        except InterruptedError:
            raise
        except Exception as e:
            logger.debug(f"Volume table scan fallback triggered: {e}")

        if self._abort:
            raise InterruptedError("Image scan cancelled")
        if not discovered:
            offsets_to_try = [0, 512, 1024, 2048 * 512, 63 * 512]
            for i, off in enumerate(offsets_to_try):
                if off >= self.media_size:
                    continue
                if progress_cb:
                    progress_cb(i + 1, len(offsets_to_try))
                slot_idx = len(discovered)
                pm = self._inspect_partition_slice(
                    slot_idx, f"Single Partition at offset {off}", off, self.media_size - off, base_tsk_img, status_cb
                )
                if pm.fs_type not in ("Unrecognized", "Unknown") or pm.bitlocker_info.is_encrypted:
                    discovered.append(pm)
                    break

        if not discovered:
            pm = PartitionModel(0, "Raw Disk Image", 0, self.media_size, "Raw/Unknown")
            pm.snapshots = [{"id": "Live", "vss_index": None, "creation_utc": None, "label": "Main Volume"}]
            discovered.append(pm)

        self.partitions = discovered

    def _inspect_partition_slice(
        self, idx: int, desc: str, start_offset: int, size_bytes: int, base_tsk_img, status_cb=None
    ) -> PartitionModel:
        is_bde = BitLockerAnalyzer.detect_bitlocker(self.read_raw, start_offset)
        fs_type = "BitLocker" if is_bde else "Unknown"

        if not is_bde and TSK_AVAILABLE:
            try:
                fs_info = pytsk3.FS_Info(base_tsk_img, offset=start_offset)
                fs_type = tsk_fs_type_name(fs_info.info.ftype)
            except Exception:
                fs_type = "Unrecognized"

        pm = PartitionModel(idx, desc, start_offset, size_bytes, fs_type)
        if is_bde:
            if status_cb:
                status_cb(f"🔒 Analyzing BitLocker metadata on Partition {idx}...")
            pm.bitlocker_info = BitLockerAnalyzer.analyze_bitlocker_volume(self.read_raw, start_offset, size_bytes)
            if pm.bitlocker_info.is_unlocked:
                self.finalize_unlock(pm)
                return pm

        self.refresh_partition_snapshots(pm, status_cb=status_cb)
        return pm

    def refresh_partition_snapshots(self, pm: PartitionModel, status_cb=None):
        if self.is_demo:
            return
        pm.snapshots = [{"id": "Live", "vss_index": None, "creation_utc": None, "label": "Main Volume (Live State)"}]
        if not PYVSHADOW_AVAILABLE:
            return
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            return
        if not pm.bitlocker_info.is_encrypted and pm.fs_type != "NTFS":
            return

        try:
            if status_cb:
                status_cb(f"📂 Enumerating Volume Shadow Copies on Partition {pm.index}...")
            vshadow_vol, _, v_lock = self._get_or_open_vshadow(pm)
            with v_lock:
                num_stores = vshadow_vol.get_number_of_stores()
                for s_idx in range(num_stores):
                    store = vshadow_vol.get_store(s_idx)
                    c_epoch = self._extract_vss_utc_epoch(store)
                    pm.snapshots.append({
                        "id": f"VSS_{s_idx}",
                        "vss_index": s_idx,
                        "creation_utc": c_epoch,
                        "label": f"VSS #{s_idx + 1}",
                    })
        except Exception as e:
            logger.debug(f"VSS detection warning on P{pm.index}: {e}")

    @staticmethod
    def _extract_vss_utc_epoch(store) -> Optional[int]:
        try:
            if hasattr(store, "get_creation_time_as_datetime"):
                return coerce_forensic_epoch(store.get_creation_time_as_datetime())
            return coerce_forensic_epoch(store.get_creation_time())
        except Exception:
            return None

    def _get_partition_read_stream(self, pm: PartitionModel) -> Tuple[Any, int, int, List[Any]]:
        if pm.bitlocker_info.is_encrypted and pm.bitlocker_info.is_unlocked and pm.bitlocker_info.bde_volume:
            bde_lock = pm.bitlocker_info.bde_lock
            bde_vol = pm.bitlocker_info.bde_volume

            def read_bde(offset: int, size: int) -> bytes:
                with bde_lock:
                    if self._closed or self._abort:
                        return b""
                    bde_vol.seek_offset(offset, os.SEEK_SET)
                    return bde_vol.read_buffer(size)

            return read_bde, 0, bde_vol.get_size(), [pm, bde_vol, pm.bitlocker_info.bde_stream]
        return self.read_raw, pm.start_offset, pm.size, [self, pm]

    def _get_or_open_vshadow(self, pm: PartitionModel):
        with self._mount_lock:
            if pm.index in self._vshadow_cache:
                return self._vshadow_cache[pm.index]
            read_fn, offset, size, _ = self._get_partition_read_stream(pm)
            sliced = SlicedStreamAdapter(read_fn, offset, size)
            vshadow_vol = pyvshadow.volume()
            vshadow_vol.open_file_object(sliced)
            v_lock = threading.RLock()
            self._vshadow_cache[pm.index] = (vshadow_vol, sliced, v_lock)
            return self._vshadow_cache[pm.index]

    def get_or_mount_fs(self, part_idx: int, snap_id: str) -> Tuple[Any, Optional[threading.RLock]]:
        if self._closed or self.is_demo or not TSK_AVAILABLE:
            return None, None
        if part_idx < 0 or part_idx >= len(self.partitions):
            raise IndexError(f"Partition index out of range: {part_idx}")

        key = (part_idx, snap_id)
        with self._mount_lock:
            pm = self.partitions[part_idx]
            if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
                raise PermissionError(f"Partition P{part_idx} is BitLocker locked")
            if key in self._fs_cache:
                fs_info, fs_lock, _tsk_img = self._fs_cache[key]
                return fs_info, fs_lock
            snap_meta = next((s for s in pm.snapshots if s["id"] == snap_id), None)
            if snap_meta is None:
                raise ValueError(f"Unknown snapshot ID '{snap_id}' on partition {part_idx}")

            vss_idx = snap_meta["vss_index"]
            fs_lock = threading.RLock()

            if vss_idx is None:
                read_fn, offset, size, refs = self._get_partition_read_stream(pm)
                tsk_img = ThreadSafeCallableImgInfo(read_fn, offset + size, refs)
                fs_info = pytsk3.FS_Info(tsk_img, offset=offset)
            else:
                vshadow_vol, sliced, v_lock = self._get_or_open_vshadow(pm)
                store = vshadow_vol.get_store(vss_idx)

                def read_store(offset: int, size: int) -> bytes:
                    with v_lock:
                        if self._closed or self._abort:
                            return b""
                        store.seek(offset)
                        return store.read(size)

                tsk_img = ThreadSafeCallableImgInfo(
                    read_store, store.get_size(), [self, pm, vshadow_vol, sliced, store]
                )
                fs_info = pytsk3.FS_Info(tsk_img, offset=0)

            self._fs_cache[key] = (fs_info, fs_lock, tsk_img)
            return fs_info, fs_lock

    def finalize_unlock(self, pm: PartitionModel):
        """After a BitLocker unlock: identify the filesystem inside the volume (pm.fs_type used to stay
        'BitLocker' forever) and enumerate its shadow copies."""
        if not self.is_demo and TSK_AVAILABLE and pm.bitlocker_info.is_unlocked and pm.bitlocker_info.bde_volume:
            try:
                read_fn, offset, size, refs = self._get_partition_read_stream(pm)
                tsk_img = ThreadSafeCallableImgInfo(read_fn, offset + size, refs)
                fs_info = pytsk3.FS_Info(tsk_img, offset=offset)
                pm.fs_type = tsk_fs_type_name(fs_info.info.ftype)
            except Exception as e:
                logger.warning(f"Could not identify filesystem inside unlocked BitLocker volume P{pm.index}: {e}")
                pm.fs_type = "Unrecognized"
            # A previously cached filesystem handle / vshadow handle for this partition is stale now.
            with self._mount_lock:
                for key in [k for k in self._fs_cache if k[0] == pm.index]:
                    self._fs_cache.pop(key, None)
                self._vshadow_cache.pop(pm.index, None)
        elif self.is_demo and pm.bitlocker_info.is_unlocked and self.index_db:
            for (part_idx, sid, path_key), items in self._demo_backing_store.items():
                if part_idx == pm.index:
                    self.index_db.insert_directory_batch(part_idx, sid, path_key, items)
        self.refresh_partition_snapshots(pm)

    def get_root_inode(self, part_idx: int, snap_id: str) -> Optional[int]:
        """Real root-directory inode of the mounted filesystem (NTFS 5, ext 2, FAT 2, ...). The old
        code hard-coded 5, which on other filesystems could make an unrelated directory look
        'already visited' and silently drop it from the snapshot index and exports."""
        key = (part_idx, snap_id)
        with self._mount_lock:
            if key in self._root_inode_cache:
                return self._root_inode_cache[key]
        root: Optional[int] = None
        if not self.is_demo and TSK_AVAILABLE:
            try:
                fs_info, _lock = self.get_or_mount_fs(part_idx, snap_id)
                if fs_info is not None:
                    root = int(fs_info.info.root_inum)
            except Exception as e:
                logger.debug(f"root inode lookup failed for P{part_idx} {snap_id}: {e}")
        if root is not None or self.is_demo:
            with self._mount_lock:
                self._root_inode_cache[key] = root
        return root

    def _remember_directory(self, cache_key: Tuple[int, str, str], entries: List[Dict[str, Any]]):
        with self._cache_lock:
            if cache_key not in self.directory_cache and len(self.directory_cache) >= 256:
                self.directory_cache.pop(next(iter(self.directory_cache)), None)
            self.directory_cache[cache_key] = entries

    def get_known_child_dir_count(self, part_idx: int, snap_id: str, path: str) -> Optional[int]:
        norm_path = normalize_forensic_path(path)
        cache_key = (part_idx, snap_id, norm_path)
        with self._cache_lock:
            if cache_key in self.directory_cache:
                return sum(1 for e in self.directory_cache[cache_key] if e.get("is_dir"))
        if self.index_db:
            return self.index_db.get_cached_child_dir_count(part_idx, snap_id, norm_path)
        return None

    @staticmethod
    def needs_inode_open(dir_entry: Optional[Dict[str, Any]]) -> bool:
        """True when a folder must be opened by inode instead of by path.

        FIX (2026-11-03): TSK resolves a path to the ALLOCATED entry when a live and
        a deleted folder share a name, so a deleted folder opened by path showed (and
        exported) the live folder's contents under the deleted folder's name. Deleted
        folders, and anything listed from inside one ("via_inode"), are opened by inode.
        """
        if not dir_entry or not dir_entry.get("inode"):
            return False
        return bool(dir_entry.get("is_deleted") or dir_entry.get("via_inode"))

    def list_directory_sync(
        self, part_idx: int, snap_id: str, path: str, dir_entry: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        if self.is_aborting:
            raise RuntimeError(f"Directory read aborted: {path}")
        if part_idx < 0 or part_idx >= len(self.partitions):
            raise IndexError(f"Partition index out of range: {part_idx}")
        pm = self.partitions[part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            raise PermissionError(f"Partition P{part_idx} is BitLocker locked")
        if dir_entry and dir_entry.get("meta_realloc"):
            raise RuntimeError(
                f"'{dir_entry.get('name')}' is a deleted name whose inode {dir_entry.get('inode')} now "
                "belongs to a newer file/folder; its original contents cannot be listed."
            )
        norm_path = normalize_forensic_path(path)
        cache_key = (part_idx, snap_id, norm_path)
        by_inode = (
            int(dir_entry["inode"])
            if not self.is_demo and self.needs_inode_open(dir_entry)
            else None
        )

        # Listings opened by inode are never cached: the caches are keyed by path, and
        # a deleted folder's path can be identical to a live folder's.
        if by_inode is None:
            with self._cache_lock:
                if cache_key in self.directory_cache:
                    return self.directory_cache[cache_key]

            if self.index_db and self.index_db.is_directory_cached(part_idx, snap_id, norm_path):
                sql_entries = self.index_db.get_directory_children(part_idx, snap_id, norm_path)
                if sql_entries is not None:
                    self._remember_directory(cache_key, sql_entries)
                    return sql_entries
                # cache unreadable -> fall through and read the real filesystem

            if self.is_demo:
                if cache_key not in self._demo_backing_store:
                    raise FileNotFoundError(f"Path not found in demo snapshot: {norm_path}")
                demo_entries = list(self._demo_backing_store[cache_key])
                if self.index_db:
                    self.index_db.insert_directory_batch(part_idx, snap_id, norm_path, demo_entries)
                self._remember_directory(cache_key, demo_entries)
                return demo_entries

        fs_info, fs_lock = self.get_or_mount_fs(part_idx, snap_id)
        if fs_info is None or fs_lock is None:
            raise RuntimeError(f"Cannot mount filesystem for P{part_idx} {snap_id}: {norm_path}")

        entries: List[Dict[str, Any]] = []
        with fs_lock:
            if self._closed or self._abort:
                raise RuntimeError(f"Directory read aborted: {norm_path}")
            d_obj = fs_info.open_dir(inode=by_inode) if by_inode is not None else fs_info.open_dir(path=norm_path)
            unalloc_flag = getattr(pytsk3, "TSK_FS_NAME_FLAG_UNALLOC", 2)
            meta_unalloc_flag = getattr(pytsk3, "TSK_FS_META_FLAG_UNALLOC", 2)
            meta_alloc_flag = getattr(pytsk3, "TSK_FS_META_FLAG_ALLOC", 1)
            dir_types = (
                getattr(pytsk3, "TSK_FS_META_TYPE_DIR", 2),
                getattr(pytsk3, "TSK_FS_META_TYPE_VIRT_DIR", 11),  # TSK's virtual $OrphanFiles folder
            )
            try:
                is_ntfs = fs_info.info.ftype == pytsk3.TSK_FS_TYPE_NTFS
            except Exception:
                is_ntfs = False
            for entry in d_obj:
                raw_name = entry.info.name.name
                if isinstance(raw_name, str):
                    name = raw_name
                else:
                    name = raw_name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                meta = entry.info.meta
                name_flags = getattr(entry.info.name, "flags", 0) or 0
                name_unalloc = bool(name_flags & unalloc_flag)
                full_path = normalize_forensic_path(posixpath.join(norm_path, name))
                if not meta:
                    # A directory-entry name whose inode/metadata is gone (typical for deleted names).
                    # Dropping it silently would hide evidence, so list it with unknown metadata.
                    entries.append({
                        "name": name,
                        "path": full_path,
                        "is_dir": False,
                        "is_deleted": name_unalloc,
                        "size": 0,
                        "mtime": None, "ctime": None, "crtime": None, "atime": None,
                        "inode": int(getattr(entry.info.name, "meta_addr", 0) or 0),
                        "ads": [],
                        "meta_realloc": False,
                        "via_inode": by_inode is not None,
                    })
                    continue
                is_dir = meta.type in dir_types
                meta_flags = getattr(meta, "flags", 0) or 0
                is_deleted = bool(name_unalloc or (meta_flags & meta_unalloc_flag))
                # FIX (2026-11-03): a deleted name whose inode is allocated again (or whose
                # NTFS sequence number no longer matches) now describes a DIFFERENT, newer
                # file. Size, timestamps and content come from that file, so the entry
                # is flagged instead of being presented as the deleted file.
                name_seq = getattr(entry.info.name, "meta_seq", None)
                meta_seq = getattr(meta, "seq", None)
                meta_realloc = bool(
                    name_unalloc and (
                        (meta_flags & meta_alloc_flag)
                        or (name_seq is not None and meta_seq is not None and int(name_seq) != int(meta_seq))
                    )
                )
                entries.append({
                    "name": name,
                    "path": full_path,
                    "is_dir": is_dir,
                    "is_deleted": is_deleted,
                    "size": max(0, int(meta.size)) if meta.size else 0,
                    "mtime": coerce_tsk_epoch(meta.mtime),
                    "ctime": coerce_tsk_epoch(meta.ctime),
                    "crtime": coerce_tsk_epoch(meta.crtime),
                    "atime": coerce_tsk_epoch(meta.atime),
                    "inode": int(meta.addr) if meta.addr is not None else 0,
                    # FEATURE (2026-11-04): named data streams. Not collected for a reallocated
                    # inode: those streams belong to the newer file.
                    "ads": self._enumerate_streams(entry) if (is_ntfs and not meta_realloc) else [],
                    "meta_realloc": meta_realloc,
                    "via_inode": by_inode is not None,
                })

        # FIX (2026-11-03): reads return b"" once an abort/close starts, which can make
        # TSK hand back a truncated listing without raising. Never cache or show that.
        if self._abort or self._closed:
            raise RuntimeError(f"Directory read aborted: {norm_path}")

        entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        if by_inode is not None:
            return entries
        if self.index_db:
            self.index_db.insert_directory_batch(part_idx, snap_id, norm_path, entries)
        self._remember_directory(cache_key, entries)
        return entries

    def invalidate_directory_cache(self, part_idx: int, snap_id: str, path: str):
        norm_path = normalize_forensic_path(path)
        with self._cache_lock:
            self.directory_cache.pop((part_idx, snap_id, norm_path), None)
        if self.index_db:
            self.index_db.invalidate_directory(part_idx, snap_id, norm_path)

    def clear_persistent_index(self):
        with self._cache_lock:
            self.directory_cache.clear()
        if self.index_db:
            self.index_db.clear_all()
        if self.is_demo:
            self._seed_demo_directories_to_sqlite()

    def read_file_slice(
        self, part_idx: int, snap_id: str, entry: Dict[str, Any], offset: int, size: int
    ) -> bytes:
        if self.is_aborting:
            return b""
        if part_idx < 0 or part_idx >= len(self.partitions):
            raise IndexError(f"Partition index out of range: {part_idx}")
        pm = self.partitions[part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            raise PermissionError(f"Partition P{part_idx} is BitLocker locked")
        file_size = max(0, int(entry.get("size", 0)))
        if offset >= file_size or size <= 0:
            return b""
        read_len = min(size, file_size - offset)

        if self.is_demo:
            if entry.get("ads_stream") == "Zone.Identifier":
                body = (
                    "[ZoneTransfer]\r\nZoneId=3\r\n"
                    "ReferrerUrl=https://mail.example-phish.test/inbox\r\n"
                    f"HostUrl=https://cdn.example-phish.test/{entry.get('ads_host', 'file')}\r\n"
                ).encode("ascii")
                body = body.ljust(file_size, b"\x00")[:file_size]
                return body[offset:offset + read_len]
            header = (
                f"=== VSCExplorer Forensic Artifact Stream ===\n"
                f"Path     : {entry['path']}\n"
                f"Stream   : {entry.get('ads_stream') or '$DATA'}\n"
                f"Inode    : {entry.get('inode', 0)}\n"
                f"Size     : {file_size} bytes\n"
                f"Modified : {entry.get('mtime', 0)}\n"
                f"============================================\n"
            ).encode("utf-8")
            # FEATURE (2026-11-04): table-based generator (the per-byte loop took
            # minutes for multi-MB demo files once whole-file hashing was added).
            key = entry.get("inode", 1) & 0xFF
            table = bytes((i ^ key) & 0xFF for i in range(256))
            out = bytearray()
            pos = offset
            end = offset + read_len
            if pos < len(header):
                out += header[pos:min(end, len(header))]
                pos = min(end, len(header))
            if pos < end:
                n = end - pos
                start = pos & 0xFF
                out += (table * ((start + n) // 256 + 1))[start:start + n]
            return bytes(out)

        fs_info, fs_lock = self.get_or_mount_fs(part_idx, snap_id)
        if not fs_info or not fs_lock:
            if self.is_aborting:
                return b""
            raise RuntimeError(f"Cannot mount filesystem for P{part_idx} {snap_id}: {entry.get('path')}")
        with fs_lock:
            if self.is_aborting:
                return b""
            raw_inode = entry.get("inode")
            inode = int(raw_inode) if raw_inode is not None else 0
            host_name = (entry.get("ads_host") or entry.get("name", "")).upper()
            has_inode = inode > 0 or (raw_inode is not None and inode == 0 and host_name == "$MFT")
            if not has_inode and entry.get("is_deleted"):
                raise FileNotFoundError(f"Deleted entry '{entry.get('name')}' has no associated inode")
            stream = entry.get("ads_stream")
            if stream is not None:
                # FEATURE (2026-11-04): read a named $DATA stream (ADS) of the host.
                f_obj = fs_info.open_meta(inode=inode) if has_inode else fs_info.open(path=entry["ads_host_path"])
                attr_id = entry.get("ads_attr_id")
                if attr_id is None:
                    attr_id = self._find_stream_attr_id(f_obj, stream)
                    if attr_id is None:
                        raise FileNotFoundError(f"Stream '{stream}' not found on inode {inode}")
                return f_obj.read_random(offset, read_len, NTFS_DATA_ATTR_TYPE, int(attr_id)) or b""
            f_obj = fs_info.open_meta(inode=inode) if has_inode else fs_info.open(path=entry["path"])
            return f_obj.read_random(offset, read_len) or b""

    @staticmethod
    def _find_stream_attr_id(f_obj, stream_name: str) -> Optional[int]:
        for attr in f_obj:
            if int(attr.info.type) == NTFS_DATA_ATTR_TYPE and attr.info.name:
                raw = attr.info.name
                name = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
                if name == stream_name:
                    return int(attr.info.id)
        return None

    @staticmethod
    def _enumerate_streams(tsk_file) -> List[Dict[str, Any]]:
        """Named $DATA attributes (ADS) of a pytsk3 File; [] on any error."""
        streams: List[Dict[str, Any]] = []
        try:
            for attr in tsk_file:
                if int(attr.info.type) != NTFS_DATA_ATTR_TYPE or not attr.info.name:
                    continue
                raw = attr.info.name
                name = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
                streams.append({"name": name, "size": max(0, int(attr.info.size)), "id": int(attr.info.id)})
        except Exception as e:
            logger.debug(f"ADS enumeration failed: {e}")
        return streams

    def close(self):
        if self._closed:
            return
        self._closed = True

        with self._mount_lock:
            for _k, (_fs_info, fs_lock, tsk_img) in list(self._fs_cache.items()):
                with fs_lock:
                    try:
                        tsk_img.close()
                    except Exception:
                        pass
            self._fs_cache.clear()

            # Do NOT call pyvshadow volume.close() here. Bisected live
            # (2026-11-02, vss.raw): vol.close() itself segfaults (exit 139)
            # when the volume was opened via open_file_object() with a
            # Python file-like adapter, even with no VSS filesystem mounted
            # — session creation alone (store enumeration) is enough to
            # trigger it. Exiting / GC without an explicit close is clean
            # (exit 0). So drop the references and let the interpreter
            # collect the volume instead of closing it explicitly.
            self._vshadow_cache.clear()

        for pm in self.partitions:
            if pm.bitlocker_info.bde_volume is not None:
                with pm.bitlocker_info.bde_lock:
                    try:
                        pm.bitlocker_info.bde_volume.close()
                    except Exception:
                        pass
                    pm.bitlocker_info.bde_volume = None

        with self._cache_lock:
            self.directory_cache.clear()

        if self.index_db:
            self.index_db.close()
            self.index_db = None

        with self._raw_lock:
            if self.media is not None:
                try:
                    self.media.close()
                except Exception:
                    pass
                self.media = None


# ============================================================================
# Section 5: Background Workers
# ============================================================================

class WorkerSignals(QObject):
    progress = Signal(int, int)
    status = Signal(str)
    session_ready = Signal(int, object)
    tree_children_ready = Signal(int, int, str, str, list)
    navigation_ready = Signal(int, int, int, str, str, list, list)
    metadata_ready = Signal(int, int, str)
    diff_ready = Signal(int, list)
    export_done = Signal(int, int, str, bool)
    error = Signal(str)
    warning = Signal(str)
    search_ready = Signal(int, int, list, bool)   # token, request id, rows, truncated
    indexed = Signal(int, str)                    # token, summary
    history_ready = Signal(int, int, list)        # token, request id, version rows
    image_hash_ready = Signal(int, object)        # token, result dict
    report_ready = Signal(int, object)            # token, report data
    finished = Signal()


class ImageOpenWorker(QRunnable):
    """FIX (2026-11-03): cancellable. The scan used to be uncancellable, so loading the
    demo or closing the window mid-scan froze the GUI in waitForDone() until the whole
    image had been scanned."""
    def __init__(self, image_path: str, req_id: int = 0):
        super().__init__()
        self.image_path = image_path
        self.req_id = req_id
        self.signals = WorkerSignals()
        self._cancelled = threading.Event()
        self._session_lock = threading.Lock()
        self._session: Optional[ForensicSession] = None

    def cancel(self):
        self._cancelled.set()
        with self._session_lock:
            if self._session is not None:
                self._session.request_abort()

    def run(self):
        session: Optional[ForensicSession] = None
        try:
            session = ForensicSession(self.image_path, is_demo=False, auto_scan=False)
            with self._session_lock:
                self._session = session
                if self._cancelled.is_set():
                    session.request_abort()
            session.open_and_scan_real_image(
                status_cb=self.signals.status.emit,
                progress_cb=self.signals.progress.emit,
            )
            if self._cancelled.is_set():
                raise InterruptedError("Image scan cancelled")
            self.signals.session_ready.emit(self.req_id, session)
            session = None
        except Exception as e:
            if session is not None:
                session.close()
            if self._cancelled.is_set():
                logger.info(f"Image open cancelled: {self.image_path}")
            else:
                logger.error(f"Error opening image {self.image_path}: {e}")
                self.signals.error.emit(f"Failed to open image: {e}")
        finally:
            with self._session_lock:
                self._session = None
            self.signals.finished.emit()


class DirectoryLoadWorker(QRunnable):
    def __init__(
        self,
        session: ForensicSession,
        part_idx: int,
        snap_id: str,
        path: str,
        tree_only: bool = False,
        nav_req_id: int = 0,
        dir_entry: Optional[Dict[str, Any]] = None,
        tree_key: Optional[str] = None,
    ):
        super().__init__()
        self.session = session
        self.token = session.session_token
        self.part_idx = part_idx
        self.snap_id = snap_id
        self.path = normalize_forensic_path(path)
        self.tree_only = tree_only
        self.nav_req_id = nav_req_id
        self.dir_entry = dir_entry
        self.tree_key = tree_key or self.path
        self.signals = WorkerSignals()

    def run(self):
        try:
            if self.tree_only:
                entries = self.session.list_directory_sync(
                    self.part_idx, self.snap_id, self.path, dir_entry=self.dir_entry
                )
                if self.session.is_aborting:
                    return
                self.signals.tree_children_ready.emit(
                    self.token, self.part_idx, self.snap_id, self.tree_key, entries
                )
                return

            # A deleted folder (or one inside a deleted folder) cannot be reached by
            # walking its path, so it is listed directly by inode.
            if ForensicSession.needs_inode_open(self.dir_entry):
                entries = self.session.list_directory_sync(
                    self.part_idx, self.snap_id, self.path, dir_entry=self.dir_entry
                )
                if self.session.is_aborting:
                    return
                self.signals.navigation_ready.emit(
                    self.token, self.nav_req_id, self.part_idx, self.snap_id,
                    self.path, entries, [],
                )
                return

            parts = [p for p in self.path.strip("/").split("/") if p]
            curr = "/"
            resolved_path = "/"
            resolved_entries = self.session.list_directory_sync(self.part_idx, self.snap_id, "/")
            if self.session.is_aborting:
                return
            ancestor_chain: List[Tuple[str, List[Dict[str, Any]]]] = [("/", resolved_entries)]

            for part_name in parts:
                if self.session.is_aborting:
                    return
                next_path = normalize_forensic_path(posixpath.join(curr, part_name))
                try:
                    entries = self.session.list_directory_sync(self.part_idx, self.snap_id, next_path)
                    ancestor_chain.append((next_path, entries))
                    curr = next_path
                    resolved_path = next_path
                    resolved_entries = entries
                except Exception:
                    if self.session.is_aborting:
                        return
                    self.signals.status.emit(
                        f"ℹ️ Folder '{next_path}' did not exist in {self.snap_id}; fell back to '{resolved_path}'."
                    )
                    break

            if self.session.is_aborting:
                return

            self.signals.navigation_ready.emit(
                self.token,
                self.nav_req_id,
                self.part_idx,
                self.snap_id,
                resolved_path,
                resolved_entries,
                ancestor_chain,
            )
        except Exception as e:
            if self.session.is_aborting:
                return  # session is being torn down; not a user-facing error
            logger.error(f"Error loading directory {self.path}: {e}")
            self.signals.error.emit(f"Failed to load directory {self.path}: {e}")
        finally:
            self.signals.finished.emit()


class MetadataPreviewWorker(QRunnable):
    """Fixed P2-03: Sanitizes embedded null bytes (`\\x00`) in binary text previews for clean clipboard copy."""
    def __init__(
        self,
        session: ForensicSession,
        part_idx: int,
        snap_id: str,
        entry: Dict[str, Any],
        tz_info: datetime.tzinfo,
        tz_name: str,
        preview_req_id: int = 0,
    ):
        super().__init__()
        self.session = session
        self.token = session.session_token
        self.part_idx = part_idx
        self.snap_id = snap_id
        self.entry = entry
        self.tz_info = tz_info
        self.tz_name = tz_name
        self.preview_req_id = preview_req_id
        self.signals = WorkerSignals()

    def run(self):
        try:
            e = self.entry
            mtime = e.get("mtime")
            ctime = e.get("ctime")
            crtime = e.get("crtime")
            atime = e.get("atime")

            anomalies = []
            if crtime is not None and ctime is not None and crtime < (ctime - 86400 * 30) and mtime == crtime:
                anomalies.append(
                    "⚠️ Possible timestamp anomaly (heuristic only, NOT proof of tampering): Created == Modified "
                    "but both are >30 days older than Entry-Modified (ctime). Also seen with extracted/copied files; "
                    "verify against $STANDARD_INFORMATION vs $FILE_NAME in the MFT."
                )
            if e.get("meta_realloc"):
                anomalies.insert(0,
                    "⚠️ INODE REALLOCATED: this deleted name points to an inode that now belongs to a "
                    "newer file. Size, timestamps, ADS and the preview below describe THAT file, "
                    "not the deleted one."
                )
            anomaly_str = "\n".join(anomalies) if anomalies else "None (Consistent MACB sequence)"

            # FEATURE (2026-11-04): streams come from the listing (enumerated once per folder).
            streams = ads_streams(e)
            if streams:
                ads_str = "\n" + "\n".join(
                    f"  {ADS_BADGE} {st['name']:<32} {st['size']:>14,} bytes" for st in streams
                )
            elif e.get("ads_stream") is not None:
                ads_str = f"(this row IS stream '{e['ads_stream']}' of {e.get('ads_host')})"
            else:
                ads_str = "None"

            # Mark-of-the-Web: parse Zone.Identifier when present (on the host or as this row).
            motw_str = ""
            zone_entry = None
            if e.get("ads_stream") == "Zone.Identifier":
                zone_entry = e
            elif any(st["name"] == "Zone.Identifier" for st in streams):
                zone_entry = make_ads_entry(e, next(st for st in streams if st["name"] == "Zone.Identifier"))
            if zone_entry is not None:
                try:
                    raw_zone = self.session.read_file_slice(self.part_idx, self.snap_id, zone_entry, 0, 65536)
                    if self.session.is_aborting:
                        return
                    if zone_entry.get("size", 0) > 0 and not raw_zone:
                        raise OSError("Unexpected EOF while reading Zone.Identifier")
                    zone = parse_zone_identifier(raw_zone)
                    zid = zone.get("ZoneId", "")
                    lines = [f"ZoneId             : {zid} ({ZONE_ID_NAMES.get(zid, 'unknown zone')})"]
                    for key in ("ReferrerUrl", "HostUrl", "LastWriterPackageFamilyName", "AppZoneId", "AppDefinedZoneId"):
                        if key in zone:
                            lines.append(f"{key:<19}: {zone[key]}")
                    for key, val in zone.items():
                        if key not in ("ZoneId", "ReferrerUrl", "HostUrl", "LastWriterPackageFamilyName", "AppZoneId", "AppDefinedZoneId"):
                            lines.append(f"{key:<19}: {val}")
                    motw_str = "\n--- Mark-of-the-Web (Zone.Identifier) ---\n" + "\n".join(lines) + "\n"
                except Exception as zex:
                    if self.session.is_aborting:
                        return
                    motw_str = f"\n--- Mark-of-the-Web (Zone.Identifier) ---\n(unreadable: {zex})\n"

            text_snippet = ""
            if not e["is_dir"] and e.get("size", 0) > 0:
                try:
                    raw_head = self.session.read_file_slice(self.part_idx, self.snap_id, e, 0, 4096)
                    if self.session.is_aborting:
                        return
                    if not raw_head:
                        raise OSError("Unexpected EOF while reading preview")
                    text, encoding = decode_text_bytes(raw_head)
                    printable = "".join(
                        ch if (ch.isprintable() or ch in "\n\t") else "." for ch in text.replace("\r\n", "\n")
                    )[:2048]
                    text_snippet = f"\n--- Text Preview (first 4 KB, {encoding}) ---\n{printable}"
                except Exception as ex:
                    if self.session.is_aborting:
                        return
                    text_snippet = f"\n--- Text Preview ---\n(unreadable: {ex})"

            if self.session.is_aborting:
                return

            alloc_state = "Unallocated / Deleted" if e.get("is_deleted") else "Allocated (Active)"
            report = (
                f"=== Forensic Artifact Metadata ({self.tz_name}) ===\n"
                f"Name               : {e['name']}\n"
                f"Path               : {e['path']}\n"
                f"Snapshot ID        : {self.snap_id}\n"
                f"Allocation Status  : {alloc_state}\n"
                f"Type               : {'ADS Stream' if e.get('ads_stream') is not None else ('Directory' if e['is_dir'] else 'File')}\n"
                f"Size               : {e.get('size', 0):,} bytes\n"
                f"Inode / MFT Record : {e.get('inode', 0)}\n\n"
                f"--- MACB Timestamps ({self.tz_name}) ---\n"
                f"Modified (M)       : {format_epoch_tz(mtime, self.tz_info, True)}\n"
                f"Accessed (A)       : {format_epoch_tz(atime, self.tz_info, True)}\n"
                f"Entry Modified (C) : {format_epoch_tz(ctime, self.tz_info, True)}\n"
                f"Created / Born (B) : {format_epoch_tz(crtime, self.tz_info, True)}\n\n"
                f"--- Forensic Heuristics ---\n"
                f"NTFS ADS Streams   : {ads_str}\n"
                f"Timestamp Analysis : {anomaly_str}\n"
                f"{motw_str}"
                f"{text_snippet}"
            )
            self.signals.metadata_ready.emit(self.token, self.preview_req_id, report)
        except Exception as ex:
            if not self.session.is_aborting:
                self.signals.error.emit(f"Metadata preview error: {ex}")
        finally:
            self.signals.finished.emit()


class SnapshotDiffWorker(QRunnable):
    MAX_DIRS_TO_CRAWL = 500_000  # was 25,000: far below a normal Windows volume, so real diffs were always refused

    def __init__(self, session: ForensicSession, part_idx: int, snap_a: str, snap_b: str):
        super().__init__()
        self.session = session
        self.token = session.session_token
        self.part_idx = part_idx
        self.snap_a = snap_a
        self.snap_b = snap_b
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def cancel(self):
        self.cancel_event.set()

    def _ensure_snapshot_indexed(self, snap_id: str) -> List[str]:
        """Crawl snap_id into the index. Returns the folders whose contents could NOT be
        indexed (unreadable, or never reached because the crawl cap was hit).

        FIX (2026-11-03): one unreadable folder (common in real VSS stores) used to
        block the diff permanently ("comparison withheld" on every retry). The diff now
        runs, the unindexed subtrees are excluded from it (otherwise their children
        would appear as false CREATED/DELETED), and the result is labelled PARTIAL.
        """
        if self.session.index_db and self.session.index_db.is_snapshot_fully_indexed(self.part_idx, snap_id):
            return []

        # Real root inode (NTFS 5, ext 2, FAT 2 ...): hard-coding 5 wrongly skipped a genuine
        # directory with inode 5 on non-NTFS filesystems.
        root_inode = self.session.get_root_inode(self.part_idx, snap_id)
        queue: Deque[Tuple[str, Optional[int]]] = deque([("/", root_inode)])
        visited_paths: Set[str] = set()
        visited_inodes: Set[int] = set()
        failed_dirs: List[str] = []

        while queue and len(visited_paths) < self.MAX_DIRS_TO_CRAWL:
            if self.cancel_event.is_set() or self.session.is_aborting:
                return []
            curr_dir, dir_inode = queue.popleft()
            if curr_dir in visited_paths:
                continue
            if dir_inode is not None and dir_inode != 0:
                if dir_inode in visited_inodes:
                    continue
                visited_inodes.add(dir_inode)
            visited_paths.add(curr_dir)
            if len(visited_paths) % 500 == 0:
                self.signals.status.emit(
                    f"🔍 Indexing {snap_id}: {len(visited_paths):,} folders scanned, {len(queue):,} queued..."
                )

            try:
                entries = self.session.list_directory_sync(self.part_idx, snap_id, curr_dir)
                for item in entries:
                    if item.get("is_deleted"):
                        continue
                    if item["is_dir"]:
                        queue.append((item["path"], item.get("inode")))
            except Exception as e:
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return []
                failed_dirs.append(curr_dir)
                logger.warning(f"Diff crawler could not index {curr_dir} in {snap_id}: {e}")

        if self.cancel_event.is_set() or self.session.is_aborting:
            return []
        # Fix 11 (2026-11-02): only a drained queue with no failures is "fully indexed".
        unreached = [p for p, _ino in queue if p not in visited_paths]
        if not failed_dirs and not unreached:
            if self.session.index_db:
                self.session.index_db.mark_snapshot_fully_indexed(self.part_idx, snap_id)
            return []
        if unreached:
            logger.warning(
                f"Snapshot diff crawl capped at {self.MAX_DIRS_TO_CRAWL} directories for {snap_id}; "
                f"{len(unreached)} queued folders were not indexed."
            )
        return failed_dirs + unreached

    @staticmethod
    def _is_under_any(path: str, roots: Set[str]) -> bool:
        if not roots:
            return False
        if "/" in roots:
            return True
        cur = path
        while cur and cur != "/":
            if cur in roots:
                return True
            cur = posixpath.dirname(cur)
        return False

    def run(self):
        self.signals.status.emit(f"🔍 Indexing & comparing snapshots in SQLite WAL ({self.snap_a} vs {self.snap_b})...")
        try:
            gaps_a = self._ensure_snapshot_indexed(self.snap_a)
            if self.cancel_event.is_set() or self.session.is_aborting:
                return
            gaps_b = self._ensure_snapshot_indexed(self.snap_b)
            if self.cancel_event.is_set() or self.session.is_aborting:
                return
            db = self.session.index_db
            if not db:
                raise RuntimeError("Index database is not available.")

            diffs = db.compute_snapshot_diff(self.part_idx, self.snap_a, self.snap_b)
            excluded = {normalize_forensic_path(p) for p in (gaps_a + gaps_b)}
            if excluded:
                # A row whose own folder (or any ancestor) was not indexed in either snapshot
                # cannot be compared, so it is dropped rather than reported as a change.
                diffs = [
                    d for d in diffs
                    if not self._is_under_any(posixpath.dirname(d["path"]) or "/", excluded)
                ]
            self.signals.diff_ready.emit(self.token, diffs)
            if excluded:
                sample = ", ".join(sorted(excluded)[:5])
                more = f" (+{len(excluded) - 5} more)" if len(excluded) > 5 else ""
                msg = (
                    f"PARTIAL snapshot diff ({self.snap_a} -> {self.snap_b}): {len(excluded):,} folder(s) "
                    f"could not be indexed in one or both snapshots, so nothing beneath them was compared.\n\n"
                    f"Not compared: {sample}{more}\n\nSee the log for the read errors."
                )
                self.signals.warning.emit(msg)
                self.signals.status.emit(
                    f"⚠️ PARTIAL diff ({self.snap_a} -> {self.snap_b}): {len(diffs)} altered items; "
                    f"{len(excluded):,} folder(s) not compared."
                )
            else:
                self.signals.status.emit(
                    f"✅ SQLite WAL Snapshot Diff complete ({self.snap_a} -> {self.snap_b}): {len(diffs)} altered items."
                )
        except Exception as e:
            if not self.session.is_aborting:
                self.signals.error.emit(f"Snapshot diff error: {e}")
        finally:
            self.signals.finished.emit()


class SnapshotIndexWorker(SnapshotDiffWorker):
    """FEATURE (2026-11-04): crawl one or more snapshots fully into the index (for search),
    reusing the diff crawler. Reports folders that could not be indexed."""

    def __init__(self, session: ForensicSession, part_idx: int, snap_ids: List[str]):
        super().__init__(session, part_idx, snap_ids[0] if snap_ids else "Live", snap_ids[0] if snap_ids else "Live")
        self.snap_ids = list(snap_ids)

    def run(self):
        try:
            parts = []
            for snap in self.snap_ids:
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                self.signals.status.emit(f"🔍 Indexing {snap} for search...")
                gaps = self._ensure_snapshot_indexed(snap)
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                parts.append(f"{snap}: complete" if not gaps else f"{snap}: {len(gaps):,} folder(s) not indexed")
            summary = "; ".join(parts)
            self.signals.indexed.emit(self.token, summary)
            self.signals.status.emit(f"✅ Indexing finished — {summary}")
        except Exception as e:
            if not self.session.is_aborting:
                self.signals.error.emit(f"Indexing error: {e}")
        finally:
            self.signals.finished.emit()


class SnapshotSearchWorker(QRunnable):
    """FEATURE (2026-11-04): runs a name search against the SQLite index off the GUI thread."""

    def __init__(self, session: ForensicSession, part_idx: int, snap_ids: List[str], query: str,
                 options: Dict[str, Any], req_id: int):
        super().__init__()
        self.session, self.part_idx, self.snap_ids = session, part_idx, list(snap_ids)
        self.token = session.session_token
        self.query, self.options, self.req_id = query, options, req_id
        self.signals = WorkerSignals()

    def run(self):
        try:
            rows, truncated = self.session.index_db.search_entries(
                self.part_idx, self.snap_ids, self.query, **self.options
            )
            self.signals.search_ready.emit(self.token, self.req_id, rows, truncated)
        except re.error as e:
            self.signals.error.emit(f"Invalid regular expression: {e}")
        except Exception as e:
            if not self.session.is_aborting:
                self.signals.error.emit(f"Search error: {e}")
        finally:
            self.signals.finished.emit()


def locate_in_snapshot(session: ForensicSession, part_idx: int, snap_id: str,
                       entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """FEATURE (2026-11-04): find the same path (or path:stream) in another snapshot.
    A live entry is preferred over deleted names with the same path."""
    host_path = entry.get("ads_host_path") or entry["path"]
    parent = posixpath.dirname(host_path.rstrip("/")) or "/"
    listing = session.list_directory_sync(part_idx, snap_id, parent)
    cands = [e for e in listing if e["path"] == host_path]
    if not cands:
        return None
    host = sorted(cands, key=lambda e: (bool(e.get("is_deleted")), bool(e.get("meta_realloc"))))[0]
    if entry.get("ads_stream") is not None:
        if host.get("meta_realloc"):
            return None
        st = next((x for x in ads_streams(host) if x["name"] == entry["ads_stream"]), None)
        return make_ads_entry(host, st) if st else None
    return host


def ordered_snapshots(pm: "PartitionModel") -> List[Dict[str, Any]]:
    """Snapshots oldest -> newest: shadow copies by creation time, then the live volume."""
    vss = [sn for sn in pm.snapshots if sn.get("vss_index") is not None]
    vss.sort(key=lambda sn: (sn.get("creation_utc") is None, sn.get("creation_utc") or 0, sn.get("vss_index") or 0))
    live = [sn for sn in pm.snapshots if sn.get("vss_index") is None]
    return vss + live


class VersionHistoryWorker(QRunnable):
    """FEATURE (2026-11-04): every version of one file across all snapshots, hashed."""
    HASH_LIMIT = 4 * 1024 ** 3  # files above this are listed but not hashed
    CHUNK = 4 * 1024 * 1024

    def __init__(self, session: ForensicSession, part_idx: int, entry: Dict[str, Any], req_id: int):
        super().__init__()
        self.session, self.part_idx, self.entry, self.req_id = session, part_idx, entry, req_id
        self.token = session.session_token
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def _hash(self, snap_id: str, e: Dict[str, Any]) -> Tuple[str, str, str]:
        size = max(0, int(e.get("size", 0)))
        if e.get("is_dir"):
            return "", "", "folder"
        if e.get("meta_realloc"):
            return "", "", "inode reallocated — not hashed"
        if size > self.HASH_LIMIT:
            return "", "", f"not hashed (> {format_size_human(self.HASH_LIMIT)})"
        md5, sha = hashlib.md5(), hashlib.sha256()
        off = 0
        while off < size:
            if self.cancel_event.is_set() or self.session.is_aborting:
                return "", "", "cancelled"
            data = self.session.read_file_slice(self.part_idx, snap_id, e, off, min(self.CHUNK, size - off))
            if self.cancel_event.is_set() or self.session.is_aborting:
                return "", "", "cancelled"
            if not data:
                return "", "", f"short read at {off:,} of {size:,}"
            md5.update(data)
            sha.update(data)
            off += len(data)
        return md5.hexdigest(), sha.hexdigest(), ""

    def run(self):
        try:
            pm = self.session.partitions[self.part_idx]
            rows: List[Dict[str, Any]] = []
            prev_sha: Optional[str] = None
            prev_deleted: Optional[bool] = None
            seen_before = False
            previous_absent = False
            for sn in ordered_snapshots(pm):
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                snap_id = sn["id"]
                self.signals.status.emit(f"🕘 Version history: checking {snap_id}...")
                row: Dict[str, Any] = {"snap_id": snap_id, "label": sn.get("label", snap_id),
                                       "creation_utc": sn.get("creation_utc"), "entry": None,
                                       "md5": "", "sha256": "", "note": "", "change": ""}
                try:
                    found = locate_in_snapshot(self.session, self.part_idx, snap_id, self.entry)
                except Exception as e:
                    if self.cancel_event.is_set() or self.session.is_aborting:
                        return
                    row["state"] = "Unknown (unreadable)"
                    row["note"] = f"folder not readable here: {e}"
                    row["change"] = "?"
                    prev_sha = None
                    prev_deleted = None
                    previous_absent = False
                    rows.append(row)
                    continue
                if found is None:
                    row["state"] = "Not present"
                    row["change"] = "removed" if seen_before else "—"
                    prev_sha = None if seen_before else prev_sha
                    prev_deleted = None if seen_before else prev_deleted
                    previous_absent = True
                else:
                    found = dict(found)
                    found["source_snap"] = snap_id
                    is_del = bool(found.get("is_deleted"))
                    row["entry"] = found
                    row["state"] = (
                        "Deleted (inode reallocated)" if found.get("meta_realloc")
                        else "Deleted" if is_del else "Present"
                    )
                    try:
                        row["md5"], row["sha256"], note = self._hash(snap_id, found)
                    except Exception as e:
                        if self.cancel_event.is_set() or self.session.is_aborting:
                            return
                        note = f"read error: {e}"
                    if self.cancel_event.is_set() or self.session.is_aborting:
                        return
                    row["note"] = note or row["note"]
                    if not seen_before:
                        row["change"] = "first seen"
                    elif row["sha256"] and prev_sha:
                        if row["sha256"] == prev_sha:
                            if prev_deleted is not None and is_del != prev_deleted:
                                row["change"] = "deleted (content intact)" if is_del else "restored"
                            else:
                                row["change"] = "unchanged"
                        else:
                            row["change"] = "CHANGED"
                    else:
                        row["change"] = "reappeared" if previous_absent else "?"
                    seen_before = True
                    prev_sha = row["sha256"] or None
                    prev_deleted = is_del
                    previous_absent = False
                rows.append(row)
            if self.cancel_event.is_set() or self.session.is_aborting:
                return
            self.signals.history_ready.emit(self.token, self.req_id, rows)
            self.signals.status.emit(
                f"✅ Version history: {sum(1 for r in rows if r['entry'])} version(s) in {len(rows)} snapshot(s)."
            )
        except Exception as e:
            if not self.session.is_aborting:
                self.signals.error.emit(f"Version history error: {e}")
        finally:
            self.signals.finished.emit()


class ImageHashWorker(QRunnable):
    """FEATURE (2026-11-04): MD5/SHA-1/SHA-256 of the whole acquired media, verified against
    the acquisition hashes stored in an E01 when present."""
    CHUNK = 8 * 1024 * 1024

    def __init__(self, session: ForensicSession):
        super().__init__()
        self.session = session
        self.token = session.session_token
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def run(self):
        try:
            size = self.session.media_size
            md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
            off = 0
            last = time.time()
            while off < size:
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                data = self.session.read_raw(off, min(self.CHUNK, size - off))
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
                off += len(data)
                if time.time() - last > 0.5:
                    last = time.time()
                    self.signals.progress.emit(off * 1000 // max(1, size), 1000)
                    self.signals.status.emit(f"🔐 Hashing image… {off * 100 // max(1, size)}%")
            if self.cancel_event.is_set() or self.session.is_aborting:
                return
            stored = self.session.media.stored_hashes() if self.session.media else {}
            result = {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(),
                      "bytes_hashed": off, "media_size": size, "stored": stored}
            if off < size:
                result["verification"] = f"INCOMPLETE — read stopped at {off:,} of {size:,} bytes"
            elif stored:
                checks = []
                for algo in ("MD5", "SHA1", "SHA256"):
                    if algo in stored:
                        ok = stored[algo].lower() == result[algo.lower()]
                        checks.append(f"{algo} {'MATCH' if ok else 'MISMATCH'}")
                result["verification"] = ", ".join(checks) or "no comparable stored hash"
            else:
                result["verification"] = "no acquisition hash stored in this container"
            self.signals.image_hash_ready.emit(self.token, result)
        except Exception as e:
            if not self.session.is_aborting:
                self.signals.error.emit(f"Image hashing failed: {e}")
        finally:
            self.signals.finished.emit()


class CaseReportWorker(QRunnable):
    """FEATURE (2026-11-04): gathers report data off the GUI thread (bookmarked files are
    hashed now, export manifests are re-hashed to detect later changes)."""
    BOOKMARK_HASH_LIMIT = 512 * 1024 * 1024

    def __init__(self, session: ForensicSession, store: CaseStore):
        super().__init__()
        self.session, self.store = session, store
        self.token = session.session_token
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def _hash_entry(self, b: Dict[str, Any]) -> str:
        e = b["entry"]
        size = int(e.get("size", 0))
        if e.get("is_dir"):
            return "(folder)"
        if e.get("meta_realloc"):
            return "(inode reallocated — not hashed)"
        part_idx = int(b.get("part_idx", 0))
        if 0 <= part_idx < len(self.session.partitions):
            pm = self.session.partitions[part_idx]
            if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
                return "(BitLocker volume locked — unlock to hash)"
        if size > self.BOOKMARK_HASH_LIMIT:
            return f"(not hashed: larger than {format_size_human(self.BOOKMARK_HASH_LIMIT)})"
        h = hashlib.sha256()
        off = 0
        while off < size:
            if self.cancel_event.is_set() or self.session.is_aborting:
                return "(cancelled)"
            data = self.session.read_file_slice(b["part_idx"], b["snap_id"], e, off, min(4 << 20, size - off))
            if self.cancel_event.is_set() or self.session.is_aborting:
                return "(cancelled)"
            if not data:
                return f"(short read at {off:,} of {size:,})"
            h.update(data)
            off += len(data)
        return h.hexdigest()

    def run(self):
        try:
            bookmarks = self.store.list_bookmarks()
            for i, b in enumerate(bookmarks):
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                self.signals.status.emit(f"📄 Report: hashing bookmarked item {i + 1}/{len(bookmarks)}…")
                try:
                    b["sha256"] = self._hash_entry(b)
                except Exception as e:
                    b["sha256"] = f"(read error: {e})"
            exports = self.store.list_exports()
            for ex in exports:
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                mp = ex.get("manifest_path") or ""
                try:
                    ex["sha256_now"] = file_sha256(host_path(mp)) if mp and os.path.isfile(host_path(mp)) else "(manifest missing)"
                except Exception as e:
                    ex["sha256_now"] = f"(unreadable: {e})"
            if self.cancel_event.is_set() or self.session.is_aborting:
                return
            data = {
                "info": self.store.get_info(), "bookmarks": bookmarks, "exports": exports,
                "image_hash": self.store.latest_image_hash(),
            }
            self.signals.report_ready.emit(self.token, data)
        except Exception as e:
            if not self.session.is_aborting:
                self.signals.error.emit(f"Report generation failed: {e}")
        finally:
            self.signals.finished.emit()


def build_case_report_html(session: ForensicSession, data: Dict[str, Any]) -> str:
    """FEATURE (2026-11-04): self-contained HTML report. Every evidence-derived string is
    HTML-escaped (file names, notes, descriptions can contain markup). Times are UTC."""
    import html as _html

    def esc(v: Any) -> str:
        return _html.escape("" if v is None else str(v))

    def utc(ts: Optional[int]) -> str:
        return format_epoch_tz(ts, datetime.timezone.utc, True) if ts is not None else "—"

    def table(headers: List[str], rows: List[List[Any]]) -> str:
        head = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
        return f'<table border="1" cellspacing="0" cellpadding="4" width="100%"><tr>{head}</tr>{body}</table>'

    info = data.get("info", {})
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    parts: List[str] = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>VSCExplorer Case Report</title>",
        "<style>body{font-family:'Segoe UI',Arial,sans-serif;font-size:10pt;color:#1f2328}"
        "h1{color:#0969da;font-size:18pt}h2{color:#0969da;font-size:13pt;border-bottom:1px solid #d0d7de}"
        "h3{font-size:11pt}th{background:#eaeef2;text-align:left}td,th{vertical-align:top}"
        ".mono{font-family:Consolas,monospace}.warn{color:#cf222e;font-weight:bold}.ok{color:#1a7f37;font-weight:bold}"
        ".muted{color:#57606a}</style></head><body>",
        "<h1>VSCExplorer Case Report</h1>",
        f"<p class='muted'>Generated {esc(now)} by VSCExplorer v{esc(APP_VERSION)}. All times are UTC.</p>",
        "<h2>1. Case Information</h2>",
        table(["Field", "Value"], [
            [esc(label), esc(info.get(key, "")) or "<span class='muted'>(not set)</span>"]
            for key, label in (("case_number", "Case number"), ("examiner", "Examiner"),
                               ("organization", "Organization"), ("description", "Description"))
        ]),
    ]

    media = session.media
    ih = data.get("image_hash")
    stored = media.stored_hashes() if media else {}
    ev_rows = [
        ["Image path", f"<span class='mono'>{esc(session.image_path)}</span>"],
        ["Container", esc(media.label if media else "demo case")],
        ["Media size", esc(f"{session.media_size:,} bytes ({format_size_human(session.media_size)})")],
    ]
    for k, v in (media.info.items() if media else []):
        ev_rows.append([esc(k), esc(v)])
    if media and media.segment_paths:
        seg_lines = []
        for seg in media.segment_paths:
            try:
                seg_lines.append(f"{esc(seg)} ({os.path.getsize(seg):,} bytes)")
            except OSError:
                seg_lines.append(esc(seg))
        ev_rows.append(["Files", "<span class='mono'>" + "<br>".join(seg_lines) + "</span>"])
    for algo, val in stored.items():
        ev_rows.append([esc(f"Stored acquisition {algo}"), f"<span class='mono'>{esc(val)}</span>"])
    if ih:
        ev_rows += [
            ["Computed MD5", f"<span class='mono'>{esc(ih.get('md5'))}</span>"],
            ["Computed SHA-1", f"<span class='mono'>{esc(ih.get('sha1'))}</span>"],
            ["Computed SHA-256", f"<span class='mono'>{esc(ih.get('sha256'))}</span>"],
            ["Hashed at", esc(utc(ih.get("time_utc")))],
        ]
        ver = ih.get("verification") or ""
        cls_ = "warn" if ("MISMATCH" in ver or "INCOMPLETE" in ver) else "ok" if "MATCH" in ver else "muted"
        ev_rows.append(["Verification", f"<span class='{cls_}'>{esc(ver)}</span>"])
    else:
        ev_rows.append(["Image hash", "<span class='warn'>Not computed in this case (Tools &gt; Compute Image Hash)</span>"])
    if info.get("_fingerprint_changed_utc"):
        try:
            fp_changed_ts = int(info["_fingerprint_changed_utc"])
        except (TypeError, ValueError):
            fp_changed_ts = None
        ev_rows.append(["Case-file warning",
                        "<span class='warn'>The image's file fingerprint changed at "
                        f"{esc(utc(fp_changed_ts))} — bookmarks/logs made before then may "
                        "refer to a different image at the same path.</span>"])
    parts += ["<h2>2. Evidence</h2>", table(["Property", "Value"], ev_rows)]

    vol_rows = []
    snap_rows = []
    for pm in session.partitions:
        bi = pm.bitlocker_info
        if bi.is_encrypted:
            bde = (f"BitLocker {'unlocked' if bi.is_unlocked else 'LOCKED'}; {esc(bi.encryption_method_name)}; "
                   f"protectors: {esc(', '.join(k.protector_type for k in bi.key_protectors) or 'n/a')}")
        else:
            bde = "—"
        vol_rows.append([esc(f"P{pm.index}"), esc(pm.description), esc(f"{pm.start_offset:,}"),
                         esc(format_size_human(pm.size)), esc(pm.fs_type), bde])
        for sn in pm.snapshots:
            snap_rows.append([esc(f"P{pm.index}"), esc(sn["id"]), esc(sn.get("label", "")),
                              esc(utc(sn.get("creation_utc")) if sn.get("creation_utc") else "(live volume)")])
    parts += ["<h2>3. Volumes</h2>",
              table(["#", "Description", "Offset", "Size", "Filesystem", "Encryption"], vol_rows),
              "<h2>4. Volume Shadow Copies</h2>",
              table(["Partition", "Snapshot", "Label", "Created"], snap_rows)]

    bookmarks = data.get("bookmarks", [])
    parts.append(f"<h2>5. Bookmarked Items ({len(bookmarks)})</h2>")
    if not bookmarks:
        parts.append("<p class='muted'>No bookmarks.</p>")
    by_tag: Dict[str, List[Dict[str, Any]]] = {}
    for b in bookmarks:
        by_tag.setdefault(b["tag"] or "(untagged)", []).append(b)
    for tag in sorted(by_tag, key=str.lower):
        rows = []
        for b in by_tag[tag]:
            e = b["entry"]
            state = []
            if e.get("ads_stream") is not None:
                state.append("ADS stream")
            if e.get("is_deleted"):
                state.append("Deleted")
            if e.get("meta_realloc"):
                state.append("inode reallocated")
            streams = ads_streams(e)
            if streams:
                state.append("ADS: " + ", ".join(st["name"] for st in streams))
            rows.append([
                f"<span class='mono'>{esc(e.get('path'))}</span><br><span class='muted'>"
                f"P{esc(b['part_idx'])} / {esc(b['snap_id'])} · inode {esc(e.get('inode'))}"
                + (f" · {esc('; '.join(state))}" if state else "") + "</span>",
                esc("folder" if e.get("is_dir") else f"{int(e.get('size', 0)):,}"),
                "M " + esc(utc(e.get("mtime"))) + "<br>A " + esc(utc(e.get("atime")))
                + "<br>C " + esc(utc(e.get("ctime"))) + "<br>B " + esc(utc(e.get("crtime"))),
                f"<span class='mono'>{esc(b.get('sha256', ''))}</span>",
                esc(b.get("note", "")).replace("\n", "<br>"),
            ])
        parts += [f"<h3>Tag: {esc(tag)} ({len(by_tag[tag])})</h3>",
                  table(["Item", "Size (bytes)", "MACB (UTC)", "SHA-256 (at report time)", "Examiner note"], rows)]

    exports = data.get("exports", [])
    parts.append(f"<h2>6. Exports ({len(exports)})</h2>")
    if not exports:
        parts.append("<p class='muted'>No exports were made in this case.</p>")
    else:
        rows = []
        for ex in exports:
            then, now_h = ex.get("manifest_sha256") or "", ex.get("sha256_now") or ""
            if then and now_h == then:
                integrity = "<span class='ok'>unchanged since export</span>"
            elif then and now_h and not now_h.startswith("("):
                integrity = "<span class='warn'>MANIFEST CHANGED SINCE EXPORT</span>"
            else:
                integrity = f"<span class='muted'>{esc(now_h or 'n/a')}</span>"
            rows.append([
                esc(utc(ex.get("time_utc"))), esc(f"P{ex.get('part_idx')} / {ex.get('snap_id')}"),
                f"<span class='mono'>{esc(ex.get('dest_dir'))}<br>{esc(ex.get('manifest_path'))}</span>",
                esc(f"{ex.get('items_success')}/{ex.get('items_total')}" + (" (cancelled)" if ex.get("cancelled") else "")),
                f"<span class='mono'>{esc(then or '—')}</span>", integrity,
            ])
        parts.append(table(["Time", "Source", "Destination / manifest", "Items OK", "Manifest SHA-256 at export", "Integrity now"], rows))

    parts.append("<p class='muted'>End of report. A SHA-256 of this file is written beside it (.sha256).</p></body></html>")
    return "".join(parts)


def write_case_report(session: ForensicSession, data: Dict[str, Any], html_path: str) -> List[Tuple[str, str]]:
    """Write the HTML report, render the same HTML to PDF (Qt, GUI thread), and write a
    .sha256 sidecar for each. Returns [(path, sha256)]."""
    html_text = build_case_report_html(session, data)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    pdf_path = os.path.splitext(html_path)[0] + ".pdf"
    writer = QPdfWriter(pdf_path)
    a4 = QPageSize.PageSizeId.A4 if hasattr(QPageSize, "PageSizeId") else QPageSize.A4
    writer.setPageSize(QPageSize(a4))
    writer.setResolution(96)
    writer.setTitle("VSCExplorer Case Report")
    writer.setCreator(f"VSCExplorer v{APP_VERSION}")
    # A CSS font list that falls through to Qt's own fallback produced a PDF whose text
    # layer maps '-' and ':' to private-use codepoints (copy/paste of dates and paths
    # came out corrupted). Use concrete installed families for the PDF.
    try:
        families = set(QFontDatabase.families())
    except TypeError:  # PyQt5: instance method
        families = set(QFontDatabase().families())
    sans = next((f for f in ("Segoe UI", "Arial", "Liberation Sans", "DejaVu Sans", "Helvetica") if f in families), None)
    mono = next((f for f in ("Consolas", "DejaVu Sans Mono", "Liberation Mono", "Courier New") if f in families), None)
    pdf_html = html_text
    if sans:
        pdf_html = pdf_html.replace("'Segoe UI',Arial,sans-serif", f"'{sans}'")
    if mono:
        pdf_html = pdf_html.replace("Consolas,monospace", f"'{mono}'")
    doc = QTextDocument()
    if sans:
        doc.setDefaultFont(QFont(sans, 9))
    doc.setHtml(pdf_html)
    doc.setPageSize(writer.pageLayout().paintRectPixels(writer.resolution()).size().toSizeF())
    if hasattr(doc, "print_"):
        doc.print_(writer)
    else:
        doc.print(writer)
    del writer  # flushes the PDF
    written = []
    for pth in (html_path, pdf_path):
        digest = file_sha256(pth)
        with open(pth + ".sha256", "w", encoding="utf-8") as fh:
            fh.write(f"{digest}  {os.path.basename(pth)}\n")
        written.append((pth, digest))
    return written


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> Any:
    """FIX (2026-11-03): neutralise spreadsheet formula injection (OWASP CSV injection).
    Names and paths come from the evidence, so a file planted as
    '=HYPERLINK("http://...")' became a live formula when the analyst opened
    export_summary.csv in Excel/LibreOffice. CSV quoting does not prevent this;
    a leading apostrophe does."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def host_path(path: str) -> str:
    """FIX (2026-11-03): on Windows, use the \\\\?\\ prefix so exports deeper than
    MAX_PATH (260 chars; common under AppData) do not fail. No-op elsewhere."""
    if os.name != "nt":
        return path
    path = os.path.abspath(path)
    if path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


class BufferedExportWorker(QRunnable):
    """
    Fixed P1-05 & P2-01:
    - Pre-seeds `used_names_in_dir` with existing filenames on the host destination folder
      (guarded by `os.path.isdir`) so repeat exports never overwrite existing evidence files.

    FIX (2026-11-03):
    - The manifest name is reserved before planning, so an evidence file named
      export_summary.csv can no longer be overwritten by the manifest. A repeat
      export writes export_summary_<UTC>.csv instead of overwriting the previous
      run's manifest and hashes.
    - The plan is built iteratively (deep nesting can no longer raise
      RecursionError and abort the export), and deleted folders are listed by inode.
    - Directory creation and parent creation errors are per item: one bad folder
      used to abort the whole export with no manifest.
    - The manifest is written on cancel too, listing what was exported.
    - Deleted names whose inode was reallocated are not exported as if they were
      the deleted file; they are recorded as skipped.
    """
    MANIFEST_BASENAME = "export_summary"

    def __init__(
        self,
        session: ForensicSession,
        part_idx: int,
        snap_id: str,
        root_items: List[Dict[str, Any]],
        dest_dir: str,
        export_options: Dict[str, Any],
    ):
        super().__init__()
        self.session = session
        self.part_idx = part_idx
        self.snap_id = snap_id
        self.root_items = root_items
        self.dest_dir = dest_dir
        self.options = export_options
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()
        self._manifest_name: Optional[str] = None
        self._plan_errors: Dict[str, str] = {}

    def cancel(self):
        self.cancel_event.set()

    def _choose_manifest_name(self) -> str:
        base = self.MANIFEST_BASENAME
        name = f"{base}.csv"
        if not os.path.exists(host_path(os.path.join(self.dest_dir, name))):
            return name
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"{base}_{stamp}.csv"
        counter = 2
        while os.path.exists(host_path(os.path.join(self.dest_dir, name))):
            name = f"{base}_{stamp}_{counter}.csv"
            counter += 1
        return name

    def _seed_used_names(self, parent_rel_dir: str) -> Set[str]:
        used: Set[str] = set()
        host_target_dir = os.path.join(self.dest_dir, parent_rel_dir) if parent_rel_dir else self.dest_dir
        if os.path.isdir(host_path(host_target_dir)):
            try:
                for existing_f in os.listdir(host_path(host_target_dir)):
                    used.add(existing_f.lower())
            except OSError:
                pass
        if not parent_rel_dir and self._manifest_name:
            used.add(self._manifest_name.lower())
        return used

    def _seed_ancestor_inodes(self, visited_inodes: Set[Tuple[str, int]], default_snap: str,
                              items: List[Dict[str, Any]]):
        for snap_key in {default_snap, *(i.get("source_snap", default_snap) for i in items)}:
            root_ino = self.session.get_root_inode(self.part_idx, snap_key)
            if root_ino:
                visited_inodes.add((snap_key, root_ino))
        for item in items:
            item_snap = item.get("source_snap", default_snap)
            p = normalize_forensic_path(item.get("path", "/"))
            parts = [seg for seg in p.strip("/").split("/") if seg][:-1]
            curr = "/"
            for seg in parts:
                try:
                    parent_entries = self.session.list_directory_sync(self.part_idx, item_snap, curr)
                    next_p = normalize_forensic_path(posixpath.join(curr, seg))
                    match = next((e for e in parent_entries if e["path"] == next_p and not e.get("is_deleted")), None)
                    if match and match.get("inode"):
                        visited_inodes.add((item_snap, int(match["inode"])))
                    curr = next_p
                except Exception:
                    break

    def _collect_export_plan(
        self,
        items: List[Dict[str, Any]],
        default_snap: str,
    ) -> List[Tuple[Dict[str, Any], str, str]]:
        plan: List[Tuple[Dict[str, Any], str, str]] = []
        # Track ancestors per branch. A global set suppresses explicitly selected
        # parents when another selection happens to be below them.
        stack = [(iter(items), "", self._seed_used_names(""), default_snap, frozenset())]
        while stack:
            if self.cancel_event.is_set() or self.session.is_aborting:
                break
            children_it, parent_rel_dir, used_names_in_dir, frame_snap, ancestors = stack[-1]
            item = next(children_it, None)
            if item is None:
                stack.pop()
                continue
            item_snap = item.get("source_snap", frame_snap)
            inode = int(item.get("inode", 0) or 0)
            if item["is_dir"] and not parent_rel_dir:
                root_ancestors: Set[Tuple[str, int]] = set()
                self._seed_ancestor_inodes(root_ancestors, item_snap, [item])
                ancestors = frozenset(root_ancestors)
            if item["is_dir"] and parent_rel_dir and inode != 0:
                inode_key = (item_snap, inode)
                if inode_key in ancestors:
                    continue

            safe_name = sanitize_filename(item["name"], inode, used_names_in_dir)
            rel_path = os.path.join(parent_rel_dir, safe_name) if parent_rel_dir else safe_name
            plan.append((item, rel_path, item_snap))

            # FEATURE (2026-11-04): each named stream is exported beside its host
            # ('evil.exe' -> 'evil.exe_Zone.Identifier'); ':' is not portable.
            if (
                self.options.get("include_ads", True)
                and item.get("ads_stream") is None
                and not item.get("meta_realloc")
            ):
                for st in ads_streams(item):
                    st_item = make_ads_entry(item, st)
                    st_name = sanitize_filename(st_item["name"], inode, used_names_in_dir)
                    st_rel = os.path.join(parent_rel_dir, st_name) if parent_rel_dir else st_name
                    plan.append((st_item, st_rel, item_snap))

            if item["is_dir"] and not item.get("meta_realloc"):
                try:
                    children = self.session.list_directory_sync(
                        self.part_idx, item_snap, item["path"], dir_entry=item
                    )
                except Exception as e:
                    if self.cancel_event.is_set() or self.session.is_aborting:
                        break
                    logger.error(f"Error expanding subfolder {item['path']} for export: {e}")
                    self._plan_errors[rel_path] = str(e)
                    continue
                child_ancestors = ancestors | {(item_snap, inode)} if inode else ancestors
                stack.append((iter(children), rel_path, self._seed_used_names(rel_path), item_snap, child_ancestors))
        return plan

    def run(self):
        try:
            os.makedirs(host_path(self.dest_dir), exist_ok=True)
            self.signals.status.emit("🔍 Building recursive export manifest...")

            include_hashes = self.options.get("include_hashes", False)
            hash_types = self.options.get("hash_types", [])
            generate_csv = self.options.get("generate_csv", True)
            self._manifest_name = self._choose_manifest_name() if generate_csv else None

            export_plan = self._collect_export_plan(self.root_items, self.snap_id)
            total_count = len(export_plan)
            success_count = 0
            dir_post_order_stack: List[Tuple[str, Dict[str, Any]]] = []
            export_records: List[Dict[str, Any]] = []

            csv_fieldnames = [
                "Name", "Snapshot", "Source_Path", "Exported_Relative_Path",
                "Type", "Allocation", "Size", "Inode", "Modified_UTC", "Created_UTC",
                "Entry_Modified_UTC", "Accessed_UTC", "Export_Status",
                "Export_Time_UTC", "Error",
            ]
            if include_hashes:
                for ht in hash_types:
                    csv_fieldnames.append(f"{ht.upper()}_Hash")

            for idx, (item, rel_path, item_snap) in enumerate(export_plan):
                if self.cancel_event.is_set() or self.session.is_aborting:
                    break

                self.signals.progress.emit(idx + 1, max(1, total_count))
                host_out_path = host_path(os.path.join(self.dest_dir, rel_path))

                if item["is_dir"]:
                    self.signals.status.emit(f"📁 Creating folder: {rel_path}")
                    status, err_msg = "Success", ""
                    try:
                        os.makedirs(host_out_path, exist_ok=True)
                        dir_post_order_stack.append((host_out_path, item))
                        if item.get("meta_realloc"):
                            status = "Partial (inode reallocated; original folder contents unavailable)"
                        elif rel_path in self._plan_errors:
                            status = "Partial (folder contents unreadable)"
                            err_msg = self._plan_errors[rel_path]
                        else:
                            success_count += 1
                    except Exception as ex:
                        status, err_msg = "Failed", str(ex)
                    if generate_csv:
                        export_records.append(
                            self._build_csv_record(item, rel_path, item_snap, status, err_msg, {})
                        )
                    continue

                if ads_export_skipped(item):
                    if generate_csv:
                        export_records.append(self._build_csv_record(
                            item, rel_path, item_snap, "Skipped (volume-sized sparse placeholder stream)",
                            "$BadClus:$Bad reports the whole volume size; it is not exported", {},
                        ))
                    continue

                if item.get("meta_realloc"):
                    if generate_csv:
                        export_records.append(self._build_csv_record(
                            item, rel_path, item_snap,
                            "Skipped (inode reallocated)",
                            f"inode {item.get('inode')} now belongs to a newer file; its content is not this deleted file's",
                            {},
                        ))
                    continue

                self.signals.status.emit(f"📤 Exporting file: {rel_path}")

                hash_calcs = {}
                if include_hashes:
                    for ht in hash_types:
                        if ht == "md5":
                            hash_calcs["MD5_Hash"] = hashlib.md5()
                        elif ht == "sha1":
                            hash_calcs["SHA1_Hash"] = hashlib.sha1()
                        elif ht == "sha256":
                            hash_calcs["SHA256_Hash"] = hashlib.sha256()

                status = "Success"
                err_msg = ""

                try:
                    parent_dir = os.path.dirname(host_out_path)
                    if parent_dir:
                        os.makedirs(parent_dir, exist_ok=True)
                    chunk_size = 4 * 1024 * 1024
                    file_size = max(0, int(item.get("size", 0)))
                    offset = 0
                    consecutive_read_errors = 0
                    max_consecutive_errors = 16  # 16 x 4 MB; stops a corrupt size field from zero-filling the disk

                    with open(host_out_path, "xb") as out_fp:
                        while offset < file_size:
                            if self.cancel_event.is_set() or self.session.is_aborting:
                                status = "Cancelled"
                                err_msg = "Export cancelled by user"
                                break
                            to_read = min(chunk_size, file_size - offset)
                            try:
                                data = self.session.read_file_slice(
                                    self.part_idx, item_snap, item, offset, to_read
                                )
                            except Exception as read_err:
                                if self.cancel_event.is_set() or self.session.is_aborting:
                                    status = "Cancelled"
                                    err_msg = "Export cancelled by user"
                                    break
                                consecutive_read_errors += 1
                                status = f"Partial (Bad sector zero-filled at {offset})"
                                err_msg = str(read_err)
                                if consecutive_read_errors >= max_consecutive_errors:
                                    status = f"Partial (Aborted after {consecutive_read_errors} consecutive read errors at offset {offset})"
                                    break
                                data = b"\x00" * to_read
                            else:
                                consecutive_read_errors = 0

                            if self.cancel_event.is_set() or self.session.is_aborting:
                                status = "Cancelled"
                                err_msg = "Export cancelled by user"
                                break
                            if not data:
                                status = f"Partial (Unexpected EOF at offset {offset})"
                                err_msg = f"Unexpected EOF at byte {offset} of {file_size}"
                                break
                            out_fp.write(data)
                            for hc in hash_calcs.values():
                                hc.update(data)
                            offset += len(data)

                    if status == "Cancelled":
                        try:
                            if os.path.exists(host_out_path):
                                os.remove(host_out_path)
                        except Exception:
                            pass
                    elif status.startswith("Success") or status.startswith("Partial"):
                        self._preserve_timestamps(host_out_path, item, is_directory=False)
                    if status == "Success":
                        success_count += 1
                except Exception as ex:
                    status = "Failed"
                    err_msg = str(ex)

                computed_hashes = {
                    k: (hc.hexdigest() if status == "Success" else "")
                    for k, hc in hash_calcs.items()
                }
                if generate_csv:
                    export_records.append(
                        self._build_csv_record(item, rel_path, item_snap, status, err_msg, computed_hashes)
                    )

            for d_host_path, d_item in reversed(dir_post_order_stack):
                self._preserve_timestamps(d_host_path, d_item, is_directory=True)

            manifest_path = ""
            if generate_csv and self._manifest_name:
                manifest_path = os.path.join(self.dest_dir, self._manifest_name)
                with open(host_path(manifest_path), "x", newline="", encoding="utf-8") as csv_fp:
                    writer = csv.DictWriter(csv_fp, fieldnames=csv_fieldnames)
                    writer.writeheader()
                    writer.writerows(export_records)

            self.signals.export_done.emit(
                success_count, total_count, manifest_path, self.cancel_event.is_set() or self.session.is_aborting
            )
        except Exception as e:
            if not self.session.is_aborting:
                logger.error(f"Export worker failed: {e}")
                self.signals.error.emit(f"Export operation failed: {e}")
        finally:
            self.signals.finished.emit()

    def _build_csv_record(
        self,
        item: Dict[str, Any],
        rel_path: str,
        snap_id: str,
        status: str,
        err_msg: str,
        hashes: Dict[str, str],
    ) -> Dict[str, Any]:
        if item.get("meta_realloc"):
            allocation = "Deleted (inode reallocated)"
        elif item.get("is_deleted"):
            allocation = "Deleted"
        else:
            allocation = "Allocated"
        rec: Dict[str, Any] = {
            "Name": item["name"],
            "Snapshot": snap_id,
            "Source_Path": item["path"],
            "Exported_Relative_Path": rel_path,
            "Type": "ADS Stream" if item.get("ads_stream") is not None else ("Directory" if item["is_dir"] else "File"),
            "Allocation": allocation,
            "Size": 0 if item["is_dir"] else max(0, int(item.get("size", 0))),
            "Inode": item.get("inode", 0),
            "Modified_UTC": format_epoch_tz(item.get("mtime"), datetime.timezone.utc),
            "Created_UTC": format_epoch_tz(item.get("crtime"), datetime.timezone.utc),
            "Entry_Modified_UTC": format_epoch_tz(item.get("ctime"), datetime.timezone.utc),
            "Accessed_UTC": format_epoch_tz(item.get("atime"), datetime.timezone.utc),
            "Export_Status": status,
            "Export_Time_UTC": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "Error": err_msg,
        }
        if self.options.get("include_hashes", False):
            for ht in self.options.get("hash_types", []):
                col_key = f"{ht.upper()}_Hash"
                rec[col_key] = hashes.get(col_key, "")
        return {k: csv_safe(v) for k, v in rec.items()}

    @staticmethod
    def _preserve_timestamps(host_path: str, item: Dict[str, Any], is_directory: bool = False):
        # FIX (2026-11-03): values are already whole seconds (see coerce_tsk_epoch); the
        # old code re-ran unit guessing on them and failed on pre-1970 values.
        now_ts = int(time.time())

        def _secs(v: Any) -> Optional[int]:
            try:
                return int(v) if v is not None else None
            except (TypeError, ValueError, OverflowError):
                return None

        raw_a = _secs(item.get("atime"))
        raw_m = _secs(item.get("mtime"))
        raw_cr = _secs(item.get("crtime"))

        atime = raw_a if raw_a is not None else now_ts
        mtime = raw_m if raw_m is not None else now_ts
        crtime = raw_cr if raw_cr is not None else mtime

        try:
            os.utime(host_path, (atime, mtime))
        except (OSError, OverflowError, ValueError):
            pass

        if PYWIN32_AVAILABLE and os.name == "nt":
            try:
                def epoch_to_filetime(ts: int):
                    return pywintypes.Time(_EPOCH_UTC + datetime.timedelta(seconds=ts))

                flags = (
                    win32con.FILE_FLAG_BACKUP_SEMANTICS
                    if is_directory
                    else win32con.FILE_ATTRIBUTE_NORMAL
                )
                handle = win32file.CreateFile(
                    host_path,
                    win32con.GENERIC_WRITE,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | getattr(win32con, "FILE_SHARE_DELETE", 4),
                    None,
                    win32con.OPEN_EXISTING,
                    flags,
                    None,
                )
                try:
                    win32file.SetFileTime(
                        handle,
                        epoch_to_filetime(crtime),
                        epoch_to_filetime(atime),
                        epoch_to_filetime(mtime),
                    )
                finally:
                    handle.close()
            except Exception:
                pass


# ============================================================================
# Section 6: Virtual Table Models, Custom Proxy Sorter & 64-Bit Hex Viewer
# ============================================================================

def _ts_sort_key(value: Optional[int]) -> Tuple[int, int]:
    return (0, 0) if value is None else (1, int(value))


class ForensicSortFilterProxyModel(QSortFilterProxyModel):
    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        src = self.sourceModel()
        if src is None:
            return super().lessThan(left, right)
        role = self.sortRole()
        val_a = src.data(left, role)
        val_b = src.data(right, role)
        if val_a is None and val_b is None:
            return False
        if val_a is None:
            return True
        if val_b is None:
            return False
        try:
            return bool(val_a < val_b)
        except TypeError:
            return str(val_a) < str(val_b)


class ForensicFileSystemTableModel(QAbstractTableModel):
    SORT_ROLE = ROLE_USER + 1

    def __init__(self, parent=None):
        super().__init__(parent)
        self._entries: List[Dict[str, Any]] = []
        # Optional callback returning extra name-column markers (e.g. bookmark badge).
        self._marker_fn = None
        self._tz_info: datetime.tzinfo = datetime.timezone.utc
        self._tz_label: str = "UTC"

    def set_timezone(self, tz_name: str, tz_info: datetime.tzinfo):
        self.beginResetModel()
        self._tz_label = tz_name
        self._tz_info = tz_info
        self.endResetModel()

    def set_entries(self, entries: List[Dict[str, Any]]):
        self.beginResetModel()
        self._entries = entries
        self.endResetModel()

    def get_entries(self) -> List[Dict[str, Any]]:
        return self._entries

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else 7

    def headerData(self, section: int, orientation, role=ROLE_DISPLAY):
        if orientation == ORIENT_HORIZONTAL and role == ROLE_DISPLAY:
            headers = [
                "Name",
                "Size",
                "Type",
                f"Modified ({self._tz_label})",
                f"Created ({self._tz_label})",
                f"Accessed ({self._tz_label})",
                "Inode",
            ]
            return headers[section]
        return None

    def data(self, index: QModelIndex, role=ROLE_DISPLAY):
        if not index.isValid() or index.row() >= len(self._entries):
            return None

        entry = self._entries[index.row()]
        col = index.column()

        if role == ROLE_USER:
            return entry

        if role == self.SORT_ROLE:
            dir_rank = 0 if entry["is_dir"] else 1
            if col == 0:
                if entry.get("ads_stream") is not None:
                    return (0 if entry.get("ads_host_is_dir") else 1, entry["ads_host"].lower(), 1, entry["ads_stream"].lower())
                return (dir_rank, entry["name"].lower(), 0, "")
            elif col == 1:
                return (dir_rank, 0 if entry["is_dir"] else int(entry.get("size", 0)))
            elif col == 2:
                ext = "0_Folder" if entry["is_dir"] else os.path.splitext(entry["name"])[1].upper()
                return (dir_rank, ext, entry["name"].lower())
            # FIX (2026-11-03): (has_value, value) instead of a -1 sentinel, which sorted
            # "unknown" among genuine pre-1970 values now that those are kept.
            elif col == 3:
                return (dir_rank,) + _ts_sort_key(entry.get("mtime"))
            elif col == 4:
                return (dir_rank,) + _ts_sort_key(entry.get("crtime"))
            elif col == 5:
                return (dir_rank,) + _ts_sort_key(entry.get("atime"))
            elif col == 6:
                return int(entry.get("inode", 0))

        if role == ROLE_DISPLAY:
            is_del = bool(entry.get("is_deleted"))
            if col == 0:
                if entry.get("meta_realloc"):
                    del_tag = " [Deleted, inode reallocated]"
                else:
                    del_tag = " [Deleted]" if is_del else ""
                marks = self._marker_fn(entry) if self._marker_fn else ""
                if entry.get("ads_stream") is not None:
                    # FEATURE (2026-11-04): a stream row, listed right under its host file.
                    return f"   ↳ {ADS_BADGE} :{entry['ads_stream']}{del_tag}{marks}"
                icon = FileIconProvider.get_file_icon(entry["name"], entry["is_dir"], is_del)
                streams = ads_streams(entry)
                badge = f"  {ADS_BADGE}{len(streams)}" if streams else ""
                return f"{icon} {entry['name']}{badge}{del_tag}{marks}"
            elif col == 1:
                return "—" if entry["is_dir"] else format_size_human(entry.get("size", 0))
            elif col == 2:
                if entry.get("ads_stream") is not None:
                    return "ADS Stream"
                if entry["is_dir"]:
                    return "Deleted Folder" if is_del else "Folder"
                ext = os.path.splitext(entry["name"])[1].upper()
                base_type = f"{ext[1:]} File" if ext else "File"
                return f"Deleted {base_type}" if is_del else base_type
            elif col == 3:
                return format_epoch_tz(entry.get("mtime"), self._tz_info)
            elif col == 4:
                return format_epoch_tz(entry.get("crtime"), self._tz_info)
            elif col == 5:
                return format_epoch_tz(entry.get("atime"), self._tz_info)
            elif col == 6:
                return str(entry.get("inode", 0))

        if role == ROLE_FOREGROUND and entry.get("is_deleted"):
            return QColor("#e5534b")
        if role == ROLE_FOREGROUND and entry.get("ads_stream") is not None:
            return QColor("#8957e5")

        if role == ROLE_TOOLTIP and col == 0:
            streams = ads_streams(entry)
            if streams:
                lines = "\n".join(f"  • {st['name']}  ({st['size']:,} bytes)" for st in streams)
                return f"{ADS_BADGE} {len(streams)} alternate data stream(s):\n{lines}"
            if entry.get("ads_stream") is not None:
                return f"Alternate data stream '{entry['ads_stream']}' of {entry.get('ads_host')}"

        if role == ROLE_TEXT_ALIGN and col in (1, 6):
            return int(ALIGN_RIGHT | ALIGN_VCENTER)

        return None


class ForensicDiffTableModel(QAbstractTableModel):
    SORT_ROLE = ROLE_USER + 1

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[Dict[str, Any]] = []
        self._tz_info: datetime.tzinfo = datetime.timezone.utc
        self._tz_label: str = "UTC"

    def set_timezone(self, tz_name: str, tz_info: datetime.tzinfo):
        self.beginResetModel()
        self._tz_label = tz_name
        self._tz_info = tz_info
        self.endResetModel()

    def set_entries(self, rows: List[Dict[str, Any]]):
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else 7

    def headerData(self, section: int, orientation, role=ROLE_DISPLAY):
        if orientation == ORIENT_HORIZONTAL and role == ROLE_DISPLAY:
            headers = [
                "Change",
                "Path",
                "Baseline Size",
                "Target Size",
                "Delta",
                f"Modified ({self._tz_label})",
                f"ADS Δ ({ADS_BADGE})",
            ]
            return headers[section]
        return None

    def data(self, index: QModelIndex, role=ROLE_DISPLAY):
        if not index.isValid() or index.row() >= len(self._rows):
            return None

        row = self._rows[index.row()]
        col = index.column()

        if role == ROLE_USER:
            return row

        if role == self.SORT_ROLE:
            if col == 0:
                return (row["delta"], row["path"].lower())
            elif col == 1:
                return row["path"].lower()
            elif col == 2:
                return int(row.get("old_size", 0))
            elif col == 3:
                return int(row.get("new_size", 0))
            elif col == 4:
                return int(row.get("size_delta", 0))
            elif col == 5:
                return _ts_sort_key(row.get("mtime"))
            elif col == 6:
                return row.get("ads_change", "")

        if role == ROLE_DISPLAY:
            if col == 0:
                return row["delta"]
            elif col == 1:
                icon = FileIconProvider.get_file_icon(row["name"], row["is_dir"])
                return f"{icon} {row['path']}"
            elif col == 2:
                return "—" if row["is_dir"] else format_size_human(row.get("old_size", 0))
            elif col == 3:
                return "—" if row["is_dir"] else format_size_human(row.get("new_size", 0))
            elif col == 4:
                if row["is_dir"]:
                    return "—"
                d_val = row.get("size_delta", 0)
                sign = "+" if d_val > 0 else ""
                return f"{sign}{d_val:,} B"
            elif col == 5:
                return format_epoch_tz(row.get("mtime"), self._tz_info)
            elif col == 6:
                if row.get("ads_change"):
                    return row["ads_change"]
                streams = ads_streams(row)
                return f"{ADS_BADGE}{len(streams)}" if streams else ""

        if role == ROLE_FOREGROUND:
            delta = row["delta"]
            if delta == "CREATED":
                return QColor("#2ea043")
            elif delta == "MODIFIED":
                return QColor("#d29922")
            elif delta == "DELETED":
                return QColor("#f85149")

        if role == ROLE_TEXT_ALIGN and col in (2, 3, 4):
            return int(ALIGN_RIGHT | ALIGN_VCENTER)

        return None


class _HexPageSignals(QObject):
    page_ready = Signal(int, int, object)  # generation, page index, bytes (None = read error)
    finished = Signal(object)


class _HexPageWorker(QRunnable):
    def __init__(self, session, part_idx, snap_id, entry, page_idx, page_size, generation, signals):
        super().__init__()
        self.session = session
        self.part_idx = part_idx
        self.snap_id = snap_id
        self.entry = entry
        self.page_idx = page_idx
        self.page_size = page_size
        self.generation = generation
        self.signals = signals

    def run(self):
        try:
            if self.session.is_aborting:
                return
            try:
                data = self.session.read_file_slice(
                    self.part_idx, self.snap_id, self.entry, self.page_idx * self.page_size, self.page_size
                )
            except Exception as e:
                logger.debug(f"Hex page {self.page_idx} read failed: {e}")
                data = None
            if self.session.is_aborting:
                return
            self.signals.page_ready.emit(self.generation, self.page_idx, data)
        finally:
            self.signals.finished.emit(self)


class VirtualHexViewer(QAbstractScrollArea):
    """FIX (2026-11-03): pages are read on the thread pool instead of inside
    paintEvent(). read_file_slice() takes the per-snapshot filesystem lock, which
    the diff crawler and exports hold for long stretches, so painting on the GUI
    thread froze the whole window. Rows still loading are drawn as such and
    repainted when their page arrives. Unreadable pages are shown, not skipped."""
    PAGE_SIZE = 4096
    MAX_QT_SCROLL_RANGE = 2_000_000_000
    MAX_CACHED_PAGES = 64
    MAX_PENDING_PAGES = 8
    view_info = Signal(str)  # FEATURE (2026-11-04): top offset + page entropy for the hex panel

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hl_start: int = -1
        self._hl_len: int = 0
        self._last_view_info: str = ""
        self._session: Optional[ForensicSession] = None
        self._part_idx: int = 0
        self._snap_id: str = "Live"
        self._entry: Optional[Dict[str, Any]] = None
        self._page_cache: Dict[int, Optional[bytes]] = {}
        self._pending_pages: Set[int] = set()
        self._active_workers: Set[_HexPageWorker] = set()
        self._generation: int = 0
        self._page_signals = _HexPageSignals()
        self._page_signals.page_ready.connect(self._on_page_ready)
        self._page_signals.finished.connect(self._on_page_worker_finished)
        self._dark_mode: bool = False
        self._scroll_scale: int = 1
        self._scrollable_rows: int = 0
        self._exact_top_row: Optional[int] = None

        self.mono_font = QFont("Consolas", 10)
        self.mono_font.setStyleHint(FONT_MONOSPACE)
        self.row_height = 20
        self.setFont(self.mono_font)
        self._char_w = max(1, QFontMetrics(self.mono_font).horizontalAdvance("0"))
        self.verticalScrollBar().valueChanged.connect(self._on_vertical_scroll)
        self.horizontalScrollBar().valueChanged.connect(self.viewport().update)

    def set_theme_mode(self, dark_mode: bool):
        self._dark_mode = dark_mode
        self.viewport().update()

    def _reset_pages(self):
        self._exact_top_row = None
        self._generation += 1
        self._page_cache.clear()
        self._pending_pages.clear()
        self._hl_start, self._hl_len = -1, 0
        self._last_view_info = ""
        self.view_info.emit("")

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def bound_entry(self) -> Optional[Dict[str, Any]]:
        return self._entry

    def set_highlight(self, start: int, length: int):
        self._hl_start, self._hl_len = start, max(0, length)
        self.viewport().update()

    def goto_offset(self, offset: int, highlight_len: int = 1):
        """Scroll so offset is on screen (two rows of context above) and highlight it."""
        if not self._entry:
            return
        size = max(0, int(self._entry.get("size", 0)))
        offset = max(0, min(offset, max(0, size - 1)))
        row = max(0, offset // 16 - 2)
        self.verticalScrollBar().setValue(min(self.verticalScrollBar().maximum(), row // max(1, self._scroll_scale)))
        # The integer scrollbar is coarse for huge files. Preserve the exact row
        # for go-to/search until the user moves the scrollbar again.
        self._exact_top_row = min(row, self._scrollable_rows)
        self.set_highlight(offset, highlight_len)

    def highlight_start(self) -> int:
        return self._hl_start

    def top_offset(self) -> int:
        if self._exact_top_row is not None:
            return min(self._scrollable_rows, self._exact_top_row) * 16
        return min(self._scrollable_rows, self.verticalScrollBar().value() * self._scroll_scale) * 16

    def _on_vertical_scroll(self, _value: int):
        self._exact_top_row = None
        self.viewport().update()

    def wheelEvent(self, event):
        if self._exact_top_row is not None and self._scroll_scale > 1:
            delta_y = event.angleDelta().y() if hasattr(event, "angleDelta") else 0
            if delta_y != 0:
                step = -3 if delta_y > 0 else 3
                new_row = max(0, min(self._scrollable_rows, self._exact_top_row + step))
                sb = self.verticalScrollBar()
                sb.blockSignals(True)
                sb.setValue(min(sb.maximum(), new_row // max(1, self._scroll_scale)))
                sb.blockSignals(False)
                self._exact_top_row = new_row
                self.viewport().update()
                event.accept()
                return
        super().wheelEvent(event)

    def clear_source(self):
        self._session = None
        self._entry = None
        self._reset_pages()
        self._scrollable_rows = 0
        self._last_view_info = ""
        self.verticalScrollBar().setRange(0, 0)
        self.horizontalScrollBar().setRange(0, 0)
        self.view_info.emit("")
        self.viewport().update()

    def bind_file(self, session: ForensicSession, part_idx: int, snap_id: str, entry: Dict[str, Any]):
        self._session = session
        self._part_idx = part_idx
        self._snap_id = snap_id
        self._entry = entry
        self._reset_pages()
        self._update_scrollbar()
        self.verticalScrollBar().setValue(0)
        self.viewport().update()

    def visible_rows(self) -> int:
        return max(1, self.viewport().height() // self.row_height)

    def _update_scrollbar(self):
        if not self._entry or self._entry.get("is_dir"):
            self._scrollable_rows = 0
            self.verticalScrollBar().setRange(0, 0)
            self.horizontalScrollBar().setRange(0, 0)
            return
        total_size = max(0, int(self._entry.get("size", 0)))
        total_rows = (total_size + 15) // 16
        vis = self.visible_rows()
        self._scrollable_rows = max(0, total_rows - vis)

        if self._scrollable_rows > self.MAX_QT_SCROLL_RANGE:
            self._scroll_scale = (self._scrollable_rows // self.MAX_QT_SCROLL_RANGE) + 1
            scaled_max = int((self._scrollable_rows + self._scroll_scale - 1) // self._scroll_scale)
        else:
            self._scroll_scale = 1
            scaled_max = int(self._scrollable_rows)

        self.verticalScrollBar().setSingleStep(1)
        self.verticalScrollBar().setPageStep(max(1, vis // self._scroll_scale))
        self.verticalScrollBar().setRange(0, scaled_max)

        content_width = 680
        vp_width = self.viewport().width()
        self.horizontalScrollBar().setSingleStep(16)
        self.horizontalScrollBar().setPageStep(vp_width)
        self.horizontalScrollBar().setRange(0, max(0, content_width - vp_width))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_scrollbar()

    def _on_page_ready(self, generation: int, page_idx: int, data):
        if generation != self._generation:
            return  # result for a file that is no longer displayed
        self._pending_pages.discard(page_idx)
        if page_idx not in self._page_cache and len(self._page_cache) >= self.MAX_CACHED_PAGES:
            self._page_cache.pop(next(iter(self._page_cache)), None)
        self._page_cache[page_idx] = data
        self.viewport().update()

    def _on_page_worker_finished(self, worker: _HexPageWorker):
        self._active_workers.discard(worker)
        if worker.generation == self._generation and worker.page_idx not in self._page_cache:
            self._pending_pages.discard(worker.page_idx)

    def _request_page(self, page_idx: int):
        if (
            page_idx in self._pending_pages
            or len(self._pending_pages) >= self.MAX_PENDING_PAGES
            or not self._session
            or not self._entry
        ):
            return
        self._pending_pages.add(page_idx)
        worker = _HexPageWorker(
            self._session, self._part_idx, self._snap_id, self._entry,
            page_idx, self.PAGE_SIZE, self._generation, self._page_signals,
        )
        self._active_workers.add(worker)
        QThreadPool.globalInstance().start(worker)

    def _read_viewport_row(self, offset: int) -> Tuple[str, bytes]:
        """Returns ("ok", bytes), ("loading", b"") or ("error", b"")."""
        if not self._session or not self._entry:
            return "error", b""
        page_idx = offset // self.PAGE_SIZE
        if page_idx not in self._page_cache:
            self._request_page(page_idx)
            return "loading", b""
        page = self._page_cache[page_idx]
        if page is None:
            return "error", b""
        rel = offset % self.PAGE_SIZE
        chunk = page[rel:rel + 16]
        return ("ok", chunk) if chunk else ("error", b"")

    def session_read(self, offset: int, size: int) -> bytes:
        if not self._session or not self._entry:
            return b""
        return self._session.read_file_slice(self._part_idx, self._snap_id, self._entry, offset, size)

    def paintEvent(self, event):
        painter = QPainter(self.viewport())
        painter.setFont(self.mono_font)

        bg_color = QColor("#14161b") if self._dark_mode else QColor("#ffffff")
        offset_color = QColor("#58a6ff") if self._dark_mode else QColor("#0969da")
        hex_color = QColor("#e6edf3") if self._dark_mode else QColor("#1f2328")
        ascii_color = QColor("#7ee787") if self._dark_mode else QColor("#116329")
        warn_color = QColor("#f85149")

        painter.fillRect(self.viewport().rect(), bg_color)

        if not self._entry or self._entry.get("is_dir"):
            painter.setPen(hex_color)
            painter.drawText(16, 30, "Select a file in the table to inspect raw bytes on demand.")
            return

        file_size = max(0, int(self._entry.get("size", 0)))
        if file_size == 0:
            painter.setPen(hex_color)
            painter.drawText(16, 30, f"File '{self._entry.get('name', '')}' is empty (0 bytes).")
            return

        first_row = self.top_offset() // 16
        x_shift = -self.horizontalScrollBar().value()
        rows_to_draw = self.visible_rows() + 1
        y = self.row_height

        if self._entry.get("meta_realloc"):
            painter.setPen(warn_color)
            painter.drawText(12 + x_shift, y, "⚠ Inode reallocated: these bytes belong to the NEWER file using this inode.")
            y += self.row_height
            rows_to_draw -= 1

        for r in range(first_row, first_row + rows_to_draw):
            offset = r * 16
            if offset >= file_size:
                break
            state, chunk = self._read_viewport_row(offset)

            painter.setPen(offset_color)
            painter.drawText(12 + x_shift, y, f"{offset:010X}")
            if state == "loading":
                painter.setPen(hex_color)
                painter.drawText(120 + x_shift, y, "… loading")
            elif state == "error":
                painter.setPen(warn_color)
                painter.drawText(120 + x_shift, y, "?? unreadable (read error or data shorter than recorded size)")
            else:
                if self._hl_len > 0 and offset < self._hl_start + self._hl_len and offset + len(chunk) > self._hl_start:
                    hl_brush = QColor("#9e6a03") if self._dark_mode else QColor("#ffd33d")
                    cw = self._char_w
                    for i in range(len(chunk)):
                        if self._hl_start <= offset + i < self._hl_start + self._hl_len:
                            painter.fillRect(120 + x_shift + i * 3 * cw, y - self.row_height + 5, 2 * cw, self.row_height - 2, hl_brush)
                            painter.fillRect(530 + x_shift + (1 + i) * cw, y - self.row_height + 5, cw, self.row_height - 2, hl_brush)
                hex_str = " ".join(f"{b:02X}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                painter.setPen(hex_color)
                painter.drawText(120 + x_shift, y, f"{hex_str:<48}")
                painter.setPen(ascii_color)
                painter.drawText(530 + x_shift, y, f"|{ascii_str:<16}|")
            y += self.row_height

        top = first_row * 16
        page = self._page_cache.get(top // self.PAGE_SIZE)
        ent = f"page entropy {shannon_entropy(page):.2f} bits/byte" if page else "page entropy …"
        info = f"Offset 0x{top:X} ({top:,}) of {file_size:,} bytes  |  {ent}"
        if info != self._last_view_info:
            self._last_view_info = info
            self.view_info.emit(info)


class _HexToolSignals(QObject):
    search_done = Signal(int, object, str)   # generation, offset (None = not found), message
    entropy_done = Signal(int, str)          # generation, report
    progress = Signal(int, str)              # generation, status text
    finished = Signal(object)


class HexSearchWorker(QRunnable):
    """FEATURE (2026-11-04): forward byte-pattern search with wrap-around, off the GUI thread."""
    CHUNK = 1 << 20

    def __init__(self, session, part_idx, snap_id, entry, pattern: bytes, start: int,
                 ignore_case: bool, generation: int, signals: _HexToolSignals,
                 encoding: str = "utf-8"):
        super().__init__()
        self.session, self.part_idx, self.snap_id, self.entry = session, part_idx, snap_id, entry
        self.ignore_case = ignore_case
        self.encoding = encoding
        self._regex = None
        if ignore_case:
            if encoding == "utf-16-le":
                self.pattern = pattern
                self._regex = self._compile_ci_regex(pattern, "utf-16-le")
            elif not pattern.isascii():
                self.pattern = pattern
                self._regex = self._compile_ci_regex(pattern, "utf-8")
            else:
                self.pattern = pattern.lower()
        else:
            self.pattern = pattern
        self.start = start
        self.generation = generation
        self.signals = signals
        self.cancel_event = threading.Event()

    @staticmethod
    def _compile_ci_regex(pattern: bytes, encoding: str):
        try:
            text = pattern.decode(encoding)
        except UnicodeDecodeError:
            return None
        parts: List[bytes] = []
        for ch in text:
            base_len = len(ch.encode(encoding))
            variants = sorted({
                c.encode(encoding)
                for c in {ch, ch.lower(), ch.upper(), ch.swapcase()}
                if len(c.encode(encoding)) == base_len
            })
            if len(variants) == 1:
                parts.append(re.escape(variants[0]))
            else:
                parts.append(b"(?:" + b"|".join(re.escape(v) for v in variants) + b")")
        return re.compile(b"".join(parts), re.DOTALL)

    def _scan(self, begin: int, end: int) -> Optional[int]:
        plen = len(self.pattern)
        pos = begin
        carry = b""
        last_report = time.time()
        while pos < end:
            if self.cancel_event.is_set() or self.session.is_aborting:
                return None
            n = min(self.CHUNK, end - pos)
            data = self.session.read_file_slice(self.part_idx, self.snap_id, self.entry, pos, n)
            if not data:
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return None
                raise OSError(f"Unexpected EOF at {pos:,} of {end:,} bytes; search incomplete")
            hay = carry + data
            if self._regex is not None:
                m = self._regex.search(hay)
                idx = m.start() if m else -1
            else:
                if self.ignore_case:
                    hay = hay.lower()
                idx = hay.find(self.pattern)
            if idx >= 0:
                return pos - len(carry) + idx
            carry = (carry + data)[-(plen - 1):] if plen > 1 else b""
            pos += len(data)
            if time.time() - last_report > 0.5:
                last_report = time.time()
                self.signals.progress.emit(self.generation, f"🔍 Searching… 0x{pos:X} / 0x{end:X}")
        return None

    def run(self):
        try:
            size = max(0, int(self.entry.get("size", 0)))
            hit = self._scan(self.start, size)
            wrapped = False
            if hit is None and self.start > 0 and not self.cancel_event.is_set():
                hit = self._scan(0, min(size, self.start + len(self.pattern) - 1))
                wrapped = hit is not None
            if self.cancel_event.is_set() or self.session.is_aborting:
                return
            msg = (f"Found at 0x{hit:X} ({hit:,})" + (" — wrapped to start" if wrapped else "")) if hit is not None else "Pattern not found"
            self.signals.search_done.emit(self.generation, hit, msg)
        except Exception as e:
            if not self.session.is_aborting:
                self.signals.search_done.emit(self.generation, None, f"Search failed: {e}")
        finally:
            self.signals.finished.emit(self)


class FileEntropyWorker(QRunnable):
    """FEATURE (2026-11-04): whole-file entropy plus 64 KiB blocks above 7.5 bits/byte
    (typical of encrypted or compressed data)."""
    BLOCK = 64 * 1024
    HIGH = 7.5

    def __init__(self, session, part_idx, snap_id, entry, generation, signals):
        super().__init__()
        self.session, self.part_idx, self.snap_id, self.entry = session, part_idx, snap_id, entry
        self.generation, self.signals = generation, signals
        self.cancel_event = threading.Event()

    def run(self):
        import math
        from collections import Counter
        try:
            size = max(0, int(self.entry.get("size", 0)))
            total = Counter()
            pos = 0
            high_blocks = 0
            first_high = None
            blocks = 0
            last_report = time.time()
            while pos < size:
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                data = self.session.read_file_slice(self.part_idx, self.snap_id, self.entry, pos, 16 * self.BLOCK)
                if self.cancel_event.is_set() or self.session.is_aborting:
                    return
                if not data:
                    break
                total.update(data)
                for i in range(0, len(data), self.BLOCK):
                    blocks += 1
                    if shannon_entropy(data[i:i + self.BLOCK]) >= self.HIGH:
                        high_blocks += 1
                        if first_high is None:
                            first_high = pos + i
                pos += len(data)
                if time.time() - last_report > 0.5:
                    last_report = time.time()
                    self.signals.progress.emit(self.generation, f"📈 Entropy… {pos * 100 // max(1, size)}%")
            if self.cancel_event.is_set() or self.session.is_aborting:
                return
            n = sum(total.values())
            ent = -sum((c / n) * math.log2(c / n) for c in total.values()) if n else 0.0
            verdict = ("likely encrypted/compressed" if ent >= self.HIGH
                       else "mixed / partly compressed" if ent >= 6.0 else "low (text/code/structured)")
            report = (f"File entropy {ent:.3f} bits/byte ({verdict}); {high_blocks:,} of {blocks:,} "
                      f"64 KiB blocks ≥ {self.HIGH}" + (f", first at 0x{first_high:X}" if first_high is not None else ""))
            if pos < size:
                report += f"  [read stopped at 0x{pos:X} of 0x{size:X}]"
            self.signals.entropy_done.emit(self.generation, report)
        except Exception as e:
            if not self.session.is_aborting:
                self.signals.entropy_done.emit(self.generation, f"Entropy failed: {e}")
        finally:
            self.signals.finished.emit(self)


class HexPanel(QWidget):
    """FEATURE (2026-11-04): hex viewer with go-to-offset, pattern search and entropy."""
    MODES = ("Hex bytes", "ASCII text", "UTF-16LE text")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.viewer = VirtualHexViewer(self)
        self._search_worker: Optional[HexSearchWorker] = None
        self._entropy_worker: Optional[FileEntropyWorker] = None
        self._active_workers: Set[QRunnable] = set()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Go to:"))
        self.offset_edit = QLineEdit()
        self.offset_edit.setPlaceholderText("0x1F40 or 8000")
        self.offset_edit.returnPressed.connect(self.action_goto)
        row1.addWidget(self.offset_edit, 1)
        btn_go = QPushButton("Go")
        btn_go.clicked.connect(self.action_goto)
        row1.addWidget(btn_go)
        self.btn_entropy = QPushButton("File Entropy")
        self.btn_entropy.clicked.connect(self.action_file_entropy)
        row1.addWidget(self.btn_entropy)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(list(self.MODES))
        row2.addWidget(self.mode_combo)
        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText("4D 5A 90 00   /   text to find")
        self.find_edit.returnPressed.connect(self.action_find_next)
        row2.addWidget(self.find_edit, 1)
        self.case_check = QCheckBox("Ignore case")
        row2.addWidget(self.case_check)
        btn_find = QPushButton("Find Next")
        btn_find.clicked.connect(self.action_find_next)
        row2.addWidget(btn_find)
        layout.addLayout(row2)

        layout.addWidget(self.viewer, 1)
        self.info_label = QLabel("")
        self.info_label.setTextFormat(TEXT_PLAIN)
        self.info_label.setStyleSheet("font-size: 11px;")
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)
        self.result_label = QLabel("")
        self.result_label.setTextFormat(TEXT_PLAIN)
        self.result_label.setStyleSheet("font-size: 11px; font-weight: 600;")
        self.result_label.setWordWrap(True)
        layout.addWidget(self.result_label)
        self.viewer.view_info.connect(self.info_label.setText)

    def cancel_tasks(self):
        for w in (self._search_worker, self._entropy_worker):
            if w is not None:
                w.cancel_event.set()
        self._search_worker = self._entropy_worker = None
        self.result_label.setText("")

    def _bound(self):
        v = self.viewer
        if not v._session or not v.bound_entry or v.bound_entry.get("is_dir"):
            self.result_label.setText("Select a file first.")
            return None
        return v._session, v._part_idx, v._snap_id, v.bound_entry

    def action_goto(self):
        if not self._bound():
            return
        try:
            off = parse_offset(self.offset_edit.text())
        except ValueError:
            self.result_label.setText("Offset must be decimal (8000) or hex (0x1F40 / 1F40h).")
            return
        size = int(self.viewer.bound_entry.get("size", 0))
        if off >= size:
            self.result_label.setText(f"Offset 0x{off:X} is past the end (size 0x{size:X}).")
            return
        self.viewer.goto_offset(off, 1)
        self.result_label.setText(f"At 0x{off:X} ({off:,})")

    def _pattern(self) -> bytes:
        text = self.find_edit.text()
        mode = self.mode_combo.currentText()
        if not text:
            raise ValueError("Enter something to find.")
        if mode == "Hex bytes":
            return parse_hex_pattern(text)
        if mode == "UTF-16LE text":
            return text.encode("utf-16-le")
        return text.encode("utf-8")

    def action_find_next(self):
        bound = self._bound()
        if not bound:
            return
        try:
            pattern = self._pattern()
        except ValueError as e:
            self.result_label.setText(str(e))
            return
        if self._search_worker is not None:
            self._search_worker.cancel_event.set()
        start = self.viewer.highlight_start() + 1 if self.viewer.highlight_start() >= 0 else self.viewer.top_offset()
        mode = self.mode_combo.currentText()
        ignore_case = self.case_check.isChecked() and mode != "Hex bytes"
        encoding = "utf-16-le" if mode == "UTF-16LE text" else "utf-8"
        session, part_idx, snap_id, entry = bound
        signals = _HexToolSignals()
        worker = HexSearchWorker(
            session, part_idx, snap_id, entry, pattern, start, ignore_case,
            self.viewer.generation, signals, encoding=encoding,
        )
        self._search_worker = worker
        signals.search_done.connect(lambda *args: self._on_search_done(*args)
                                    if self._search_worker is worker else None)
        signals.progress.connect(lambda *args: self._on_progress(*args)
                                 if self._search_worker is worker else None)
        signals.finished.connect(self._active_workers.discard)
        self._search_len = len(pattern)
        self.result_label.setText("🔍 Searching…")
        self._active_workers.add(worker)
        QThreadPool.globalInstance().start(worker)

    def action_file_entropy(self):
        bound = self._bound()
        if not bound:
            return
        if self._entropy_worker is not None:
            self._entropy_worker.cancel_event.set()
        session, part_idx, snap_id, entry = bound
        signals = _HexToolSignals()
        worker = FileEntropyWorker(session, part_idx, snap_id, entry, self.viewer.generation, signals)
        self._entropy_worker = worker
        signals.entropy_done.connect(lambda *args: self._on_entropy_done(*args)
                                     if self._entropy_worker is worker else None)
        signals.progress.connect(lambda *args: self._on_progress(*args)
                                 if self._entropy_worker is worker else None)
        signals.finished.connect(self._active_workers.discard)
        self.result_label.setText("📈 Computing file entropy…")
        self._active_workers.add(worker)
        QThreadPool.globalInstance().start(worker)

    def _on_progress(self, generation: int, text: str):
        if generation == self.viewer.generation:
            self.result_label.setText(text)

    def _on_search_done(self, generation: int, offset, message: str):
        if generation != self.viewer.generation:
            return
        self._search_worker = None
        if offset is not None:
            self.viewer.goto_offset(int(offset), getattr(self, "_search_len", 1))
        self.result_label.setText(message)

    def _on_entropy_done(self, generation: int, report: str):
        if generation != self.viewer.generation:
            return
        self._entropy_worker = None
        self.result_label.setText(report)


# ============================================================================
# Section 7: Automated Forensic Self-Test Suite (Run via --self-test or Help)
# ============================================================================

def run_automated_self_tests() -> Tuple[bool, str]:
    results: List[str] = []
    all_passed = True

    def record(test_name: str, passed: bool, detail: str = ""):
        nonlocal all_passed
        if not passed:
            all_passed = False
        badge = "✅ PASS" if passed else "❌ FAIL"
        results.append(f"{badge} | {test_name}: {detail}")

    tmp_sql_dir = tempfile.mkdtemp(prefix="vscexplorer_sql_persist_")
    custom_db = os.path.join(tmp_sql_dir, "persist_test.sqlite")

    try:
        session = ForensicSession("self_test_case", is_demo=True, custom_db_path=custom_db)

        # Test 1: Multi-Threaded Concurrent Read + SQLite Query Stress Test
        entry = session.list_directory_sync(0, "Live", "/Users/Analyst")[1]
        baseline_digest = hashlib.sha256(
            session.read_file_slice(0, "Live", entry, 0, 16384)
        ).hexdigest()
        thread_errors: List[str] = []

        def worker_stress():
            try:
                for _ in range(40):
                    buf = session.read_file_slice(0, "Live", entry, 0, 16384)
                    rows = session.index_db.get_directory_children(0, "Live", "/Users/Analyst")
                    if hashlib.sha256(buf).hexdigest() != baseline_digest or len(rows) < 3:
                        thread_errors.append("Concurrency mismatch")
            except Exception as exc:
                thread_errors.append(str(exc))

        threads = [threading.Thread(target=worker_stress) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        record("Multi-Threaded I/O & SQLite WAL Concurrency", len(thread_errors) == 0, "8 threads x 40 ops")

        # Test 2: Partition Slot 1-to-1 Alignment & BitLocker Unlock Idempotency
        slots_aligned = all(pm.index == idx for idx, pm in enumerate(session.partitions))
        pm1 = session.partitions[1]
        was_locked = not pm1.bitlocker_info.is_unlocked
        try:
            session.list_directory_sync(1, "Live", "/")
            locked_blocked = False
        except PermissionError:
            locked_blocked = True
        locked_not_seeded = not session.index_db.is_directory_cached(1, "Live", "/")
        # The demo now checks its secret, so a wrong (or whitespace-padded) password must fail.
        wrong_rejected = (
            not BitLockerAnalyzer.unlock_bitlocker_volume(pm1.bitlocker_info, password="wrong")
            and not BitLockerAnalyzer.unlock_bitlocker_volume(pm1.bitlocker_info, password=f"  {DEMO_BITLOCKER_PASSWORD}  ")
            and not pm1.bitlocker_info.is_unlocked
        )
        unlock_ok = BitLockerAnalyzer.unlock_bitlocker_volume(pm1.bitlocker_info, password=DEMO_BITLOCKER_PASSWORD)
        session.finalize_unlock(pm1)
        re_unlock_ok = BitLockerAnalyzer.unlock_bitlocker_volume(pm1.bitlocker_info, password=DEMO_BITLOCKER_PASSWORD)
        unlocked_seeded = session.index_db.is_directory_cached(1, "Live", "/")
        record(
            "Partition 1-to-1 Slot Alignment & BitLocker Unlock",
            slots_aligned and was_locked and locked_blocked and locked_not_seeded
            and wrong_rejected and unlock_ok and re_unlock_ok and unlocked_seeded
            and pm1.bitlocker_info.is_unlocked,
            f"{pm1.bitlocker_info.volume_id} (locked blocked={locked_blocked}, wrong/padded password rejected={wrong_rejected})",
        )

        # Test 3: Cycle-Safe & Collision-Safe Recursive Folder Export (Repeat Export Test)
        tmp_export_dir = tempfile.mkdtemp(prefix="vscexplorer_export_")
        try:
            analyst_dir = next(
                e for e in session.list_directory_sync(0, "Live", "/Users") if e["name"] == "Analyst"
            )
            for _run_num in range(2):
                export_worker = BufferedExportWorker(
                    session=session,
                    part_idx=0,
                    snap_id="Live",
                    root_items=[analyst_dir],
                    dest_dir=tmp_export_dir,
                    export_options={"generate_csv": True, "include_hashes": True, "hash_types": ["md5", "sha256"]},
                )
                export_worker.run()
            csv_file = os.path.join(tmp_export_dir, "export_summary.csv")
            nested_file = os.path.join(tmp_export_dir, "Analyst", "Documents", "incident_notes.txt")
            dedup_dir = os.path.join(tmp_export_dir, "Analyst_[inode_202]")
            has_csv = os.path.exists(csv_file)
            has_nested = os.path.exists(nested_file) and os.path.getsize(nested_file) == 8192
            has_dedup = os.path.isdir(dedup_dir)
            # The second run must not overwrite the first run's manifest.
            manifests = [f for f in os.listdir(tmp_export_dir) if f.startswith("export_summary")]
            record(
                "Recursive Export & Repeat Host Collision Protection",
                has_csv and has_nested and has_dedup and len(manifests) == 2,
                f"Verified nested file + collision-safe folder suffix + {len(manifests)} separate manifests",
            )
        finally:
            shutil.rmtree(tmp_export_dir, ignore_errors=True)

        # Test 4: SQLite C-Speed Full-Volume VSS Snapshot Diff (VSS_0 vs Live)
        diff_worker = SnapshotDiffWorker(session, 0, "VSS_0", "Live")
        captured_diffs: List[Dict[str, Any]] = []
        diff_worker.signals.diff_ready.connect(lambda _tok, d: captured_diffs.extend(d))
        diff_worker.run()
        deltas = {d["path"]: d["delta"] for d in captured_diffs}
        diff_ok = (
            deltas.get("/Users/Analyst/stage2_beacon.ps1") == "CREATED"
            and deltas.get("/Users/Analyst/exfil_staging.zip") == "DELETED"
            and deltas.get("/Users/Analyst/financial_audit_2026.xlsx") == "MODIFIED"
        )
        record("SQLite C-Speed VSS Snapshot Diff Engine", diff_ok, f"Found {len(captured_diffs)} delta entries")

        # Test 5: Timezone, Overflow Guard & Windows 64-Bit FILETIME Conversion Accuracy
        ist_tz = resolve_tzinfo("Asia/Kolkata")
        utc_str = format_epoch_tz(0, datetime.timezone.utc)
        ist_str = format_epoch_tz(0, ist_tz)
        ft_epoch = coerce_forensic_epoch(134_116_992_000_000_000)
        # Seconds are no longer clamped to 3000-01-01 (that fabricated a date).
        unclamped_epoch = coerce_forensic_epoch(99_999_999_999)
        tz_ok = (
            utc_str == "1970-01-01 00:00:00"
            and ist_str == "1970-01-01 05:30:00"
            # FIX (2026-11-02): 134116992000000000 FILETIME is 2026-01-01
            # (1767225600), not 2026-01-02 (1767312000) as the old test
            # claimed -- the old assertion failed on every run.
            and ft_epoch == 1767225600
            and unclamped_epoch == 99_999_999_999
        )
        record("Epoch Zero, Timezone Offset, No Clamping & FILETIME", tz_ok, f"UTC={utc_str}, IST={ist_str}")
        # FIX (2026-11-02, issue 3 regression): ms/us/ns epochs for the
        # same instant must not return None, as the old code did for ms.
        ms_ok = (
            coerce_forensic_epoch(1767312000 * 1000) == 1767312000
            and coerce_forensic_epoch(1767312000 * 1_000_000) == 1767312000
            and coerce_forensic_epoch(1767312000 * 1_000_000_000) == 1767312000
            and coerce_forensic_epoch(134_117_856_000_000_000) == 1767312000
        )
        record("Millisecond/Microsecond/Nanosecond Epoch Conversion", ms_ok,
               "ms/us/ns/FILETIME for 2026-01-02 all map to 1767312000")

        # Test 6: SQLite WAL Invalidation, Re-Query & Persistence Across Session Restart
        session.invalidate_directory_cache(0, "Live", "/Users")
        re_queried = session.list_directory_sync(0, "Live", "/Users")
        session.close()
        reopened_session = ForensicSession("self_test_case", is_demo=True, custom_db_path=custom_db)
        was_persisted = (
            len(re_queried) == 2
            and reopened_session.get_known_child_dir_count(0, "Live", "/Users/Administrator") == 0
            and reopened_session.get_known_child_dir_count(0, "Live", "/Users") == 2
        )
        reopened_session.close()
        record("SQLite WAL Invalidation & Persistence Across Restart", was_persisted, "Index & child counts survived restart")

        # Test 7 (2026-11-03): TSK seconds are shown as recorded (timestomp tells survive)
        y9999 = 253_370_764_800   # 9999-01-01
        y1601 = -11_644_473_600   # 1601-01-01 (FILETIME zero)
        dt1601 = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt9999 = datetime.datetime(9999, 1, 1, tzinfo=datetime.timezone.utc)
        ts_ok = (
            coerce_tsk_epoch(y9999) == y9999
            and coerce_forensic_epoch(dt1601) == y1601
            and coerce_forensic_epoch(dt9999) == y9999
            and format_epoch_tz(coerce_tsk_epoch(y9999), datetime.timezone.utc) == "9999-01-01 00:00:00"
            and format_epoch_tz(coerce_tsk_epoch(y1601), datetime.timezone.utc) == "1601-01-01 00:00:00"
            and coerce_tsk_epoch(0) is None
        )
        record("Anti-Forensic Timestamp Fidelity (1601 / 9999)", ts_ok,
               f"9999 -> {format_epoch_tz(coerce_tsk_epoch(y9999), datetime.timezone.utc)}")

        # Test 8 (2026-11-03): backslash is a filename character, not a separator
        path_ok = (
            normalize_forensic_path("/x/..\\..") == "/x/..\\.."
            and normalize_forensic_path("/Users/..\\Windows") == "/Users/..\\Windows"
            and normalize_forensic_path("//a/./b/") == "/a/b"
        )
        record("Path Normalisation Keeps Backslash Names", path_ok, "'..\\..' is not collapsed to '/'")

        # Test 9 (2026-11-03): export hardening (manifest name, CSV injection, long/reserved names)
        tmp_harden = tempfile.mkdtemp(prefix="vscexplorer_harden_")
        hard_session = ForensicSession("self_test_harden", is_demo=True)
        try:
            base = dict(is_dir=False, is_deleted=False, mtime=1767225600, ctime=1767225600,
                        crtime=1767225600, atime=1767225600, ads=[])
            long_name = "文" * 200 + ".txt"
            items = [
                dict(base, name="export_summary.csv", path="/export_summary.csv", size=4096, inode=900),
                dict(base, name='=HYPERLINK("http://x","y")', path='/=HYPERLINK("http://x","y")', size=10, inode=901),
                dict(base, name=long_name, path="/" + long_name, size=10, inode=902),
                dict(base, name="CON.tar.gz", path="/CON.tar.gz", size=10, inode=903),
            ]
            BufferedExportWorker(hard_session, 0, "Live", items, tmp_harden,
                                 {"generate_csv": True, "include_hashes": False, "hash_types": []}).run()
            names = os.listdir(tmp_harden)
            evidence_kept = any(n.startswith("export_summary_[inode_900]") for n in names)
            manifest = os.path.join(tmp_harden, "export_summary.csv")
            with open(manifest, encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            injected = [r for r in rows if "HYPERLINK" in r["Name"]]
            csv_neutralised = bool(injected) and injected[0]["Name"].startswith("'=")
            long_ok = any(r["Name"].startswith("文") and r["Export_Status"] == "Success" for r in rows)
            reserved_ok = "_CON.tar.gz" in names
            record(
                "Export Hardening (manifest clash, CSV injection, long & reserved names)",
                evidence_kept and csv_neutralised and long_ok and reserved_ok,
                f"evidence kept={evidence_kept}, csv safe={csv_neutralised}, long={long_ok}, reserved={reserved_ok}",
            )
        finally:
            hard_session.close()
            shutil.rmtree(tmp_harden, ignore_errors=True)

        # Test 10 (2026-11-03): BitLocker tables match libbde definitions.h
        bde_ok = (
            BitLockerAnalyzer.get_key_protector_type_name(0x2000) == "Password"
            and BitLockerAnalyzer.get_key_protector_type_name(0x0200).startswith("Startup Key")
            and BitLockerAnalyzer.get_key_protector_type_name(0x0100) == "TPM"
            and BitLockerAnalyzer.get_key_protector_type_name(0x0000).startswith("Clear Key")
            and BitLockerAnalyzer.ENCRYPTION_METHODS[0x8004] == "XTS-AES 128-bit"
            and BitLockerAnalyzer.ENCRYPTION_METHODS[0x8005] == "XTS-AES 256-bit"
        )
        record("BitLocker Protector & Cipher Codes (libbde)", bde_ok, "0x2000=Password, 0x8004=XTS-AES-128")

        # Test 11 (2026-11-03): partial-diff exclusion keeps unindexed subtrees out of results
        roots = {"/Windows/Temp"}
        excl_ok = (
            SnapshotDiffWorker._is_under_any("/Windows/Temp", roots)
            and SnapshotDiffWorker._is_under_any("/Windows/Temp/a/b", roots)
            and not SnapshotDiffWorker._is_under_any("/Windows", roots)
            and not SnapshotDiffWorker._is_under_any("/Windows/TempX", roots)
            and SnapshotDiffWorker._is_under_any("/anything", {"/"})
        )
        record("Partial Diff Subtree Exclusion", excl_ok, "unreadable folders are excluded, siblings kept")

        # Test 12 (2026-11-04): ADS records, stream reads, Mark-of-the-Web and UTF-16 text
        ads_session = ForensicSession("self_test_ads", is_demo=True)
        try:
            beacon = next(e for e in ads_session.list_directory_sync(0, "Live", "/Users/Analyst")
                          if e["name"] == "stage2_beacon.ps1")
            streams = ads_streams(beacon)
            zone_row = make_ads_entry(beacon, next(st for st in streams if st["name"] == "Zone.Identifier"))
            zone = parse_zone_identifier(ads_session.read_file_slice(0, "Live", zone_row, 0, 4096))
            legacy = ads_streams({"ads": ["Zone.Identifier (142 B)"]})
            u16 = decode_text_bytes("hello world".encode("utf-16-le"))
            bom = decode_text_bytes("x".encode("utf-16"))
            ads_ok = (
                [st["name"] for st in streams] == ["Zone.Identifier", "hidden_config.bin"]
                and zone_row["path"] == "/Users/Analyst/stage2_beacon.ps1:Zone.Identifier"
                and zone.get("ZoneId") == "3"
                and legacy == [{"name": "Zone.Identifier", "size": 142, "id": None}]
                and u16 == ("hello world", "UTF-16LE (detected)")
                and bom[1] == "UTF-16LE (BOM)"
                and ads_export_skipped({"ads_host": "$BadClus", "ads_stream": "$Bad", "ads_host_path": "/$BadClus"})
            )
            record("ADS Streams, Mark-of-the-Web & UTF-16 Text Detection", ads_ok,
                   f"{len(streams)} streams, ZoneId={zone.get('ZoneId')}, utf16={u16[1]}")
        finally:
            ads_session.close()

        # Test 13 (2026-11-04): hex tools (pattern/offset parsing, entropy, chunked search)
        hex_session = ForensicSession("self_test_hex", is_demo=True)
        try:
            ntuser = next(e for e in hex_session.list_directory_sync(0, "Live", "/Users/Analyst")
                          if e["name"] == "NTUSER.DAT")
            sig = _HexToolSignals()
            hits: List[Any] = []
            sig.search_done.connect(lambda _g, off, _m: hits.append(off))
            # bytes straddling the 1 MiB chunk boundary must still be found
            target = (1 << 20) - 2
            needle = hex_session.read_file_slice(0, "Live", ntuser, target, 6)
            HexSearchWorker(hex_session, 0, "Live", ntuser, needle, target - 100, False, 0, sig).run()
            HexSearchWorker(hex_session, 0, "Live", ntuser, b"\xde\xad\xbe\xef\x00\x11", 0, False, 0, sig).run()
            u16_rx = HexSearchWorker._compile_ci_regex("䄀AdminПароли".encode("utf-16-le"), "utf-16-le")
            u16_hay = b"\x00\x61" + "䄀aDmInПАРОЛИ".encode("utf-16-le")
            u16_match = u16_rx.search(u16_hay) if u16_rx is not None else None
            hex_ok = (
                parse_hex_pattern("4D 5A 90 00") == b"MZ\x90\x00"
                and parse_hex_pattern("0x4d,0x5a") == b"MZ"
                and parse_offset("0x1F40") == 8000 and parse_offset("1F40h") == 8000 and parse_offset("8000") == 8000
                and shannon_entropy(b"\x00" * 100) == 0.0
                and abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9
                and hits[0] == target and hits[1] is None
                and u16_match is not None and u16_match.start() == 2
            )
            # Test 14 (2026-11-04): snapshot-wide index search
            idx_worker = SnapshotIndexWorker(hex_session, 0, [sn["id"] for sn in hex_session.partitions[0].snapshots])
            idx_worker.run()
            db = hex_session.index_db
            snaps = [sn["id"] for sn in hex_session.partitions[0].snapshots]
            r_contains, _ = db.search_entries(0, snaps, "EXFIL", "contains")
            r_live_only, _ = db.search_entries(0, ["Live"], "exfil", "contains", include_deleted=False)
            r_wild, _ = db.search_entries(0, snaps, "*.ps1", "wildcard")
            r_regex, _ = db.search_entries(0, ["Live"], r"^(ntuser|nothing)\.dat$", "regex")
            r_ads, _ = db.search_entries(0, ["Live"], "hidden_config", "contains", include_ads=True)
            r_pct, _ = db.search_entries(0, ["Live"], "%", "contains")   # LIKE metacharacters are literal
            r_dirs, _ = db.search_entries(0, ["Live"], "s", "contains", kind="dirs")
            search_ok = (
                len(r_contains) == 4 and r_live_only == []
                and sorted(x["source_snap"] for x in r_wild) == ["Live", "VSS_2"]
                and len(r_regex) == 1 and [x["path"] for x in r_ads] == ["/Users/Analyst/stage2_beacon.ps1:hidden_config.bin"]
                and r_pct == [] and r_dirs and all(x["is_dir"] for x in r_dirs)
                and all(db.index_coverage(0, sn)[1] for sn in snaps)
            )
            record("Snapshot-Wide Index Search (contains/wildcard/regex/ADS)", search_ok,
                   f"exfil in {len(r_contains)} snapshots, *.ps1 in {sorted(x['source_snap'] for x in r_wild)}")

            # Test 15 (2026-11-04): version history across snapshots
            beacon = next(e for e in hex_session.list_directory_sync(0, "Live", "/Users/Analyst")
                          if e["name"] == "stage2_beacon.ps1")
            exfil = next(e for e in hex_session.list_directory_sync(0, "Live", "/Users/Analyst")
                         if e["name"] == "exfil_staging.zip")
            hist_rows: List[Any] = []
            hw = VersionHistoryWorker(hex_session, 0, beacon, 1)
            hw.signals.history_ready.connect(lambda _t, _r, rows: hist_rows.extend(rows))
            hw.run()
            zone_hist: List[Any] = []
            zw = VersionHistoryWorker(hex_session, 0, make_ads_entry(beacon, ads_streams(beacon)[0]), 2)
            zw.signals.history_ready.connect(lambda _t, _r, rows: zone_hist.extend(rows))
            zw.run()
            exfil_hist: List[Any] = []
            ew = VersionHistoryWorker(hex_session, 0, exfil, 3)
            ew.signals.history_ready.connect(lambda _t, _r, rows: exfil_hist.extend(rows))
            ew.run()
            hist_ok = (
                [r_["snap_id"] for r_ in hist_rows] == ["VSS_0", "VSS_1", "VSS_2", "Live"]
                and [r_["state"] for r_ in hist_rows] == ["Not present", "Not present", "Present", "Present"]
                and [r_["change"] for r_ in hist_rows][2:] == ["first seen", "unchanged"]
                and len(hist_rows[2]["sha256"]) == 64
                and [r_["change"] for r_ in zone_hist][2:] == ["first seen", "unchanged"]
                and [r_["change"] for r_ in exfil_hist][:2] == ["first seen", "deleted (content intact)"]
            )
            record("File Version History Across Snapshots", hist_ok,
                   " / ".join(f"{r_['snap_id']}:{r_['state']}" for r_ in hist_rows))

            # Test 16 (2026-11-04): case store (bookmarks survive reopen) + escaped report
            store = CaseStore.for_session(hex_session)
            try:
                store.set_info({"case_number": "T-1", "examiner": "<img src=x onerror=alert(1)>"})
                store.upsert_bookmark(0, "Live", beacon, "Malware", "note <script>x</script>")
                store.upsert_bookmark(0, "Live", beacon, "Persistence", "updated")  # same item: update
                store.upsert_bookmark(0, "VSS_2", make_ads_entry(beacon, ads_streams(beacon)[1]), "Malware", "")
                reopened = CaseStore(store.db_path)
                bms = reopened.list_bookmarks()
                reopened.close()
                rep = CaseReportWorker(hex_session, store)
                rep_data: List[Any] = []
                rep.signals.report_ready.connect(lambda _t, d: rep_data.append(d))
                rep.run()
                html_doc = build_case_report_html(hex_session, rep_data[0])
                case_ok = (
                    len(bms) == 2 and {b["tag"] for b in bms} == {"Persistence", "Malware"}
                    and store.is_bookmarked(0, "Live", beacon) and not store.is_bookmarked(0, "VSS_1", beacon)
                    and "<img src=x" not in html_doc and "&lt;img src=x" in html_doc
                    and "<script>x" not in html_doc
                    and all(len(b.get("sha256", "")) == 64 for b in rep_data[0]["bookmarks"])
                )
                record("Case Store Bookmarks & Escaped HTML Report", case_ok,
                       f"{len(bms)} bookmarks persisted; report {len(html_doc):,} chars")
            finally:
                store.close()

            # Test 17 (2026-11-04, second audit): regressions for the audit fixes
            audit_dir = tempfile.mkdtemp(prefix="vscexplorer_audit_")
            try:
                for n in (1, 2, 4):  # .003 missing
                    with open(os.path.join(audit_dir, f"img.{n:03d}"), "wb") as fh:
                        fh.write(b"\0" * 512)
                try:
                    split_raw_segments(os.path.join(audit_dir, "img.001"))
                    gap_ok = False
                except RuntimeError as gap_err:
                    gap_ok = "img.003" in str(gap_err)
                with open(os.path.join(audit_dir, "base.vmdk"), "wb") as fh:
                    fh.write(b"x")
                child = os.path.join(audit_dir, "child.vmdk")
                parent_ok = (
                    _resolve_parent_image(child, "/etc/passwd") is None
                    and _resolve_parent_image(child, r"C:\VMs\base.vmdk") == os.path.join(audit_dir, "base.vmdk")
                    and _resolve_parent_image(child, "..") is None
                )
                adb = SnapshotIndexDB("audit", 1, is_demo=True)
                try:
                    base_e = dict(is_dir=False, is_deleted=False, size=10, mtime=100, ctime=100, crtime=100, atime=100)
                    adb.insert_directory_batch(0, "A", "/", [
                        dict(base_e, name="a.txt", path="/a.txt", inode=5, ads=[]),
                        dict(base_e, name="same.txt", path="/same.txt", inode=7, ads=[{"name": "s", "size": 1, "id": 3}]),
                        dict(base_e, name="Пароли.txt", path="/Пароли.txt", inode=8, ads=[]),
                    ])
                    adb.insert_directory_batch(0, "B", "/", [
                        dict(base_e, name="a.txt", path="/a.txt", inode=5, ads=[{"name": "hidden", "size": 9, "id": 3}]),
                        dict(base_e, name="same.txt", path="/same.txt", inode=7, ads=[{"name": "s", "size": 1, "id": 9}]),
                        dict(base_e, name="Пароли.txt", path="/Пароли.txt", inode=8, ads=[]),
                        dict(base_e, name="new.exe", path="/new.exe", inode=6, ads=[{"name": "Zone.Identifier", "size": 90, "id": 4}]),
                    ])
                    adiff = {d_["path"]: d_ for d_ in adb.compute_snapshot_diff(0, "A", "B")}
                    uni = [x["name"] for x in adb.search_entries(0, ["A"], "пароли")[0]]
                finally:
                    adb.close()
                diff_ads_ok = (
                    adiff.get("/a.txt", {}).get("ads_change") == "+hidden"
                    and "/same.txt" not in adiff
                    and [x["name"] for x in adiff["/new.exe"]["ads"]] == ["Zone.Identifier"]
                )
                skip_ok = (ads_export_skipped({"ads_host": "$BadClus", "ads_stream": "$Bad", "ads_host_path": "/$BadClus"})
                           and not ads_export_skipped({"ads_host": "$BadClus", "ads_stream": "$Bad", "ads_host_path": "/u/$BadClus"}))
                fp_store = CaseStore(os.path.join(audit_dir, "fp.vsccase.sqlite"))
                try:
                    first = fp_store.check_fingerprint("fp-1")
                    same = fp_store.check_fingerprint("fp-1")
                    changed = fp_store.check_fingerprint("fp-2")
                    fp_store.upsert_bookmark(0, "Live", {"path": "/x", "inode": 1, "name": "x"}, "A", "")
                    fp_store.upsert_bookmark(0, "Live", {"path": "/x", "inode": 1, "name": "x"}, "B", "n")
                    one_row = [(b_["tag"], b_["note"]) for b_ in fp_store.list_bookmarks()] == [("B", "n")]
                finally:
                    fp_store.close()
                for idx_c in range(260):
                    hex_session._remember_directory((9, "Live", f"/dir_{idx_c}"), [])
                fifo_ok = len(hex_session.directory_cache) == 256 and (9, "Live", "/dir_259") in hex_session.directory_cache
                inode0_ok = (
                    not ForensicSession.needs_inode_open({"inode": 0, "is_deleted": True, "is_dir": True})
                    and ForensicSession.needs_inode_open({"inode": 42, "is_deleted": True, "is_dir": True})
                )
                for n in (1, 2):
                    with open(os.path.join(audit_dir, f"ok.{n:03d}"), "wb") as fh:
                        fh.write(b"\0" * 512)
                for ext_s in ("E01", "E02", "EAA"):
                    with open(os.path.join(audit_dir, f"ewfset.{ext_s}"), "wb") as fh:
                        fh.write(b"\0" * 64)
                seg_db = SnapshotIndexDB(os.path.join(audit_dir, "ok.001"), 1024, is_demo=True)
                try:
                    segs_ok = (
                        len(seg_db._image_segment_paths()) == 2
                        and ForensicSession._is_ewf_path("ewfset.EAA")
                        and ForensicSession._is_ewf_path("ewfset.Ex02")
                        and len(ewf_segment_paths(os.path.join(audit_dir, "ewfset.E02"))) == 3
                    )
                finally:
                    seg_db.close()
                abort_sess = ForensicSession("abort_test", is_demo=True)
                try:
                    abort_entry = next(
                        e for e in abort_sess.list_directory_sync(0, "Live", "/Users/Analyst")
                        if e["name"] == "NTUSER.DAT"
                    )
                    cancel_out = os.path.join(audit_dir, "cancel_export")
                    cexp = BufferedExportWorker(
                        abort_sess, 0, "Live", [abort_entry], cancel_out,
                        {"generate_csv": True, "include_hashes": True, "hash_types": ["sha256"]},
                    )
                    cexp_done: List[Any] = []
                    cexp.signals.export_done.connect(lambda *a: cexp_done.append(a))
                    cexp.cancel()
                    cexp.run()
                    abort_sess.request_abort()
                    try:
                        abort_sess.list_directory_sync(0, "Live", "/")
                        abort_dir_raised = False
                    except RuntimeError:
                        abort_dir_raised = True
                    vh_abort: List[Any] = []
                    vhw = VersionHistoryWorker(abort_sess, 0, abort_entry, 99)
                    vhw.signals.history_ready.connect(lambda *a: vh_abort.append(a))
                    vhw.run()
                    abort_ok = (
                        bool(cexp_done) and cexp_done[0][3] is True and cexp_done[0][0] == 0
                        and not os.path.exists(os.path.join(cancel_out, "NTUSER.DAT"))
                        and abort_dir_raised and vh_abort == []
                    )
                finally:
                    abort_sess.close()
                fp_ok = (
                    first is None and same is None and changed == "fp-1"
                    and one_row and fifo_ok and inode0_ok and segs_ok and abort_ok
                )
            finally:
                shutil.rmtree(audit_dir, ignore_errors=True)
            record("Audit Regressions (split gap, parent path, Unicode search, diff ADS, case fingerprint)",
                   gap_ok and parent_ok and uni == ["Пароли.txt"] and diff_ads_ok and skip_ok and fp_ok,
                   f"gap={gap_ok} parent={parent_ok} unicode={uni} diffADS={diff_ads_ok} skip={skip_ok} fp={fp_ok}")

            record("Hex Tools: Pattern/Offset Parsing, Entropy, Cross-Chunk Search", hex_ok,
                   f"boundary hit at 0x{hits[0]:X}" if hits and hits[0] is not None else f"hits={hits}")
        finally:
            hex_session.close()

    except Exception as exc:
        all_passed = False
        results.append(f"❌ FAIL | Unhandled Self-Test Exception: {exc}")
    finally:
        shutil.rmtree(tmp_sql_dir, ignore_errors=True)

    return all_passed, "\n".join(results)


class SearchResultsModel(QAbstractTableModel):
    """FEATURE (2026-11-04)"""
    HEADERS = ["Snapshot", "Name", "Path", "Size", "Modified", "State"]
    SORT_ROLE = ROLE_USER + 1

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[Dict[str, Any]] = []
        self._tz: datetime.tzinfo = datetime.timezone.utc

    def set_rows(self, rows: List[Dict[str, Any]], tz: datetime.tzinfo):
        self.beginResetModel()
        self._rows, self._tz = rows, tz
        self.endResetModel()

    def rows(self) -> List[Dict[str, Any]]:
        return self._rows

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=ROLE_DISPLAY):
        if orientation == ORIENT_HORIZONTAL and role == ROLE_DISPLAY:
            return self.HEADERS[section]
        return None

    @staticmethod
    def _state(e: Dict[str, Any]) -> str:
        bits = []
        if e.get("ads_stream") is not None:
            bits.append("ADS stream")
        if e.get("is_deleted"):
            bits.append("Deleted")
        if e.get("meta_realloc"):
            bits.append("inode reallocated")
        if ads_streams(e):
            bits.append(f"{ADS_BADGE}{len(ads_streams(e))}")
        return ", ".join(bits) or ("Folder" if e.get("is_dir") else "")

    def data(self, index, role=ROLE_DISPLAY):
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        e = self._rows[index.row()]
        c = index.column()
        if role == ROLE_USER:
            return e
        if role == self.SORT_ROLE:
            return [e.get("source_snap", ""), e["name"].lower(), e["path"].lower(),
                    int(e.get("size", 0)), _ts_sort_key(e.get("mtime")), self._state(e)][c]
        if role == ROLE_DISPLAY:
            if c == 0:
                return e.get("source_snap", "")
            if c == 1:
                icon = ADS_BADGE if e.get("ads_stream") is not None else FileIconProvider.get_file_icon(
                    e["name"], e["is_dir"], bool(e.get("is_deleted")))
                return f"{icon} {e['name']}"
            if c == 2:
                return e["path"]
            if c == 3:
                return "—" if e["is_dir"] else format_size_human(int(e.get("size", 0)))
            if c == 4:
                return format_epoch_tz(e.get("mtime"), self._tz)
            if c == 5:
                return self._state(e)
        if role == ROLE_FOREGROUND and e.get("is_deleted"):
            return QColor("#e5534b")
        return None


class SnapshotSearchDialog(QDialog):
    """FEATURE (2026-11-04): search names across a snapshot (or all snapshots) using the
    SQLite index. Only folders already in the index are searched; 'Index Snapshot(s)'
    crawls the rest first."""

    def __init__(self, main: "VSCExplorerMainWindow"):
        super().__init__(main)
        self.main = main
        self.setWindowTitle("Search Snapshot Index")
        self.resize(980, 560)
        self._req_id = 0
        self._index_worker: Optional[SnapshotIndexWorker] = None

        layout = QVBoxLayout(self)
        row1 = QHBoxLayout()
        self.query_edit = QLineEdit()
        self.query_edit.setPlaceholderText("e.g.  mimikatz   |   *.ps1   |   ^(?:svch0st|lsas)\\.exe$")
        self.query_edit.returnPressed.connect(self.action_search)
        row1.addWidget(self.query_edit, 1)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Contains", "Wildcard (* ?)", "Regex"])
        row1.addWidget(self.mode_combo)
        self.btn_search = QPushButton("Search")
        self.btn_search.clicked.connect(self.action_search)
        row1.addWidget(self.btn_search)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.scope_combo = QComboBox()
        self.scope_combo.addItems(["Current snapshot", "All snapshots of this partition"])
        self.scope_combo.currentIndexChanged.connect(self.update_coverage)
        row2.addWidget(self.scope_combo)
        self.kind_combo = QComboBox()
        self.kind_combo.addItems(["Files & folders", "Files only", "Folders only"])
        row2.addWidget(self.kind_combo)
        self.chk_deleted = QCheckBox("Include deleted")
        self.chk_deleted.setChecked(True)
        row2.addWidget(self.chk_deleted)
        self.chk_path = QCheckBox("Match full path")
        row2.addWidget(self.chk_path)
        self.chk_ads = QCheckBox(f"Also match ADS stream names ({ADS_BADGE})")
        self.chk_ads.setChecked(True)
        row2.addWidget(self.chk_ads)
        row2.addStretch()
        layout.addLayout(row2)

        row3 = QHBoxLayout()
        self.coverage_label = QLabel("")
        self.coverage_label.setTextFormat(TEXT_PLAIN)
        row3.addWidget(self.coverage_label, 1)
        self.btn_index = QPushButton("Index Snapshot(s) Fully")
        self.btn_index.clicked.connect(self.action_index)
        row3.addWidget(self.btn_index)
        layout.addLayout(row3)

        self.model = SearchResultsModel(self)
        self.proxy = ForensicSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(SearchResultsModel.SORT_ROLE)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(SEL_ROWS)
        self.table.setSelectionMode(SEL_EXTENDED)
        hdr = self.table.horizontalHeader()
        for c in range(6):
            hdr.setSectionResizeMode(c, RESIZE_INTERACTIVE)
        hdr.resizeSection(0, 80)
        hdr.resizeSection(1, 220)
        hdr.resizeSection(2, 380)
        hdr.resizeSection(4, 160)
        hdr.setStretchLastSection(True)
        self.table.doubleClicked.connect(self.action_open_selected)
        self.table.setContextMenuPolicy(CTX_CUSTOM)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.table, 1)

        self.result_label = QLabel("Type a name and press Search.")
        self.result_label.setTextFormat(TEXT_PLAIN)
        layout.addWidget(self.result_label)

    # -- helpers --------------------------------------------------------------
    def _snap_ids(self) -> List[str]:
        sess = self.main.session
        if not sess or not sess.partitions:
            return []
        pm = sess.partitions[self.main.current_part_idx]
        if self.scope_combo.currentIndex() == 1:
            return [sn["id"] for sn in pm.snapshots]
        return [self.main.current_snap_id]

    def update_coverage(self):
        sess = self.main.session
        if not sess or not sess.index_db:
            self.coverage_label.setText("No image open.")
            return
        bits = []
        for snap in self._snap_ids():
            folders, full = sess.index_db.index_coverage(self.main.current_part_idx, snap)
            bits.append(f"{snap}: {folders:,} folders indexed{' (complete)' if full else ' (partial — only browsed folders)'}")
        self.coverage_label.setText("Index coverage — " + "; ".join(bits))

    def reset(self):
        self._req_id += 1
        if self._index_worker is not None:
            self._index_worker.cancel()
            self._index_worker = None
        self.model.set_rows([], self.main.current_tz_info)
        self.result_label.setText("Type a name and press Search.")
        self.update_coverage()

    def selected_entries(self) -> List[Dict[str, Any]]:
        out = []
        for idx in self.table.selectionModel().selectedRows():
            e = self.model.data(self.proxy.mapToSource(idx), ROLE_USER)
            if e:
                out.append(e)
        return out

    # -- actions --------------------------------------------------------------
    def action_search(self):
        self._req_id += 1
        self.model.set_rows([], self.main.current_tz_info)
        sess = self.main.session
        query = self.query_edit.text().strip()
        if not sess or not sess.index_db or not query:
            self.result_label.setText("Type a name and press Search." if sess else "No image open.")
            return
        mode = {0: "contains", 1: "wildcard", 2: "regex"}[self.mode_combo.currentIndex()]
        if mode == "regex":
            try:
                re.compile(query)
            except re.error as e:
                self.result_label.setText(f"Invalid regular expression: {e}")
                return
        options = {
            "mode": mode,
            "include_deleted": self.chk_deleted.isChecked(),
            "match_path": self.chk_path.isChecked(),
            "kind": {0: "all", 1: "files", 2: "dirs"}[self.kind_combo.currentIndex()],
            "include_ads": self.chk_ads.isChecked(),
        }
        worker = SnapshotSearchWorker(sess, self.main.current_part_idx, self._snap_ids(), query, options, self._req_id)
        worker.signals.search_ready.connect(self._on_results)
        worker.signals.error.connect(lambda msg: self.result_label.setText(msg)
                                     if worker.req_id == self._req_id and
                                     self.main._is_valid_session_token(worker.token) else None)
        self.result_label.setText("🔎 Searching…")
        self.main._start_task(worker)

    def _on_results(self, token: int, req_id: int, rows: list, truncated: bool):
        if req_id != self._req_id or not self.main._is_valid_session_token(token):
            return
        self.model.set_rows(rows, self.main.current_tz_info)
        self.update_coverage()
        partial = any("partial" in t for t in [self.coverage_label.text()])
        msg = f"{len(rows):,} result(s)" + (" — limit reached, refine the query" if truncated else "")
        if partial:
            msg += "  ⚠️ index is partial: folders never browsed or indexed are not searched."
        self.result_label.setText(msg)

    def action_index(self):
        sess = self.main.session
        if not sess:
            return
        pm = sess.partitions[self.main.current_part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            self.result_label.setText("🔒 Unlock the BitLocker volume first.")
            return
        if self._index_worker is not None:
            self._index_worker.cancel()
        worker = SnapshotIndexWorker(sess, self.main.current_part_idx, self._snap_ids())
        self._index_worker = worker
        def current_index():
            return self._index_worker is worker and self.main._is_valid_session_token(worker.token)
        worker.signals.status.connect(lambda msg: self.result_label.setText(msg) if current_index() else None)
        worker.signals.indexed.connect(lambda *args: self._on_indexed(*args) if current_index() else None)
        worker.signals.error.connect(lambda msg: self.result_label.setText(msg) if current_index() else None)
        worker.signals.finished.connect(
            lambda w=worker: setattr(self, "_index_worker", None) if self._index_worker is w else None)
        self.main._start_task(worker)

    def _on_indexed(self, token: int, summary: str):
        if not self.main._is_valid_session_token(token):
            return
        self._index_worker = None
        self.update_coverage()
        self.result_label.setText(f"Indexing finished — {summary}")
        if self.query_edit.text().strip():
            self.action_search()

    def action_open_selected(self, proxy_idx: QModelIndex):
        e = self.model.data(self.proxy.mapToSource(proxy_idx), ROLE_USER)
        if e:
            self.main.reveal_entry(e)

    def show_context_menu(self, pos):
        items = self.selected_entries()
        if not items:
            return
        menu = QMenu(self)
        menu.addAction("📂 Show in Folder", lambda: self.main.reveal_entry(items[0]))
        menu.addAction("📤 Export Selected...", lambda: self.main._launch_export(items))
        for label, fn in self.main.extra_entry_actions(items):
            menu.addAction(label, fn)
        menu.exec(self.table.viewport().mapToGlobal(pos))


class VersionHistoryDialog(QDialog):
    """FEATURE (2026-11-04): one file's versions across all snapshots."""
    HEADERS = ["Snapshot", "Snapshot Created", "State", "Size", "Modified (M)", "Created (B)",
               "Entry Mod (C)", "Inode", "SHA-256", "MD5", "Change", "Note"]

    def __init__(self, main: "VSCExplorerMainWindow", entry: Dict[str, Any]):
        super().__init__(main)
        self.main, self.entry = main, entry
        self._session_token = main.session.session_token if main.session else None
        self._part_idx = main.current_part_idx
        self.rows: List[Dict[str, Any]] = []
        self.setWindowTitle("File Version History")
        self.resize(1250, 420)
        layout = QVBoxLayout(self)
        title = QLabel(f"🕘 {entry['path']}")
        title.setTextFormat(TEXT_PLAIN)
        title.setStyleSheet("font-weight: 700; font-size: 14px;")
        layout.addWidget(title)
        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setSelectionBehavior(SEL_ROWS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers
                                   if hasattr(QAbstractItemView, "EditTrigger") else QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(lambda r, _c: self._show_row(r))
        layout.addWidget(self.table, 1)
        self.status = QLabel("Collecting versions…")
        self.status.setTextFormat(TEXT_PLAIN)
        layout.addWidget(self.status)
        btns = QHBoxLayout()
        btns.addStretch()
        self.btn_show = QPushButton("📂 Show Selected in Folder")
        self.btn_show.clicked.connect(lambda: self._show_row(self.table.currentRow()))
        btns.addWidget(self.btn_show)
        self.btn_export = QPushButton("📤 Export All Versions...")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.action_export_all)
        btns.addWidget(self.btn_export)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btns.addWidget(close_btn)
        layout.addLayout(btns)

    def set_rows(self, rows: List[Dict[str, Any]]):
        self.rows = rows
        tz = self.main.current_tz_info
        self.table.setRowCount(len(rows))
        for i, r_ in enumerate(rows):
            e = r_.get("entry") or {}
            vals = [
                r_["snap_id"], format_epoch_tz(r_.get("creation_utc"), tz) if r_.get("creation_utc") else "(live volume)",
                r_["state"], format_size_human(int(e.get("size", 0))) if e and not e.get("is_dir") else "—",
                format_epoch_tz(e.get("mtime"), tz) if e else "—", format_epoch_tz(e.get("crtime"), tz) if e else "—",
                format_epoch_tz(e.get("ctime"), tz) if e else "—", str(e.get("inode", "")) if e else "",
                r_.get("sha256", ""), r_.get("md5", ""), r_.get("change", ""), r_.get("note", ""),
            ]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if r_.get("change") == "CHANGED":
                    item.setForeground(QColor("#d29922"))
                elif r_["state"] != "Present":
                    item.setForeground(QColor("#e5534b"))
                self.table.setItem(i, c, item)
        self.table.resizeColumnsToContents()
        versions = [r_ for r_ in rows if r_.get("entry")]
        distinct = len({r_["sha256"] for r_ in versions if r_.get("sha256")})
        self.status.setText(
            f"{len(versions)} version(s) found in {len(rows)} snapshot(s); {distinct} distinct content hash(es). "
            "Double-click a row to open it in its snapshot."
        )
        self.btn_export.setEnabled(bool(versions))

    def _activate_source_partition(self) -> bool:
        if not self.main._is_valid_session_token(self._session_token):
            self.main._show_message("info", "Version History", "This history belongs to an image that is no longer open.")
            return False
        if self.main.current_part_idx != self._part_idx:
            index = self.main.combo_partition.findData(self._part_idx)
            if index < 0:
                return False
            self.main.combo_partition.setCurrentIndex(index)
        return True

    def _show_row(self, row: int):
        if 0 <= row < len(self.rows) and self.rows[row].get("entry"):
            if self._activate_source_partition():
                self.main.reveal_entry(dict(self.rows[row]["entry"], source_snap=self.rows[row]["snap_id"]))

    def action_export_all(self):
        if not self._activate_source_partition():
            return
        items = []
        for r_ in self.rows:
            e = r_.get("entry")
            if not e:
                continue
            item = dict(e)
            item["source_snap"] = r_["snap_id"]
            if e.get("ads_stream") is not None:
                host_stem, host_ext = os.path.splitext(e.get("ads_host", e["name"]).replace(":", "_"))
                stream_clean = str(e["ads_stream"]).replace(":", "_")
                item["name"] = f"{host_stem}__{r_['snap_id']}{host_ext}_{stream_clean}"
            else:
                stem, ext = os.path.splitext(e["name"].replace(":", "_"))
                item["name"] = f"{stem}__{r_['snap_id']}{ext}"
            items.append(item)
        self.main._launch_export(items)


BOOKMARK_BADGE = "🔖"


class BookmarkEditDialog(QDialog):
    """FEATURE (2026-11-04): tag + note for one or more items."""

    def __init__(self, parent, tags: List[str], count: int, tag: str = "", note: str = ""):
        super().__init__(parent)
        self.setWindowTitle(f"{BOOKMARK_BADGE} Bookmark {count} item(s)")
        self.resize(460, 300)
        layout = QFormLayout(self)
        self.tag_combo = QComboBox()
        self.tag_combo.setEditable(True)
        self.tag_combo.addItems(tags)
        self.tag_combo.setCurrentText(tag or (tags[0] if tags else ""))
        layout.addRow("Tag:", self.tag_combo)
        self.note_edit = QTextEdit()
        self.note_edit.setAcceptRichText(False)
        self.note_edit.setPlainText(note)
        self.note_edit.setPlaceholderText("Examiner note (why this item matters)…")
        layout.addRow("Note:", self.note_edit)
        btns = QDialogButtonBox(BTN_OK_CANCEL)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    @property
    def tag(self) -> str:
        return self.tag_combo.currentText().strip()

    @property
    def note(self) -> str:
        return self.note_edit.toPlainText().strip()


class CaseInfoDialog(QDialog):
    FIELDS = (("case_number", "Case number"), ("examiner", "Examiner"),
              ("organization", "Organization"), ("description", "Description"))

    def __init__(self, parent, info: Dict[str, str]):
        super().__init__(parent)
        self.setWindowTitle("Case Information")
        self.resize(480, 280)
        layout = QFormLayout(self)
        self.edits: Dict[str, Any] = {}
        for key, label in self.FIELDS:
            w = QTextEdit() if key == "description" else QLineEdit()
            if key == "description":
                w.setAcceptRichText(False)
                w.setPlainText(info.get(key, ""))
            else:
                w.setText(info.get(key, ""))
            self.edits[key] = w
            layout.addRow(f"{label}:", w)
        btns = QDialogButtonBox(BTN_OK_CANCEL)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def values(self) -> Dict[str, str]:
        return {k: (w.toPlainText() if isinstance(w, QTextEdit) else w.text()).strip() for k, w in self.edits.items()}


class BookmarksDialog(QDialog):
    """FEATURE (2026-11-04): all bookmarks of the case, filterable by tag."""
    HEADERS = ["Tag", "Snapshot", "Path", "Size", "Modified (UTC)", "Note", "Bookmarked (UTC)"]

    def __init__(self, main: "VSCExplorerMainWindow"):
        super().__init__(main)
        self.main = main
        self.setWindowTitle(f"{BOOKMARK_BADGE} Bookmarks")
        self.resize(1050, 480)
        self._rows: List[Dict[str, Any]] = []
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(QLabel("Tag:"))
        self.tag_filter = QComboBox()
        self.tag_filter.currentIndexChanged.connect(self.refresh)
        top.addWidget(self.tag_filter)
        top.addStretch()
        layout.addLayout(top)
        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setSelectionBehavior(SEL_ROWS)
        self.table.setSelectionMode(SEL_EXTENDED)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers
                                   if hasattr(QAbstractItemView, "EditTrigger") else QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.cellDoubleClicked.connect(lambda r, _c: self._reveal(r))
        layout.addWidget(self.table, 1)
        btns = QHBoxLayout()
        for label, fn in (("📂 Show in Folder", lambda: self._reveal(self.table.currentRow())),
                          ("✏️ Edit Tag/Note", self.action_edit), ("🗑 Remove", self.action_remove),
                          ("📤 Export Selected...", self.action_export)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            btns.addWidget(b)
        btns.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btns.addWidget(close_btn)
        layout.addLayout(btns)

    def refresh(self):
        store = self.main.case_store
        if store is None:
            self._rows = []
            self.table.setRowCount(0)
            return
        current = self.tag_filter.currentText()
        self.tag_filter.blockSignals(True)
        self.tag_filter.clear()
        used = sorted({b["tag"] for b in store.list_bookmarks()}, key=str.lower)
        self.tag_filter.addItems(["(all)"] + used)
        if current in used:
            self.tag_filter.setCurrentText(current)
        self.tag_filter.blockSignals(False)
        tag = self.tag_filter.currentText()
        self._rows = store.list_bookmarks(None if tag in ("", "(all)") else tag)
        self.table.setRowCount(len(self._rows))
        for i, b in enumerate(self._rows):
            e = b["entry"]
            vals = [b["tag"], f"P{b['part_idx']} / {b['snap_id']}", e.get("path", ""),
                    "—" if e.get("is_dir") else format_size_human(int(e.get("size", 0))),
                    format_epoch_tz(e.get("mtime"), datetime.timezone.utc), b["note"].replace("\n", " "),
                    format_epoch_tz(b["created_utc"], datetime.timezone.utc)]
            for c, v in enumerate(vals):
                self.table.setItem(i, c, QTableWidgetItem(v))
        self.table.resizeColumnsToContents()

    def _selected(self) -> List[Dict[str, Any]]:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        return [self._rows[r] for r in rows if r < len(self._rows)]

    def _reveal(self, row: int):
        if 0 <= row < len(self._rows):
            b = self._rows[row]
            if b["part_idx"] != self.main.current_part_idx:
                idx = self.main.combo_partition.findData(b["part_idx"])
                if idx < 0:
                    return
                self.main.combo_partition.setCurrentIndex(idx)
            self.main.reveal_entry(dict(b["entry"], source_snap=b["snap_id"]))

    def action_edit(self):
        sel = self._selected()
        store = self.main.case_store
        if not sel or store is None:
            return
        dlg = BookmarkEditDialog(self, store.tags(), len(sel), sel[0]["tag"], sel[0]["note"])
        if dlg.exec() == DLG_ACCEPTED and self.main.case_store is store:
            for b in sel:
                store.upsert_bookmark(b["part_idx"], b["snap_id"], b["entry"], dlg.tag, dlg.note)
            self.refresh()
            self.main._refresh_markers()

    def action_remove(self):
        store = self.main.case_store
        if store is None:
            return
        for b in self._selected():
            store.remove_bookmark(b["id"])
        self.refresh()
        self.main._refresh_markers()

    def action_export(self):
        sel = self._selected()
        parts = {b["part_idx"] for b in sel}
        if not sel:
            return
        if len(parts) > 1:
            QMessageBox.information(self, "Export", "Select bookmarks from a single partition to export together.")
            return
        target_part = next(iter(parts))
        if target_part != self.main.current_part_idx:
            idx = self.main.combo_partition.findData(target_part)
            if idx < 0:
                QMessageBox.information(self, "Export", f"Partition P{target_part} is not available.")
                return
            self.main.combo_partition.setCurrentIndex(idx)
        self.main._launch_export([dict(b["entry"], source_snap=b["snap_id"]) for b in sel])


class PhysicalDriveDialog(QDialog):
    """FEATURE (2026-11-04): pick a physical drive to open read-only."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Open Physical Drive (read-only)")
        self.resize(560, 380)
        self.selected_path: Optional[str] = None
        layout = QVBoxLayout(self)
        warn = QLabel(
            "The drive is opened read-only, but the OS may still write to a mounted drive.\n"
            "Use a hardware write blocker for evidence drives. Administrator/root rights are needed.\n"
            "Listings from a drive are not kept in the persistent cache (a live disk keeps changing)."
        )
        warn.setTextFormat(TEXT_PLAIN)
        warn.setStyleSheet("color: #d29922;")
        layout.addWidget(warn)
        self.list_widget = QListWidget()
        self.list_widget.itemDoubleClicked.connect(self.accept)
        layout.addWidget(self.list_widget, 1)
        self._paths: List[str] = []
        try:
            drives = list_physical_drives()
        except Exception as e:
            drives = []
            logger.warning(f"Drive enumeration failed: {e}")
        for d in drives:
            size = format_size_human(d["size"]) if d.get("size") else "size unknown"
            model = f" — {d['model']}" if d.get("model") else ""
            self.list_widget.addItem(f"{d['path']}   ({size}){model}")
            self._paths.append(d["path"])
        if not drives:
            self.list_widget.addItem("(no drives found or not permitted — type a device path below)")
        form = QFormLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(r"e.g. /dev/sdb  or  \\.\PhysicalDrive1")
        form.addRow("Device path:", self.path_edit)
        layout.addLayout(form)
        self.list_widget.currentRowChanged.connect(
            lambda row: self.path_edit.setText(self._paths[row]) if 0 <= row < len(self._paths) else None
        )
        btns = QDialogButtonBox(BTN_OK_CANCEL)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def accept(self):
        path = self.path_edit.text().strip()
        if not path or not is_physical_device_path(path):
            QMessageBox.warning(self, "Validation", "Enter or select a device path (/dev/... or \\\\.\\PhysicalDriveN).")
            return
        self.selected_path = path
        super().accept()


# ============================================================================
# Section 8: Main Application Window
# ============================================================================

class VSCExplorerMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"VSCExplorer v{APP_VERSION} - Forensic Volume Shadow Copy & BitLocker Explorer")
        self.resize(1440, 880)

        if os.path.exists("logo.png"):
            self.setWindowIcon(QIcon("logo.png"))

        self.session: Optional[ForensicSession] = None
        self.thread_pool = QThreadPool.globalInstance()
        self.thread_pool.setMaxThreadCount(max(4, os.cpu_count() or 4))
        # FIX (2026-11-03): pool threads never expire. Each pool thread holds its own SQLite
        # reader connection; with Qt's default 30 s expiry, every idle period created new
        # threads and leaked the old connections (file handles + page cache) until close.
        self.thread_pool.setExpiryTimeout(-1)
        self._active_tasks: Set[QRunnable] = set()
        self._current_export_worker: Optional[BufferedExportWorker] = None
        self._current_diff_worker: Optional[SnapshotDiffWorker] = None
        self._shown_diff_worker: Optional[SnapshotDiffWorker] = None
        self._current_open_worker: Optional[ImageOpenWorker] = None
        self._nav_dir_entry: Optional[Dict[str, Any]] = None
        self._current_dir_entries: List[Dict[str, Any]] = []
        self._pending_select_entry: Optional[Dict[str, Any]] = None
        self.search_dialog: Optional[SnapshotSearchDialog] = None
        self.case_store: Optional[CaseStore] = None
        self.bookmarks_dialog: Optional[BookmarksDialog] = None
        self._version_dialogs: List[VersionHistoryDialog] = []
        self._last_export_ctx: Optional[Tuple[int, str, str]] = None
        self._image_hash_worker: Optional[ImageHashWorker] = None
        self._report_worker: Optional[CaseReportWorker] = None
        self._dir_entry_by_path: Dict[str, Dict[str, Any]] = {}

        self._image_open_req_id: int = 0
        self._nav_request_id: int = 0
        self._preview_request_id: int = 0

        self.current_part_idx: int = 0
        self.current_snap_id: str = "Live"
        self.current_path: str = "/"
        self.tree_nodes_by_path: Dict[str, QTreeWidgetItem] = {}
        self.loading_tree_paths: Set[str] = set()

        self.dark_mode: bool = False
        self.current_tz_name: str = "UTC"
        self.current_tz_info: datetime.tzinfo = datetime.timezone.utc

        self.opt_enable_hex: bool = False
        self.opt_enable_diff: bool = False
        self.opt_enable_metadata: bool = False

        self._init_menu_bar()
        self._init_workspace_ui()
        self.apply_theme(dark_mode=False)
        self._sync_inspector_tabs()

    def _init_menu_bar(self):
        menubar: QMenuBar = self.menuBar()

        # 1. FILE MENU
        file_menu: QMenu = menubar.addMenu("&File")

        self.act_open_img = QAction("&Open Forensic Image...", self)
        self.act_open_img.setShortcut(QKeySequence("Ctrl+O"))
        self.act_open_img.triggered.connect(self.action_open_image)
        file_menu.addAction(self.act_open_img)

        self.act_open_drive = QAction("Open &Physical Drive (read-only)...", self)
        self.act_open_drive.setShortcut(QKeySequence("Ctrl+Shift+O"))
        self.act_open_drive.triggered.connect(self.action_open_physical_drive)
        file_menu.addAction(self.act_open_drive)

        self.act_load_demo = QAction("Load &Demo Forensic Case", self)
        self.act_load_demo.setShortcut(QKeySequence("Ctrl+D"))
        self.act_load_demo.triggered.connect(self.action_load_demo_case)
        file_menu.addAction(self.act_load_demo)

        file_menu.addSeparator()

        self.act_unlock_bde = QAction("&Unlock / Inspect BitLocker Volume...", self)
        self.act_unlock_bde.setShortcut(QKeySequence("Ctrl+U"))
        self.act_unlock_bde.setEnabled(False)
        self.act_unlock_bde.triggered.connect(self.action_unlock_bitlocker)
        file_menu.addAction(self.act_unlock_bde)

        file_menu.addSeparator()

        self.act_export_sel = QAction("&Export Selected Items...", self)
        self.act_export_sel.setShortcut(QKeySequence("Ctrl+E"))
        self.act_export_sel.triggered.connect(self.action_export_selected)
        file_menu.addAction(self.act_export_sel)

        self.act_export_all = QAction("Export &All in Current Folder...", self)
        self.act_export_all.setShortcut(QKeySequence("Ctrl+Shift+E"))
        self.act_export_all.triggered.connect(self.action_export_all)
        file_menu.addAction(self.act_export_all)

        file_menu.addSeparator()

        act_exit = QAction("E&xit", self)
        act_exit.setShortcut(QKeySequence("Ctrl+Q"))
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # 2. VIEW MENU
        view_menu: QMenu = menubar.addMenu("&View")

        theme_submenu: QMenu = view_menu.addMenu("Appearance / &Theme")
        self.theme_group = QActionGroup(self)
        self.theme_group.setExclusive(True)

        self.act_light_mode = QAction("&Normal (Light) Mode", self, checkable=True)
        self.act_light_mode.setChecked(True)
        self.act_light_mode.triggered.connect(lambda: self.apply_theme(dark_mode=False))
        self.theme_group.addAction(self.act_light_mode)
        theme_submenu.addAction(self.act_light_mode)

        self.act_dark_mode = QAction("&Dark Mode", self, checkable=True)
        self.act_dark_mode.triggered.connect(lambda: self.apply_theme(dark_mode=True))
        self.theme_group.addAction(self.act_dark_mode)
        theme_submenu.addAction(self.act_dark_mode)

        view_menu.addSeparator()

        self.act_show_tree = QAction("Show &Directory Tree Pane", self, checkable=True)
        self.act_show_tree.setChecked(True)
        self.act_show_tree.toggled.connect(lambda checked: self.left_tree_panel.setVisible(checked))
        view_menu.addAction(self.act_show_tree)

        self.act_show_ads_rows = QAction(f"Show Alternate Data Streams as Rows ({ADS_BADGE})", self, checkable=True)
        self.act_show_ads_rows.setChecked(True)
        self.act_show_ads_rows.toggled.connect(lambda _c: self._refresh_table_rows())
        view_menu.addAction(self.act_show_ads_rows)

        view_menu.addSeparator()

        act_up = QAction("Navigate &Up One Folder", self)
        act_up.setShortcut(QKeySequence("Alt+Up"))
        act_up.triggered.connect(self.action_navigate_up)
        view_menu.addAction(act_up)

        act_refresh = QAction("&Refresh Current Folder", self)
        act_refresh.setShortcut(QKeySequence("F5"))
        act_refresh.triggered.connect(self.action_refresh_folder)
        view_menu.addAction(act_refresh)

        # 2b. TOOLS MENU (FEATURE 2026-11-04)
        self.tools_menu: QMenu = menubar.addMenu("&Tools")
        act_search = QAction("🔎 &Search Snapshot Index...", self)
        act_search.setShortcut(QKeySequence("Ctrl+F"))
        act_search.triggered.connect(self.action_open_search)
        self.tools_menu.addAction(act_search)
        act_history = QAction("🕘 File &Version History (selected file)...", self)
        act_history.setShortcut(QKeySequence("Ctrl+H"))
        act_history.triggered.connect(self.action_version_history_selected)
        self.tools_menu.addAction(act_history)
        self.tools_menu.addSeparator()
        act_bm = QAction(f"{BOOKMARK_BADGE} &Bookmark / Tag Selected...", self)
        act_bm.setShortcut(QKeySequence("Ctrl+B"))
        act_bm.triggered.connect(lambda: self.action_bookmark(self._selected_table_entries()))
        self.tools_menu.addAction(act_bm)
        act_bms = QAction("📑 Show &Bookmarks...", self)
        act_bms.setShortcut(QKeySequence("Ctrl+Shift+B"))
        act_bms.triggered.connect(self.action_show_bookmarks)
        self.tools_menu.addAction(act_bms)
        self.tools_menu.addSeparator()
        act_case = QAction("🗂 &Case Information...", self)
        act_case.triggered.connect(self.action_case_info)
        self.tools_menu.addAction(act_case)
        act_ihash = QAction("🔐 Compute / Verify &Image Hash...", self)
        act_ihash.triggered.connect(self.action_image_hash)
        self.tools_menu.addAction(act_ihash)
        act_report = QAction("📄 Generate Case &Report (HTML + PDF)...", self)
        act_report.setShortcut(QKeySequence("Ctrl+R"))
        act_report.triggered.connect(self.action_case_report)
        self.tools_menu.addAction(act_report)

        # 3. OPTIONS MENU
        options_menu: QMenu = menubar.addMenu("&Options")

        self.act_opt_hex = QAction("Enable &Virtual Hex Viewer", self, checkable=True)
        self.act_opt_hex.setChecked(False)
        self.act_opt_hex.toggled.connect(self._on_feature_options_toggled)
        options_menu.addAction(self.act_opt_hex)

        self.act_opt_diff = QAction("Enable &VSS Snapshot Diff", self, checkable=True)
        self.act_opt_diff.setChecked(False)
        self.act_opt_diff.toggled.connect(self._on_feature_options_toggled)
        options_menu.addAction(self.act_opt_diff)

        self.act_opt_meta = QAction("Enable &Text / Metadata Preview", self, checkable=True)
        self.act_opt_meta.setChecked(False)
        self.act_opt_meta.toggled.connect(self._on_feature_options_toggled)
        options_menu.addAction(self.act_opt_meta)

        options_menu.addSeparator()

        self.act_tz_dialog = QAction("Select &Time Zone... (Current: UTC)", self)
        self.act_tz_dialog.setShortcut(QKeySequence("Ctrl+T"))
        self.act_tz_dialog.triggered.connect(self.action_open_timezone_dialog)
        options_menu.addAction(self.act_tz_dialog)

        act_clear_cache = QAction("&Clear / Rebuild Persistent SQLite Index", self)
        act_clear_cache.setShortcut(QKeySequence("Ctrl+Shift+R"))
        act_clear_cache.triggered.connect(self.action_clear_sqlite_cache)
        options_menu.addAction(act_clear_cache)

        options_menu.addSeparator()
        options_menu.addMenu(theme_submenu)

        # 4. HELP MENU
        help_menu: QMenu = menubar.addMenu("&Help")

        act_selftest = QAction("Run &Automated Self-Test Suite...", self)
        act_selftest.triggered.connect(self.action_run_selftest_ui)
        help_menu.addAction(act_selftest)

        act_deps = QAction("Forensic &Dependency Status...", self)
        act_deps.triggered.connect(self.action_show_dependencies)
        help_menu.addAction(act_deps)

        help_menu.addSeparator()

        act_about = QAction("&About VSCExplorer", self)
        act_about.triggered.connect(self.action_show_about)
        help_menu.addAction(act_about)

    def _init_workspace_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(8)

        selector_bar = QHBoxLayout()
        selector_bar.setSpacing(10)

        selector_bar.addWidget(QLabel("Partition:"))
        self.combo_partition = QComboBox()
        # Fix (2026-11-02, top-left selectors): the old code set only a
        # minimum width (300/340) with no maximum and Qt's default
        # size-adjust behaviour, so a long partition/snapshot label made
        # the combo expand to the full label length and pushed the rest
        # of the top bar (and, via the layout, the panes below) out of
        # shape. Cap both combos, let them shrink to the cap, and keep
        # the full text in the item tooltip instead of in the box.
        self.combo_partition.setMinimumWidth(220)
        self.combo_partition.setMaximumWidth(360)
        self.combo_partition.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.combo_partition.currentIndexChanged.connect(self.action_partition_changed)
        selector_bar.addWidget(self.combo_partition)

        selector_bar.addWidget(QLabel("Snapshot (VSC):"))
        self.combo_vss = QComboBox()
        self.combo_vss.setMinimumWidth(220)
        self.combo_vss.setMaximumWidth(360)
        self.combo_vss.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.combo_vss.currentIndexChanged.connect(self.action_vss_changed)
        selector_bar.addWidget(self.combo_vss)

        self.lbl_tz_badge = QLabel("🕒 Time Zone: UTC")
        self.lbl_tz_badge.setStyleSheet("font-weight: 600;")
        selector_bar.addWidget(self.lbl_tz_badge)

        selector_bar.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(180)
        self.progress_bar.setVisible(False)
        selector_bar.addWidget(self.progress_bar)

        self.btn_cancel_export = QPushButton("✖ Cancel Export")
        self.btn_cancel_export.setVisible(False)
        self.btn_cancel_export.clicked.connect(self.action_cancel_export)
        selector_bar.addWidget(self.btn_cancel_export)

        main_layout.addLayout(selector_bar)

        nav_bar = QHBoxLayout()
        nav_bar.setSpacing(8)
        self.btn_up = QPushButton("⬆️ Up")
        self.btn_up.clicked.connect(self.action_navigate_up)
        nav_bar.addWidget(self.btn_up)

        nav_bar.addWidget(QLabel("Location:"))
        self.edit_location = QLineEdit("/ (Root)")
        self.edit_location.setReadOnly(True)
        nav_bar.addWidget(self.edit_location, 1)

        self.edit_filter = QLineEdit()
        self.edit_filter.setPlaceholderText("🔍 Filter current folder...")
        self.edit_filter.setMaximumWidth(250)
        nav_bar.addWidget(self.edit_filter)

        main_layout.addLayout(nav_bar)

        self.main_splitter = QSplitter(ORIENT_HORIZONTAL)
        self.main_splitter.setChildrenCollapsible(False)

        # LEFT PANE: Directory Structure Tree
        self.left_tree_panel = QWidget()
        left_layout = QVBoxLayout(self.left_tree_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)

        tree_header = QLabel("📁 Directory Structure")
        tree_header.setStyleSheet("font-weight: 600; padding: 4px;")
        left_layout.addWidget(tree_header)

        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderHidden(True)
        self.tree_widget.itemExpanded.connect(self.on_tree_item_expanded)
        self.tree_widget.itemClicked.connect(self.on_tree_item_clicked)
        self.tree_widget.setContextMenuPolicy(CTX_CUSTOM)
        self.tree_widget.customContextMenuRequested.connect(self.show_tree_context_menu)
        left_layout.addWidget(self.tree_widget, 1)

        self.main_splitter.addWidget(self.left_tree_panel)

        # CENTER PANE: File Details Virtual Table
        center_panel = QWidget()
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(4)

        table_header = QLabel("📄 File Details")
        table_header.setStyleSheet("font-weight: 600; padding: 4px;")
        center_layout.addWidget(table_header)

        self.table_model = ForensicFileSystemTableModel(self)
        self.table_model._marker_fn = self._bookmark_marker
        self.proxy_model = ForensicSortFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.table_model)
        self.proxy_model.setSortRole(ForensicFileSystemTableModel.SORT_ROLE)
        self.proxy_model.setSortCaseSensitivity(CASE_INSENSITIVE)
        self.proxy_model.setFilterCaseSensitivity(CASE_INSENSITIVE)
        self.proxy_model.setFilterKeyColumn(0)
        self.edit_filter.textChanged.connect(self.proxy_model.setFilterFixedString)

        self.file_table = QTableView()
        self.file_table.setModel(self.proxy_model)
        self.file_table.setSortingEnabled(True)
        self.file_table.sortByColumn(0, SORT_ASCENDING)
        self.file_table.setAlternatingRowColors(True)
        self.file_table.setSelectionBehavior(SEL_ROWS)
        self.file_table.setSelectionMode(SEL_EXTENDED)
        # FIX (2026-11-04): Name was a Stretch column next to ResizeToContents columns, so
        # with an inspector tab open it shrank to a few pixels ("$E…"). It now starts at a
        # readable width and is user-resizable; the table scrolls horizontally if needed.
        hdr = self.file_table.horizontalHeader()
        hdr.setSectionResizeMode(0, RESIZE_INTERACTIVE)
        hdr.resizeSection(0, 300)
        for col_i in range(1, 7):
            hdr.setSectionResizeMode(col_i, RESIZE_CONTENTS)
        hdr.setStretchLastSection(True)
        self.file_table.doubleClicked.connect(self.action_table_double_clicked)
        self.file_table.selectionModel().selectionChanged.connect(self.action_table_selection_changed)
        self.file_table.setContextMenuPolicy(CTX_CUSTOM)
        self.file_table.customContextMenuRequested.connect(self.show_file_context_menu)

        center_layout.addWidget(self.file_table, 1)
        self.main_splitter.addWidget(center_panel)

        # RIGHT PANE: Optional Inspector Tabs
        self.inspector_tabs = QTabWidget()

        self.hex_panel = HexPanel(self)
        self.hex_viewer = self.hex_panel.viewer

        self.diff_panel = QWidget()
        diff_layout = QVBoxLayout(self.diff_panel)
        diff_layout.setContentsMargins(6, 6, 6, 6)
        diff_ctrl_bar = QHBoxLayout()
        diff_ctrl_bar.addWidget(QLabel("Baseline:"))
        self.combo_diff_a = QComboBox()
        diff_ctrl_bar.addWidget(self.combo_diff_a, 1)
        diff_ctrl_bar.addWidget(QLabel("Target:"))
        self.combo_diff_b = QComboBox()
        diff_ctrl_bar.addWidget(self.combo_diff_b, 1)
        self.btn_run_diff = QPushButton("Compare Full Snapshots")
        self.btn_run_diff.clicked.connect(self.action_run_diff)
        diff_ctrl_bar.addWidget(self.btn_run_diff)
        diff_layout.addLayout(diff_ctrl_bar)

        self.diff_model = ForensicDiffTableModel(self)
        self.diff_proxy = ForensicSortFilterProxyModel(self)
        self.diff_proxy.setSourceModel(self.diff_model)
        self.diff_proxy.setSortRole(ForensicDiffTableModel.SORT_ROLE)
        self.diff_table = QTableView()
        self.diff_table.setModel(self.diff_proxy)
        self.diff_table.setSortingEnabled(True)
        self.diff_table.sortByColumn(1, SORT_ASCENDING)
        self.diff_table.setSelectionBehavior(SEL_ROWS)
        self.diff_table.setSelectionMode(SEL_EXTENDED)
        self.diff_table.horizontalHeader().setSectionResizeMode(1, RESIZE_STRETCH)
        for c_i in (0, 2, 3, 4, 5, 6):
            self.diff_table.horizontalHeader().setSectionResizeMode(c_i, RESIZE_CONTENTS)
        self.diff_table.doubleClicked.connect(self.on_diff_row_double_clicked)
        self.diff_table.setContextMenuPolicy(CTX_CUSTOM)
        self.diff_table.customContextMenuRequested.connect(self.show_diff_context_menu)
        diff_layout.addWidget(self.diff_table, 1)

        self.text_preview = QTextEdit()
        self.text_preview.setReadOnly(True)
        self.text_preview.setFont(QFont("Consolas", 10))

        self.main_splitter.addWidget(self.inspector_tabs)
        self.main_splitter.setSizes([300, 720, 420])
        main_layout.addWidget(self.main_splitter, 1)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel(
            "Ready — Use File -> Open Forensic Image or File -> Load Demo Forensic Case."
        )
        # FIX (2026-11-03): the status bar shows evidence-derived paths/names. As AutoText a
        # name containing e.g. <b>..</b> or <img> was rendered as HTML (UI spoofing).
        self.status_label.setTextFormat(TEXT_PLAIN)
        self.status_bar.addWidget(self.status_label)

    def apply_theme(self, dark_mode: bool):
        self.dark_mode = dark_mode
        if dark_mode:
            self.act_dark_mode.setChecked(True)
            self.setStyleSheet("""
                QMainWindow, QDialog { background-color: #181a20; color: #e6edf3; }
                QWidget { color: #e6edf3; font-family: 'Segoe UI', Tahoma, sans-serif; font-size: 13px; }
                QMenuBar { background-color: #111318; color: #e6edf3; border-bottom: 1px solid #2d3139; }
                QMenuBar::item:selected { background-color: #2b313c; }
                QMenu { background-color: #1e222a; color: #e6edf3; border: 1px solid #383e4a; }
                QMenu::item:selected { background-color: #2f6fab; color: #ffffff; }
                QTreeWidget, QTableView, QListWidget, QTextEdit, QAbstractScrollArea {
                    background-color: #14161b; alternate-background-color: #1a1d24;
                    color: #e6edf3; border: 1px solid #2e3440; border-radius: 4px; gridline-color: #252932;
                }
                QTreeWidget::item { padding: 3px 4px; }
                QTreeWidget::item:selected, QTableView::item:selected {
                    background-color: #2f6fab; color: #ffffff;
                }
                QHeaderView::section {
                    background-color: #21262d; color: #c9d1d9; padding: 6px;
                    border: 1px solid #30363d; font-weight: 600;
                }
                QGroupBox {
                    border: 1px solid #30363d; border-radius: 6px;
                    margin-top: 10px; padding-top: 10px; font-weight: bold;
                }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #58a6ff; }
                QPushButton {
                    background-color: #21262d; color: #e6edf3; border: 1px solid #383e4a;
                    padding: 5px 12px; border-radius: 4px; font-weight: 600;
                }
                QPushButton:hover { background-color: #30363d; border-color: #58a6ff; }
                QComboBox, QLineEdit {
                    background-color: #14161b; color: #e6edf3; border: 1px solid #383e4a;
                    padding: 4px 8px; border-radius: 4px;
                }
                QTabWidget::pane { border: 1px solid #2e3440; }
                QTabBar::tab { background-color: #21262d; color: #c9d1d9; padding: 6px 12px; border: 1px solid #2e3440; }
                QTabBar::tab:selected { background-color: #2f6fab; color: #ffffff; }
                QStatusBar { background-color: #111318; border-top: 1px solid #2d3139; }
            """)
        else:
            self.act_light_mode.setChecked(True)
            self.setStyleSheet("""
                QMainWindow, QDialog { background-color: #f3f5f8; color: #1f2328; }
                QWidget { color: #1f2328; font-family: 'Segoe UI', Tahoma, sans-serif; font-size: 13px; }
                QMenuBar { background-color: #ffffff; color: #1f2328; border-bottom: 1px solid #d0d7de; }
                QMenuBar::item:selected { background-color: #e6ebf1; }
                QMenu { background-color: #ffffff; color: #1f2328; border: 1px solid #d0d7de; }
                QMenu::item:selected { background-color: #0969da; color: #ffffff; }
                QTreeWidget, QTableView, QListWidget, QTextEdit, QAbstractScrollArea {
                    background-color: #ffffff; alternate-background-color: #f6f8fa;
                    color: #1f2328; border: 1px solid #d0d7de; border-radius: 4px; gridline-color: #e6ebf1;
                }
                QTreeWidget::item { padding: 3px 4px; }
                QTreeWidget::item:selected, QTableView::item:selected {
                    background-color: #c7ddf5; color: #1c3f6c;
                }
                QHeaderView::section {
                    background-color: #eaeef2; color: #1f2328; padding: 6px;
                    border: 1px solid #d0d7de; font-weight: 600;
                }
                QGroupBox {
                    border: 1px solid #d0d7de; border-radius: 6px;
                    margin-top: 10px; padding-top: 10px; font-weight: bold; background-color: #ffffff;
                }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #0969da; }
                QPushButton {
                    background-color: #ffffff; color: #1f2328; border: 1px solid #d0d7de;
                    padding: 5px 12px; border-radius: 4px; font-weight: 600;
                }
                QPushButton:hover { background-color: #f3f4f6; border-color: #0969da; }
                QComboBox, QLineEdit {
                    background-color: #ffffff; color: #1f2328; border: 1px solid #d0d7de;
                    padding: 4px 8px; border-radius: 4px;
                }
                QTabWidget::pane { border: 1px solid #d0d7de; }
                QTabBar::tab { background-color: #eaeef2; color: #1f2328; padding: 6px 12px; border: 1px solid #d0d7de; }
                QTabBar::tab:selected { background-color: #0969da; color: #ffffff; }
                QStatusBar { background-color: #eaeef2; border-top: 1px solid #d0d7de; }
            """)
        self.hex_viewer.set_theme_mode(dark_mode)

    def _on_feature_options_toggled(self):
        self._preview_request_id += 1
        self.opt_enable_hex = self.act_opt_hex.isChecked()
        self.opt_enable_diff = self.act_opt_diff.isChecked()
        self.opt_enable_metadata = self.act_opt_meta.isChecked()
        self._sync_inspector_tabs()

        if self.opt_enable_hex or self.opt_enable_metadata:
            self.action_table_selection_changed()
        # NOTE: enabling the diff tab no longer auto-starts a full-volume crawl of two snapshots;
        # the person starts it explicitly with "Compare Full Snapshots".

    def _sync_inspector_tabs(self):
        while self.inspector_tabs.count() > 0:
            self.inspector_tabs.removeTab(0)

        # Fix 10 (2026-11-02, top-left overlap): the three inspector
        # widgets are created as children of the main window (hex_viewer
        # explicitly, via VirtualHexViewer(self)) but are only placed in
        # the tab widget when their option is enabled. A child widget
        # that is never added to a layout still becomes visible when
        # the main window shows, at position (0, 0) — so the disabled
        # hex viewer painted its placeholder text ("Select a file in
        # the table to inspect raw bytes on demand.") over the menu bar
        # at the top left, covering File/View and leaving only
        # "...ptions Help" visible. The same applied, invisibly, to the
        # diff panel and text preview. Disabled inspector widgets must
        # therefore be explicitly hidden, not just left out of the tabs.
        # No explicit .show() before addTab(): the diff panel / text preview have no parent, so show()
        # popped them up as stray top-level windows for a moment. addTab() reparents and shows them.
        if self.opt_enable_hex:
            self.inspector_tabs.addTab(self.hex_panel, "Virtual Hex Viewer")
        else:
            self.hex_panel.cancel_tasks()
            self.hex_viewer.clear_source()
            self.hex_panel.hide()

        if self.opt_enable_diff:
            self.inspector_tabs.addTab(self.diff_panel, "VSS Snapshot Diff")
        else:
            self.diff_panel.hide()

        if self.opt_enable_metadata:
            self.inspector_tabs.addTab(self.text_preview, "Text / Metadata Preview")
        else:
            self.text_preview.clear()
            self.text_preview.hide()

        self.inspector_tabs.setVisible(self.inspector_tabs.count() > 0)

    def action_open_timezone_dialog(self):
        dlg = TimeZoneSelectDialog(self.current_tz_name, self)
        if dlg.exec() == DLG_ACCEPTED:
            self.current_tz_name = dlg.selected_tz_name
            self.current_tz_info = resolve_tzinfo(self.current_tz_name)
            self.act_tz_dialog.setText(f"Select &Time Zone... (Current: {self.current_tz_name})")
            self.lbl_tz_badge.setText(f"🕒 Time Zone: {self.current_tz_name}")

            self.table_model.set_timezone(self.current_tz_name, self.current_tz_info)
            self.diff_model.set_timezone(self.current_tz_name, self.current_tz_info)
            if self.search_dialog is not None:
                self.search_dialog.model.set_rows(self.search_dialog.model.rows(), self.current_tz_info)
            for vdlg in list(self._version_dialogs):
                if vdlg.rows:
                    vdlg.set_rows(vdlg.rows)

            if self.session and self.session.partitions:
                self._populate_vss_comboboxes(preserve_selection=True)

            if self.opt_enable_metadata:
                self.action_table_selection_changed()

            self.status_label.setText(f"Display time zone updated to: {self.current_tz_name}")

    def action_clear_sqlite_cache(self):
        if not self.session:
            return
        # FIX (2026-11-03): a running diff crawl would otherwise keep writing into the
        # cleared index and then mark the snapshot "fully indexed" over partial data.
        if self._current_diff_worker is not None:
            self._current_diff_worker.cancel()
            self._current_diff_worker = None
        self._shown_diff_worker = None
        if self.search_dialog is not None and self.search_dialog._index_worker is not None:
            self.search_dialog._index_worker.cancel()
        self.session.clear_persistent_index()
        if self.search_dialog is not None:
            self.search_dialog.reset()
        self.diff_model.set_entries([])
        self._reset_and_load_root(self.current_path)
        self.status_label.setText("🗑️ Persistent SQLite WAL index cleared and rebuilt.")

    def _show_message(self, kind: str, title: str, text: str):
        """QMessageBox with PlainText format: messages embed evidence-derived names/paths,
        which the static QMessageBox helpers would render as rich text."""
        icons = QMessageBox.Icon if hasattr(QMessageBox, "Icon") else QMessageBox
        box = QMessageBox(self)
        box.setIcon({"warning": icons.Warning, "critical": icons.Critical}.get(kind, icons.Information))
        box.setWindowTitle(title)
        box.setTextFormat(TEXT_PLAIN)
        box.setText(text)
        box.exec()

    @staticmethod
    def _tree_key(entry: Optional[Dict[str, Any]]) -> str:
        """Tree-node key. A deleted folder can share its path with a live folder, so
        folders opened by inode get the inode appended (NUL can never occur in a name)."""
        if not entry:
            return "/"
        if ForensicSession.needs_inode_open(entry):
            return f"{entry['path']}\x00{entry['inode']}"
        return entry["path"]

    def _start_task(self, runnable: QRunnable):
        if hasattr(runnable, "signals") and hasattr(runnable.signals, "finished"):
            runnable.signals.finished.connect(lambda r=runnable: self._release_task(r))
        self._active_tasks.add(runnable)
        self.thread_pool.start(runnable)

    def _release_task(self, runnable: QRunnable):
        self._active_tasks.discard(runnable)

    def _is_valid_session_token(self, token: int) -> bool:
        return self.session is not None and self.session.session_token == token

    def _teardown_active_session(self):
        self._last_export_ctx = None
        self._pending_select_entry = None
        self._shown_diff_worker = None
        self._image_open_req_id += 1
        if self._current_open_worker is not None:
            self._current_open_worker.cancel()
            self._current_open_worker = None
        if self._current_export_worker is not None:
            self._current_export_worker.cancel()
            self._current_export_worker = None
        if self._current_diff_worker is not None:
            self._current_diff_worker.cancel()
            self._current_diff_worker = None
        if self._image_hash_worker is not None:
            self._image_hash_worker.cancel_event.set()
            self._image_hash_worker = None
        if self._report_worker is not None:
            self._report_worker.cancel_event.set()
            self._report_worker = None
        if self.search_dialog is not None and self.search_dialog._index_worker is not None:
            self.search_dialog._index_worker.cancel()
        self.hex_panel.cancel_tasks()
        for vdlg in list(self._version_dialogs):
            try:
                vdlg.close()
            except Exception:
                pass
        self._version_dialogs.clear()

        self.act_open_img.setEnabled(True)
        self.act_export_sel.setEnabled(True)
        self.act_export_all.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.btn_cancel_export.setVisible(False)

        self.thread_pool.clear()
        self.hex_viewer.clear_source()
        if self.session is not None:
            # Never close forensic image handles while a worker may still read them.
            # FIX (2026-11-03): request_abort() first makes every image read return b"",
            # so in-flight TSK calls fail fast and this wait is short instead of unbounded.
            self.session.request_abort()
        self.thread_pool.waitForDone()
        if self.session is not None:
            self.session.close()
            self.session = None
        # Runnables removed by clear() never emit finished; drop their references too.
        self._active_tasks.clear()
        self.hex_viewer._active_workers.clear()
        self.hex_panel._active_workers.clear()
        if self.search_dialog is not None:
            self.search_dialog.reset()
        if self.case_store is not None:
            self.case_store.close()
            self.case_store = None
        if self.bookmarks_dialog is not None:
            self.bookmarks_dialog.refresh()
        self._dir_entry_by_path.clear()
        self._nav_dir_entry = None

    def action_load_demo_case(self):
        self._teardown_active_session()
        self.session = ForensicSession("demo_memory_case", is_demo=True)
        self._open_case_store()
        self._populate_partitions()
        self.status_label.setText(
            "✅ Loaded Demo Case (SQLite WAL Active): P0 = Unlocked BitLocker (3 VSS), "
            f"P1 = Locked BitLocker Vault (demo password: {DEMO_BITLOCKER_PASSWORD})."
        )

    def action_open_image(self):
        if not TSK_AVAILABLE:
            QMessageBox.warning(
                self,
                "pytsk3 Missing",
                "pytsk3 (The Sleuth Kit) is not installed, so no filesystem can be read from a real image.\n"
                "Install it with:  pip install pytsk3\n\n(The built-in demo case still works.)",
            )
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Forensic Disk Image",
            "",
            (
                "Forensic Disk Images (*.e01 *.E01 *.ex01 *.Ex01 *.raw *.dd *.img *.bin *.001 *.000 "
                "*.vhd *.vhdx *.avhdx *.vmdk);;"
                "EnCase / EWF (*.e01 *.E01 *.ex01 *.Ex01);;Raw / split raw (*.raw *.dd *.img *.bin *.001 *.000);;"
                "Hyper-V / Virtual PC (*.vhd *.vhdx *.avhd *.avhdx);;VMware (*.vmdk);;All Files (*)"
            ),
        )
        if not file_path:
            return
        self._start_image_open(file_path)

    def action_open_physical_drive(self):
        if not TSK_AVAILABLE:
            self._show_message("warning", "pytsk3 Missing", "pytsk3 (The Sleuth Kit) is required to read a drive.")
            return
        dlg = PhysicalDriveDialog(self)
        if dlg.exec() == DLG_ACCEPTED and dlg.selected_path:
            self._start_image_open(dlg.selected_path)

    def _start_image_open(self, file_path: str):
        if self._current_open_worker is not None:
            self._current_open_worker.cancel()
        self._image_open_req_id += 1
        req_id = self._image_open_req_id
        self.act_open_img.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"🔍 Opening image: {os.path.basename(file_path)}...")

        worker = ImageOpenWorker(file_path, req_id=req_id)
        self._current_open_worker = worker
        def current_open():
            return req_id == self._image_open_req_id and self._current_open_worker is worker
        worker.signals.status.connect(lambda msg: self.status_label.setText(msg) if current_open() else None)
        worker.signals.progress.connect(
            lambda c, t: self.progress_bar.setValue(int(c * 100 / max(1, t))) if current_open() else None)
        worker.signals.session_ready.connect(self._on_image_open_ready)
        worker.signals.error.connect(lambda msg: self._on_image_open_error(msg) if current_open() else None)
        self._start_task(worker)

    def _on_image_open_ready(self, req_id: int, new_session: ForensicSession):
        if req_id != self._image_open_req_id:
            new_session.close()
            return
        self._current_open_worker = None
        self._teardown_active_session()
        self.session = new_session
        self._open_case_store()
        self._populate_partitions()
        cached_cnt = new_session.index_db.get_total_indexed_entries() if new_session.index_db else 0
        self.status_label.setText(
            f"✅ Opened {os.path.basename(new_session.image_path)} — {len(new_session.partitions)} partition(s), "
            f"{cached_cnt:,} entries in SQLite WAL cache."
        )

    def _on_image_open_error(self, message: str):
        self._current_open_worker = None
        self.act_open_img.setEnabled(True)
        self._hide_progress_bar_if_idle()
        self.status_label.setText(f"⚠️ {message}")
        self._show_message("warning", "Error Opening Image", message)

    @staticmethod
    def _partition_is_browsable(pm: "PartitionModel") -> bool:
        if pm.bitlocker_info.is_encrypted:
            return pm.bitlocker_info.is_unlocked  # locked volumes cannot be listed yet
        return pm.fs_type not in ("Unrecognized", "Unknown", "Raw/Unknown", "RAW", "SWAP", "BitLocker")

    def _populate_partitions(self, select_index: Optional[int] = None):
        self.combo_partition.blockSignals(True)
        self.combo_partition.clear()
        if self.session:
            for pm in self.session.partitions:
                sz_mb = pm.size / (1024 * 1024)
                if pm.bitlocker_info.is_encrypted:
                    icon = "🔓" if pm.bitlocker_info.is_unlocked else "🔒"
                    bde_tag = " [BitLocker Unlocked]" if pm.bitlocker_info.is_unlocked else " [BitLocker Encrypted]"
                else:
                    icon = "💾"
                    bde_tag = ""
                label = f"{icon} P{pm.index}: {pm.description} ({pm.fs_type}, {sz_mb:,.0f} MB){bde_tag}"
                self.combo_partition.addItem(label, pm.index)
                # Full label stays reachable on hover even though the
                # box itself is now width-capped (see selector fix).
                self.combo_partition.setItemData(
                    self.combo_partition.count() - 1, label, ROLE_TOOLTIP
                )
        if self.combo_partition.count() > 0:
            # Fix 12 (2026-11-02, fresh audit): default to the first
            # partition with a recognised filesystem instead of
            # always P0. M57-Jean's P0 is unallocated (0 MB, no
            # filesystem), so the old default showed an empty table
            # until the user manually picked P1 (NTFS). Unlocked
            # BitLocker partitions count as recognised; locked ones
            # do not, since their contents cannot be listed yet.
            # (A locked BitLocker partition used to count as "recognised" because its fs_type is
            # 'BitLocker', so the default selection could land on an unlistable volume.)
            preferred = 0
            if select_index is not None and 0 <= select_index < self.combo_partition.count():
                preferred = select_index
            elif self.session:
                for pm in self.session.partitions:
                    if self._partition_is_browsable(pm):
                        preferred = pm.index
                        break
            self.combo_partition.setCurrentIndex(preferred)
            self.combo_partition.blockSignals(False)
            self.action_partition_changed()
        else:
            self.combo_partition.blockSignals(False)

    def action_partition_changed(self):
        if not self.session or self.combo_partition.currentIndex() < 0:
            return
        if self._current_diff_worker is not None:
            self._current_diff_worker.cancel()
            self._current_diff_worker = None
        self._shown_diff_worker = None
        self._pending_select_entry = None
        self.current_part_idx = self.combo_partition.currentData()
        pm = self.session.partitions[self.current_part_idx]

        self.act_unlock_bde.setEnabled(pm.bitlocker_info.is_encrypted)
        self.diff_model.set_entries([])
        if self.search_dialog is not None:
            self.search_dialog.reset()
        self._populate_vss_comboboxes(preserve_selection=False)
        self._reset_and_load_root("/")

    def _populate_vss_comboboxes(self, preserve_selection: bool = False):
        if not self.session or not self.session.partitions:
            return
        pm = self.session.partitions[self.current_part_idx]
        prev_snap = self.current_snap_id if preserve_selection else "Live"

        self.combo_vss.blockSignals(True)
        self.combo_diff_a.blockSignals(True)
        self.combo_diff_b.blockSignals(True)

        self.combo_vss.clear()
        self.combo_diff_a.clear()
        self.combo_diff_b.clear()

        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            self.combo_vss.addItem("🔒 BitLocker Locked (Use File -> Unlock BitLocker Volume / Ctrl+U)", "Locked")
            self.combo_vss.setEnabled(False)
            self.combo_vss.blockSignals(False)
            self.combo_diff_a.blockSignals(False)
            self.combo_diff_b.blockSignals(False)
            return

        self.combo_vss.setEnabled(True)
        restore_idx = 0
        for i, snap in enumerate(pm.snapshots):
            if snap["creation_utc"] is not None:
                ts_str = format_epoch_tz(snap["creation_utc"], self.current_tz_info, include_tz_label=True)
                display = f"📂 {snap['label']} — {ts_str}"
            else:
                display = f"🔍 {snap['label']}"

            self.combo_vss.addItem(display, snap["id"])
            self.combo_vss.setItemData(
                self.combo_vss.count() - 1, display, ROLE_TOOLTIP
            )
            self.combo_diff_a.addItem(display, snap["id"])
            self.combo_diff_b.addItem(display, snap["id"])
            if snap["id"] == prev_snap:
                restore_idx = i

        self.combo_vss.setCurrentIndex(restore_idx)
        if self.combo_diff_a.count() > 1:
            self.combo_diff_a.setCurrentIndex(1)
            self.combo_diff_b.setCurrentIndex(0)

        self.combo_vss.blockSignals(False)
        self.combo_diff_a.blockSignals(False)
        self.combo_diff_b.blockSignals(False)
        self.current_snap_id = self.combo_vss.currentData() or "Live"

    def action_vss_changed(self):
        snap_id = self.combo_vss.currentData()
        if not snap_id or snap_id == "Locked" or not self.session:
            return
        self.current_snap_id = snap_id
        if self.search_dialog is not None:
            self.search_dialog.update_coverage()
        self._reset_and_load_root(target_path=self.current_path)

    def action_unlock_bitlocker(self):
        if not self.session:
            return
        start_token = self.session.session_token
        part_idx = self.current_part_idx
        pm = self.session.partitions[part_idx]
        if not pm.bitlocker_info.is_encrypted:
            return

        was_already_unlocked = pm.bitlocker_info.is_unlocked
        dlg = BitLockerCredentialsDialog(pm.bitlocker_info, self)
        accepted = dlg.exec() == DLG_ACCEPTED
        if not self._is_valid_session_token(start_token):
            dlg.clear_credentials()
            return
        if accepted and not was_already_unlocked and not self.session.is_demo and pm.bitlocker_info.bde_volume is None:
            # FIX (2026-11-03): this used to report "verify your password", although no
            # password was ever tried because libbde never opened the volume.
            dlg.clear_credentials()
            reason = (
                "pybde (libbde-python) is not installed."
                if not BITLOCKER_AVAILABLE
                else "libbde could not parse this volume's BitLocker metadata (see the log for the error)."
            )
            self._show_message("critical", "BitLocker Unlock Unavailable", f"❌ The volume cannot be unlocked: {reason}")
            return
        if accepted and not was_already_unlocked:
            self.status_label.setText("🔓 Unlocking BitLocker volume...")
            QApplication.processEvents()
            if not self._is_valid_session_token(start_token):
                dlg.clear_credentials()
                return
            try:
                success = BitLockerAnalyzer.unlock_bitlocker_volume(
                    pm.bitlocker_info, dlg.password, dlg.recovery_key
                )
            finally:
                # FIX (2026-11-02, issue 6): credentials are cleared
                # whether unlock succeeded or failed.
                dlg.clear_credentials()
            if success:
                self.session.finalize_unlock(pm)
                self._populate_partitions(select_index=part_idx)
                QMessageBox.information(
                    self,
                    "BitLocker Unlock Success",
                    "🔓 BitLocker volume unlocked successfully!\nVolume Shadow Copies and filesystem are now accessible.",
                )
            else:
                self._show_message(
                    "critical",
                    "BitLocker Unlock Failed",
                    "❌ BitLocker unlock failed — please verify your password or 48-digit recovery key.",
                )

    def _clear_tree_item_children(self, parent_item: QTreeWidgetItem):
        def _unregister_descendants(item: QTreeWidgetItem):
            for i in range(item.childCount()):
                child = item.child(i)
                entry = child.data(0, ROLE_USER)
                key = self._tree_key(entry) if entry else None
                if key and key in self.tree_nodes_by_path:
                    if self.tree_nodes_by_path[key] is child:
                        del self.tree_nodes_by_path[key]
                _unregister_descendants(child)

        _unregister_descendants(parent_item)
        parent_item.takeChildren()

    def _reset_and_load_root(self, target_path: str = "/"):
        self._preview_request_id += 1
        self.hex_panel.cancel_tasks()
        self.tree_widget.clear()
        self.tree_nodes_by_path.clear()
        self.loading_tree_paths.clear()
        self.table_model.set_entries([])
        self._current_dir_entries = []
        self.hex_viewer.clear_source()
        self.text_preview.clear()
        self._dir_entry_by_path.clear()

        if not self.session:
            return
        pm = self.session.partitions[self.current_part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            self.edit_location.setText("🔒 BitLocker Volume Locked")
            self.status_label.setText(
                "🔒 Partition is BitLocker locked — unlock via File -> Unlock / Inspect BitLocker Volume (Ctrl+U)."
            )
            return

        root_entry = {"name": "/ (Root)", "path": "/", "is_dir": True, "size": 0, "inode": 0}
        root_item = QTreeWidgetItem(self.tree_widget)
        root_item.setText(0, "💿 / (Root)")
        root_item.setData(0, ROLE_USER, root_entry)
        self.tree_nodes_by_path["/"] = root_item

        self.navigate_to_path(target_path or "/")

    def _child_may_have_subdirs(self, d_entry: Dict[str, Any]) -> bool:
        if d_entry.get("meta_realloc"):
            return False  # its original contents cannot be listed
        if ForensicSession.needs_inode_open(d_entry) or not self.session:
            return True  # not in the path-keyed caches; find out on expansion
        known = self.session.get_known_child_dir_count(self.current_part_idx, self.current_snap_id, d_entry["path"])
        return known is None or known > 0

    def _populate_tree_children(self, parent_path: str, entries: List[Dict[str, Any]]):
        # parent_path is a tree key (see _tree_key), equal to the path for live folders.
        parent_item = self.tree_nodes_by_path.get(parent_path)
        if not parent_item:
            return

        dir_entries = [e for e in entries if e["is_dir"]]
        new_dir_paths = [self._tree_key(e) for e in dir_entries]

        has_loading_dummy = (
            parent_item.childCount() == 1 and parent_item.child(0).text(0) == "Loading..."
        )
        if not has_loading_dummy and parent_item.childCount() > 0:
            existing_paths = []
            for i in range(parent_item.childCount()):
                c_entry = parent_item.child(i).data(0, ROLE_USER)
                if c_entry:
                    existing_paths.append(self._tree_key(c_entry))
            if existing_paths == new_dir_paths:
                for i in range(parent_item.childCount()):
                    child_item = parent_item.child(i)
                    c_entry = child_item.data(0, ROLE_USER)
                    if c_entry and child_item.childCount() == 0 and self._child_may_have_subdirs(c_entry):
                        dummy = QTreeWidgetItem(child_item)
                        dummy.setText(0, "Loading...")
                return

        self._clear_tree_item_children(parent_item)

        for d_entry in dir_entries:
            child_item = QTreeWidgetItem(parent_item)
            icon = FileIconProvider.get_file_icon(d_entry["name"], True, bool(d_entry.get("is_deleted")))
            badge = f"  {ADS_BADGE}" if ads_streams(d_entry) else ""
            child_item.setText(0, f"{icon} {d_entry['name']}{badge}")
            child_item.setData(0, ROLE_USER, d_entry)
            self.tree_nodes_by_path[self._tree_key(d_entry)] = child_item

            if self._child_may_have_subdirs(d_entry):
                dummy = QTreeWidgetItem(child_item)
                dummy.setText(0, "Loading...")

        if parent_path == "/":
            parent_item.setExpanded(True)

    def on_tree_item_expanded(self, item: QTreeWidgetItem):
        if not item or not self.session:
            return
        entry = item.data(0, ROLE_USER)
        if not entry:
            return
        path = entry["path"]
        key = self._tree_key(entry)

        if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
            if key in self.loading_tree_paths:
                return
            self.loading_tree_paths.add(key)
            worker = DirectoryLoadWorker(
                self.session, self.current_part_idx, self.current_snap_id, path, tree_only=True,
                dir_entry=entry if entry.get("path") != "/" else None, tree_key=key,
            )
            worker.signals.tree_children_ready.connect(self._on_tree_children_ready)
            worker.signals.error.connect(lambda msg, k=key: (self.loading_tree_paths.discard(k), self._on_worker_error(msg)))
            worker.signals.finished.connect(lambda k=key: self.loading_tree_paths.discard(k))
            self._start_task(worker)

    def _on_tree_children_ready(self, token: int, part_idx: int, snap_id: str, path: str, entries: List[Dict[str, Any]]):
        self.loading_tree_paths.discard(path)
        if not self._is_valid_session_token(token):
            return
        if self.search_dialog is not None:
            self.search_dialog.update_coverage()
        if part_idx == self.current_part_idx and snap_id == self.current_snap_id:
            self._populate_tree_children(path, entries)

    def on_tree_item_clicked(self, item: QTreeWidgetItem, column: int):
        if not item:
            return
        entry = item.data(0, ROLE_USER)
        if entry and entry.get("is_dir"):
            self.navigate_to_path(entry["path"], entry)

    def navigate_to_path(self, path: str, dir_entry: Optional[Dict[str, Any]] = None):
        if not self.session:
            return
        pm = self.session.partitions[self.current_part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            return

        norm_path = normalize_forensic_path(path)
        # FIX (2026-11-03): a deleted folder is navigated by its entry (inode). Walking its
        # path would land in the live folder of the same name. Remember the entry per path so
        # "Up"/"Refresh" from inside a deleted subtree stay in that subtree.
        if dir_entry is None:
            dir_entry = self._dir_entry_by_path.get(norm_path)
        if dir_entry is not None and ForensicSession.needs_inode_open(dir_entry):
            self._dir_entry_by_path[norm_path] = dir_entry
        else:
            self._dir_entry_by_path.pop(norm_path, None)
            dir_entry = None
        self.current_path = norm_path
        self._nav_request_id += 1
        self._nav_dir_entry = dir_entry

        worker = DirectoryLoadWorker(
            self.session,
            self.current_part_idx,
            self.current_snap_id,
            norm_path,
            tree_only=False,
            nav_req_id=self._nav_request_id,
            dir_entry=dir_entry,
        )
        worker.signals.navigation_ready.connect(self._on_navigation_ready)
        worker.signals.status.connect(self.status_label.setText)
        worker.signals.error.connect(self._on_worker_error)
        self._start_task(worker)

    def _on_navigation_ready(
        self,
        token: int,
        nav_req_id: int,
        part_idx: int,
        snap_id: str,
        resolved_path: str,
        entries: List[Dict[str, Any]],
        ancestor_chain: List[Tuple[str, List[Dict[str, Any]]]],
    ):
        if not self._is_valid_session_token(token):
            return
        if part_idx != self.current_part_idx or snap_id != self.current_snap_id:
            return

        for anc_path, anc_entries in ancestor_chain:
            if anc_path in self.tree_nodes_by_path:
                self._populate_tree_children(anc_path, anc_entries)

        if nav_req_id != self._nav_request_id:
            return

        self.current_path = resolved_path
        deleted_ctx = ForensicSession.needs_inode_open(self._nav_dir_entry)
        location = "/ (Root)" if resolved_path == "/" else resolved_path
        self.edit_location.setText(f"{location}   [deleted folder, inode {self._nav_dir_entry['inode']}]" if deleted_ctx else location)
        self._current_dir_entries = entries
        # Reset before restoring a pending selection, which binds fresh inspectors.
        self._preview_request_id += 1
        self.hex_panel.cancel_tasks()
        self.hex_viewer.clear_source()
        self.text_preview.clear()
        self.table_model.set_entries(self._with_ads_rows(entries))
        if self._pending_select_entry is not None:
            target, self._pending_select_entry = self._pending_select_entry, None
            rows = self.table_model.get_entries()
            hit = next((i for i, e in enumerate(rows)
                        if e["path"] == target["path"] and e.get("inode") == target.get("inode")
                        and bool(e.get("is_deleted")) == bool(target.get("is_deleted"))
                        and e.get("ads_attr_id") == target.get("ads_attr_id")), None)
            if hit is None:
                hit = next((i for i, e in enumerate(rows) if e["path"] == target["path"]), None)
            if hit is not None:
                pidx = self.proxy_model.mapFromSource(self.table_model.index(hit, 0))
                self.file_table.selectRow(pidx.row())
                self.file_table.scrollTo(pidx)
        self._sync_tree_selection_to_path(self._tree_key(self._nav_dir_entry) if deleted_ctx else resolved_path)
        if self.search_dialog is not None:
            self.search_dialog.update_coverage()
        self.status_label.setText(
            f"✅ [{snap_id}] {resolved_path} — {len(entries)} items ({self.current_tz_name}, SQLite WAL Cached)"
        )

    def _with_ads_rows(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """FEATURE (2026-11-04): add one virtual row per alternate data stream."""
        if not getattr(self, "act_show_ads_rows", None) or not self.act_show_ads_rows.isChecked():
            return list(entries)
        rows: List[Dict[str, Any]] = []
        for e in entries:
            rows.append(e)
            if not e.get("meta_realloc"):
                rows.extend(make_ads_entry(e, st) for st in ads_streams(e))
        return rows

    def _refresh_table_rows(self):
        self._preview_request_id += 1
        self.hex_panel.cancel_tasks()
        self.table_model.set_entries(self._with_ads_rows(getattr(self, "_current_dir_entries", []) or []))
        self.hex_viewer.clear_source()
        self.text_preview.clear()

    def _sync_tree_selection_to_path(self, target_path: str):
        item = self.tree_nodes_by_path.get(target_path)
        if item:
            self.tree_widget.blockSignals(True)
            self.tree_widget.setCurrentItem(item)
            parent = item.parent()
            while parent:
                parent.setExpanded(True)
                parent = parent.parent()
            self.tree_widget.blockSignals(False)

    def action_table_double_clicked(self, proxy_idx: QModelIndex):
        src_idx = self.proxy_model.mapToSource(proxy_idx)
        entry = self.table_model.data(src_idx, ROLE_USER)
        if entry and entry["is_dir"]:
            if entry.get("meta_realloc"):
                self._show_message(
                    "warning", "Folder Not Listable",
                    f"'{entry['name']}' is a deleted folder whose inode {entry.get('inode')} now belongs to a "
                    "newer file or folder, so its original contents cannot be listed.",
                )
                return
            self.navigate_to_path(entry["path"], entry)

    def on_diff_row_double_clicked(self, proxy_idx: QModelIndex):
        src_idx = self.diff_proxy.mapToSource(proxy_idx)
        entry = self.diff_model.data(src_idx, ROLE_USER)
        if entry:
            self.reveal_entry(entry)

    def _switch_snapshot(self, target_snap: str, open_path: str) -> bool:
        """Select target_snap in the snapshot combo and open open_path there.
        Returns False when it already is the current snapshot (nothing done)."""
        if not target_snap or target_snap == self.current_snap_id:
            return False
        idx = self.combo_vss.findData(target_snap)
        if idx < 0:
            return False
        self.combo_vss.blockSignals(True)
        self.combo_vss.setCurrentIndex(idx)
        self.combo_vss.blockSignals(False)
        self.current_snap_id = target_snap
        if self.search_dialog is not None:
            self.search_dialog.update_coverage()
        self._reset_and_load_root(open_path)
        return True

    def reveal_entry(self, entry: Dict[str, Any]):
        """FEATURE (2026-11-04): open the folder holding entry (in its snapshot) and select it."""
        if not self.session or not entry:
            return
        pm = self.session.partitions[self.current_part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            self._show_message(
                "warning", "BitLocker Volume Locked",
                "Partition is BitLocker locked — unlock via File -> Unlock / Inspect BitLocker Volume (Ctrl+U)."
            )
            return
        target_snap = entry.get("source_snap") or self.current_snap_id
        if self.combo_vss.findData(target_snap) < 0:
            self._show_message("warning", "Snapshot Unavailable", f"Snapshot '{target_snap}' is not available on this partition.")
            return
        self.edit_filter.clear()
        if entry.get("ads_stream") is not None:
            self.act_show_ads_rows.setChecked(True)
        host_path = entry.get("ads_host_path") or entry["path"]
        parent_dir = posixpath.dirname(host_path.rstrip("/")) or "/"
        if not entry.get("via_inode"):
            self._dir_entry_by_path.pop(parent_dir, None)
        self._pending_select_entry = dict(entry)
        if not self._switch_snapshot(target_snap, parent_dir):
            self.navigate_to_path(parent_dir)
        self.raise_()
        self.activateWindow()

    def extra_entry_actions(self, items: List[Dict[str, Any]]) -> List[Tuple[str, Any]]:
        """Context-menu actions shared by the file table, search results and bookmarks."""
        actions: List[Tuple[str, Any]] = []
        if items and self.case_store is not None:
            actions.append((f"{BOOKMARK_BADGE} Bookmark / Tag...", lambda its=list(items): self.action_bookmark(its)))
        if len(items) == 1 and not items[0].get("is_dir"):
            actions.append(("🕘 Version History Across Snapshots...", lambda e=items[0]: self.open_version_history(e)))
        return actions

    def _selected_table_entries(self) -> List[Dict[str, Any]]:
        out = []
        for idx in self.file_table.selectionModel().selectedRows():
            e = self.table_model.data(self.proxy_model.mapToSource(idx), ROLE_USER)
            if e:
                e = dict(e)
                e.setdefault("source_snap", self.current_snap_id)
                out.append(e)
        return out

    def action_version_history_selected(self):
        items = [e for e in self._selected_table_entries() if not e.get("is_dir")]
        if not items:
            self._show_message("info", "Version History", "Select a file (or ADS stream) in the file table first.")
            return
        self.open_version_history(items[0])

    def open_version_history(self, entry: Dict[str, Any]):
        if not self.session:
            return
        part_idx = self.current_part_idx
        pm = self.session.partitions[part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            self._show_message(
                "warning", "BitLocker Volume Locked",
                "Partition is BitLocker locked — unlock via File -> Unlock / Inspect BitLocker Volume (Ctrl+U).",
            )
            return
        start_token = self.session.session_token
        if entry.get("via_inode"):
            self._show_message("info", "Version History",
                               "This item is inside a deleted folder; it can only be matched by path in "
                               "other snapshots, which may find a different, live item with the same path.")
            if not self._is_valid_session_token(start_token) or self.current_part_idx != part_idx:
                return
        dlg = VersionHistoryDialog(self, entry)
        self._version_dialogs.append(dlg)
        self._history_req = getattr(self, "_history_req", 0) + 1
        worker = VersionHistoryWorker(self.session, part_idx, entry, self._history_req)
        dlg.finished.connect(worker.cancel_event.set)
        dlg.finished.connect(
            lambda _=None, d=dlg: self._version_dialogs.remove(d) if d in self._version_dialogs else None
        )
        worker.signals.history_ready.connect(
            lambda tok, req, rows, d=dlg: d.set_rows(rows) if self._is_valid_session_token(tok) else None)
        worker.signals.status.connect(dlg.status.setText)
        worker.signals.error.connect(dlg.status.setText)
        dlg.show()
        self._start_task(worker)

    # ---- FEATURE (2026-11-04): bookmarks, case info, image hash, report -------
    def _open_case_store(self):
        try:
            self.case_store = CaseStore.for_session(self.session)
        except Exception as e:
            self.case_store = None
            logger.error(f"Case store unavailable: {e}")
        sess = self.session
        store = self.case_store
        if (store is not None and sess is not None and not sess.is_demo and sess.index_db
                and sess.media is not None and sess.media.kind != "device"):
            fp = sess.index_db._compute_fingerprint()
            old = store.check_fingerprint(fp)
            if old is not None:
                n = len(store.list_bookmarks())
                store.set_info({"_fingerprint_changed_utc": str(int(time.time())), "_previous_fingerprint": old})
                store.accept_fingerprint(fp)
                self._show_message(
                    "warning", "Case File Belongs to a Different Image?",
                    f"This image's file fingerprint (segment sizes / modification times) differs from the one "
                    f"recorded when its case file was created. The {n} bookmark(s) and logs in this case may "
                    f"refer to a different image that used the same path.\n\nVerify the evidence (Tools > Compute / "
                    f"Verify Image Hash). The new fingerprint is now recorded; the report notes the change.",
                )
        if self.bookmarks_dialog is not None:
            self.bookmarks_dialog.refresh()

    def _bookmark_marker(self, entry: Dict[str, Any]) -> str:
        if self.case_store is None:
            return ""
        snap = entry.get("source_snap") or self.current_snap_id
        return f"  {BOOKMARK_BADGE}" if self.case_store.is_bookmarked(self.current_part_idx, snap, entry) else ""

    def _refresh_markers(self):
        n = self.table_model.rowCount()
        if n:
            self.table_model.dataChanged.emit(self.table_model.index(0, 0), self.table_model.index(n - 1, 0))

    def action_bookmark(self, items: List[Dict[str, Any]]):
        store = self.case_store
        if store is None or not items:
            if not items:
                self._show_message("info", "Bookmark", "Select one or more items first.")
            return
        part_idx = self.current_part_idx
        default_snap = self.current_snap_id
        first = items[0]
        existing = next((b for b in store.list_bookmarks()
                         if CaseStore.entry_key(b["part_idx"], b["snap_id"], b["entry"])
                         == CaseStore.entry_key(part_idx, first.get("source_snap") or default_snap, first)), None)
        dlg = BookmarkEditDialog(self, store.tags(), len(items),
                                 existing["tag"] if existing else "", existing["note"] if existing else "")
        if dlg.exec() != DLG_ACCEPTED or self.case_store is not store:
            return
        for e in items:
            store.upsert_bookmark(part_idx, e.get("source_snap") or default_snap,
                                  e, dlg.tag, dlg.note)
        self._refresh_markers()
        if self.bookmarks_dialog is not None:
            self.bookmarks_dialog.refresh()
        self.status_label.setText(f"{BOOKMARK_BADGE} Bookmarked {len(items)} item(s) as '{dlg.tag}'.")

    def action_show_bookmarks(self):
        if self.bookmarks_dialog is None:
            self.bookmarks_dialog = BookmarksDialog(self)
        self.bookmarks_dialog.refresh()
        self.bookmarks_dialog.show()
        self.bookmarks_dialog.raise_()

    def action_case_info(self):
        store = self.case_store
        if store is None:
            self._show_message("info", "Case Information", "Open an image (or the demo case) first.")
            return
        dlg = CaseInfoDialog(self, store.get_info())
        if dlg.exec() == DLG_ACCEPTED and self.case_store is store:
            store.set_info(dlg.values())

    def action_image_hash(self):
        if not self.session or self.case_store is None:
            return
        if self.session.is_demo:
            self._show_message("info", "Image Hash", "The demo case has no image file to hash.")
            return
        if self._image_hash_worker is not None:
            # AUDIT FIX (2026-11-04): hashing a large image can take hours; it could only be
            # stopped by closing the image.
            running_worker = self._image_hash_worker
            yes = QMessageBox.StandardButton.Yes if hasattr(QMessageBox, "StandardButton") else QMessageBox.Yes
            no = QMessageBox.StandardButton.No if hasattr(QMessageBox, "StandardButton") else QMessageBox.No
            if QMessageBox.question(self, "Image Hash", "Image hashing is running. Cancel it?", yes | no) == yes:
                if self._image_hash_worker is running_worker and running_worker is not None:
                    running_worker.cancel_event.set()
                    self._image_hash_worker = None
                    self._hide_progress_bar_if_idle()
                    self.status_label.setText("🛑 Image hashing cancelled.")
            return
        token = self.session.session_token
        worker = ImageHashWorker(self.session)
        self._image_hash_worker = worker
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        def current_hash():
            return self._image_hash_worker is worker and self._is_valid_session_token(token)
        worker.signals.progress.connect(
            lambda c, t: self.progress_bar.setValue(int(c * 100 / max(1, t))) if current_hash() else None)
        worker.signals.status.connect(lambda msg: self.status_label.setText(msg) if current_hash() else None)
        worker.signals.image_hash_ready.connect(
            lambda tok, res: self._on_image_hash_ready(tok, res) if current_hash() else None)
        worker.signals.error.connect(lambda msg: self._on_image_hash_error(msg) if current_hash() else None)
        worker.signals.finished.connect(lambda w=worker: self._on_image_hash_finished(w))
        self._start_task(worker)

    def _on_image_hash_finished(self, worker: ImageHashWorker):
        if self._image_hash_worker is worker:
            self._image_hash_worker = None
            self._hide_progress_bar_if_idle()

    def _on_image_hash_error(self, message: str):
        self._image_hash_worker = None
        self._on_worker_error(message)

    def _on_image_hash_ready(self, token: int, result: Dict[str, Any]):
        self._image_hash_worker = None
        self._hide_progress_bar_if_idle()
        if not self._is_valid_session_token(token) or self.case_store is None:
            return
        self.case_store.log_image_hash(result)
        stored = "".join(f"\nStored {k}: {v}" for k, v in result.get("stored", {}).items())
        self.status_label.setText(f"🔐 Image hashed — {result.get('verification')}")
        self._show_message(
            "warning" if "MISMATCH" in result.get("verification", "") else "info", "Image Hash",
            f"MD5:     {result['md5']}\nSHA-1:   {result['sha1']}\nSHA-256: {result['sha256']}\n"
            f"Bytes:   {result['bytes_hashed']:,} of {result['media_size']:,}{stored}\n\n"
            f"Verification: {result.get('verification')}",
        )

    def action_case_report(self):
        if not self.session or self.case_store is None:
            self._show_message("info", "Case Report", "Open an image (or the demo case) first.")
            return
        start_token = self.session.session_token
        store = self.case_store
        info = store.get_info()
        default_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"case_report_{info.get('case_number') or 'vscexplorer'}") + ".html"
        path, _ = QFileDialog.getSaveFileName(self, "Save Case Report", default_name, "HTML report (*.html)")
        if not path or not self._is_valid_session_token(start_token) or self.case_store is not store:
            return
        if not path.lower().endswith(".html"):
            path += ".html"
        if self._report_worker is not None:
            self._report_worker.cancel_event.set()
        worker = CaseReportWorker(self.session, store)
        self._report_worker = worker
        def current_report():
            return self._report_worker is worker and self._is_valid_session_token(start_token)
        worker.signals.status.connect(lambda msg: self.status_label.setText(msg) if current_report() else None)
        # AUDIT FIX (2026-11-04): the target path travels with its own run; a shared
        # attribute let a second report request redirect the first one's output.
        worker.signals.report_ready.connect(
            lambda tok, data, target=path: self._on_report_data(tok, data, target) if current_report() else None)
        worker.signals.error.connect(lambda msg: self._on_worker_error(msg) if current_report() else None)
        worker.signals.finished.connect(
            lambda w=worker: setattr(self, "_report_worker", None) if self._report_worker is w else None)
        self._start_task(worker)

    def _on_report_data(self, token: int, data: Dict[str, Any], html_path: str):
        if not self._is_valid_session_token(token) or not html_path:
            return
        try:
            written = write_case_report(self.session, data, html_path)
        except Exception as e:
            self._show_message("critical", "Case Report", f"Could not write the report: {e}")
            return
        self.status_label.setText(f"📄 Case report written: {html_path}")
        self._show_message("info", "Case Report", "Report written:\n" + "\n".join(
            f"{p}\n  SHA-256 {h}" for p, h in written))

    def action_open_search(self):
        if self.search_dialog is None:
            self.search_dialog = SnapshotSearchDialog(self)
        self.search_dialog.update_coverage()
        self.search_dialog.show()
        self.search_dialog.raise_()
        self.search_dialog.activateWindow()
        self.search_dialog.query_edit.setFocus()

    def action_navigate_up(self):
        if self.current_path in ("/", ""):
            return
        parent = posixpath.dirname(self.current_path.rstrip("/"))
        self.navigate_to_path(parent if parent else "/")

    def action_refresh_folder(self):
        if not self.session:
            return
        self.session.invalidate_directory_cache(self.current_part_idx, self.current_snap_id, self.current_path)
        self.navigate_to_path(self.current_path)

    @classmethod
    def _set_subtree_expanded(cls, item: QTreeWidgetItem, expanded: bool):
        item.setExpanded(expanded)
        for i in range(item.childCount()):
            cls._set_subtree_expanded(item.child(i), expanded)

    def show_tree_context_menu(self, position):
        item = self.tree_widget.itemAt(position)
        if not item:
            return
        entry = item.data(0, ROLE_USER)

        menu = QMenu(self)
        menu.addAction("📂 Expand All", lambda: self._set_subtree_expanded(item, True))
        menu.addAction("📁 Collapse All", lambda: self._set_subtree_expanded(item, False))
        menu.addSeparator()
        if entry:
            menu.addAction("📤 Export This Folder...", lambda: self._launch_export([entry]))
            menu.addSeparator()
        menu.addAction("🔄 Refresh", lambda: self._refresh_tree_item(item))
        menu.exec(self.tree_widget.viewport().mapToGlobal(position))

    def _refresh_tree_item(self, item: QTreeWidgetItem):
        if not item or not self.session:
            return
        entry = item.data(0, ROLE_USER)
        if not entry:
            return
        path = entry["path"]
        self.session.invalidate_directory_cache(self.current_part_idx, self.current_snap_id, path)
        self.navigate_to_path(path, entry if path != "/" else None)

    def show_file_context_menu(self, pos):
        menu = QMenu(self)
        menu.addAction("📤 Export Selected Items...", self.action_export_selected)
        menu.addAction("📦 Export All in Current Folder...", self.action_export_all)
        selected = self._selected_table_entries()
        extra = self.extra_entry_actions(selected)
        if extra:
            menu.addSeparator()
            for label, fn in extra:
                menu.addAction(label, fn)
        menu.addSeparator()
        menu.addAction("🔄 Refresh Folder", self.action_refresh_folder)
        menu.exec(self.file_table.viewport().mapToGlobal(pos))

    def show_diff_context_menu(self, pos):
        selected = self.diff_table.selectionModel().selectedRows()
        if not selected:
            return
        menu = QMenu(self)
        menu.addAction("📤 Export Selected Changed Items...", self.action_export_selected_diff)
        menu.addAction("📂 Navigate to Containing Folder", lambda: self.on_diff_row_double_clicked(selected[0]))
        menu.exec(self.diff_table.viewport().mapToGlobal(pos))

    def action_export_selected_diff(self):
        """
        Fixed P1-02: Scopes parent directory prefix deduplication to matching `source_snap`
        so DELETED files from Baseline VSS are never dropped when a parent folder from Target is selected.
        """
        if not self.session:
            return
        selected = self.diff_table.selectionModel().selectedRows()
        if not selected:
            return
        raw_items = [
            self.diff_model.data(self.diff_proxy.mapToSource(idx), ROLE_USER)
            for idx in selected
        ]
        valid_items = [i for i in raw_items if i]
        self._launch_export(valid_items)

    def action_table_selection_changed(self):
        # Invalidate queued results even when selection is cleared or inspectors disabled.
        self._preview_request_id += 1
        if not self.opt_enable_hex and not self.opt_enable_metadata:
            return
        if not self.session:
            return

        selected_rows = self.file_table.selectionModel().selectedRows()
        if not selected_rows:
            self.hex_panel.cancel_tasks()
            if self.opt_enable_hex:
                self.hex_viewer.clear_source()
            if self.opt_enable_metadata:
                self.text_preview.clear()
            return

        src_idx = self.proxy_model.mapToSource(selected_rows[0])
        entry = self.table_model.data(src_idx, ROLE_USER)
        if not entry:
            return

        if self.opt_enable_hex:
            self.hex_panel.cancel_tasks()
            self.hex_viewer.bind_file(self.session, self.current_part_idx, self.current_snap_id, entry)

        if self.opt_enable_metadata:
            worker = MetadataPreviewWorker(
                self.session,
                self.current_part_idx,
                self.current_snap_id,
                entry,
                self.current_tz_info,
                self.current_tz_name,
                preview_req_id=self._preview_request_id,
            )
            worker.signals.metadata_ready.connect(self._on_metadata_ready)
            worker.signals.error.connect(self._on_worker_error)
            self._start_task(worker)

    def _on_metadata_ready(self, token: int, preview_req_id: int, report: str):
        if self.opt_enable_metadata and self._is_valid_session_token(token) and preview_req_id == self._preview_request_id:
            self.text_preview.setPlainText(report)

    def action_run_diff(self):
        if not self.opt_enable_diff or not self.session or not self.session.partitions:
            return
        pm = self.session.partitions[self.current_part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            self.status_label.setText("🔒 Unlock BitLocker volume before running VSS Snapshot Diff.")
            return

        snap_a = self.combo_diff_a.currentData()
        snap_b = self.combo_diff_b.currentData()
        if not snap_a or not snap_b:
            return
        if self._current_diff_worker is not None:
            self._current_diff_worker.cancel()
            self._current_diff_worker = None
        self._shown_diff_worker = None
        if snap_a == snap_b:
            self.diff_model.set_entries([])
            self.status_label.setText("ℹ️ Baseline and Target snapshots are identical (0 differences).")
            return

        worker = SnapshotDiffWorker(self.session, self.current_part_idx, snap_a, snap_b)
        self._current_diff_worker = worker
        worker.signals.diff_ready.connect(lambda tok, d, w=worker: self._on_diff_ready(tok, d, w))
        worker.signals.warning.connect(lambda msg, w=worker: self._on_diff_warning(msg, w))
        def relevant_diff():
            return (self._is_valid_session_token(worker.token) and worker.part_idx == self.current_part_idx
                    and (worker is self._current_diff_worker or worker is self._shown_diff_worker))
        worker.signals.status.connect(lambda msg: self.status_label.setText(msg) if relevant_diff() else None)
        worker.signals.error.connect(lambda msg: self._on_worker_error(msg) if relevant_diff() else None)
        worker.signals.finished.connect(
            lambda w=worker: setattr(self, "_current_diff_worker", None) if self._current_diff_worker is w else None)
        self._start_task(worker)

    def _on_diff_ready(self, token: int, diffs: List[Dict[str, Any]], worker: Optional[SnapshotDiffWorker] = None):
        if worker is not None and (worker is not self._current_diff_worker or worker.part_idx != self.current_part_idx):
            return  # result of a superseded/cancelled comparison
        self._current_diff_worker = None
        if self._is_valid_session_token(token):
            self._shown_diff_worker = worker
            self.diff_model.set_entries(diffs)
            if self.search_dialog is not None:
                self.search_dialog.update_coverage()

    def _on_diff_warning(self, message: str, worker: SnapshotDiffWorker):
        if worker is self._shown_diff_worker and self._is_valid_session_token(worker.token):
            self._show_message("warning", "Partial Snapshot Diff", message)

    def action_export_selected(self):
        if not self.session:
            return
        selected = self.file_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, "Export Selected", "Please select one or more files or folders to export.")
            return
        items = [
            self.table_model.data(self.proxy_model.mapToSource(idx), ROLE_USER)
            for idx in selected
        ]
        self._launch_export([i for i in items if i])

    def action_export_all(self):
        if not self.session:
            return
        items = list(self._current_dir_entries)
        if not items:
            QMessageBox.information(self, "Export All", "Current folder is empty.")
            return
        self._launch_export(items)

    def _launch_export(self, items: List[Dict[str, Any]]):
        if not self.session:
            return
        part_idx = self.current_part_idx
        default_snap = self.current_snap_id
        pm = self.session.partitions[part_idx]
        if pm.bitlocker_info.is_encrypted and not pm.bitlocker_info.is_unlocked:
            self._show_message(
                "warning", "BitLocker Volume Locked",
                "Partition is BitLocker locked — unlock via File -> Unlock / Inspect BitLocker Volume (Ctrl+U)."
            )
            return
        if self._current_export_worker is not None:
            QMessageBox.warning(self, "Export Busy", "An export operation is already in progress.")
            return

        start_token = self.session.session_token
        opt_dlg = ExportOptionsDialog(self)
        if opt_dlg.exec() != DLG_ACCEPTED:
            return
        if not self._is_valid_session_token(start_token) or self._current_export_worker is not None:
            return

        dest_dir = QFileDialog.getExistingDirectory(self, "Select Forensic Export Destination")
        if not dest_dir:
            return
        if not self._is_valid_session_token(start_token) or self._current_export_worker is not None:
            return

        export_options = {
            "generate_csv": opt_dlg.generate_csv,
            "include_hashes": opt_dlg.include_hashes,
            "hash_types": opt_dlg.hash_types,
            "include_ads": opt_dlg.include_ads,
        }
        selected_dir_prefixes = [
            (i.get("source_snap", default_snap), i["path"], i["path"].rstrip("/") + "/")
            for i in items
            if i.get("is_dir")
        ]
        if selected_dir_prefixes:
            items = [
                i for i in items
                if not any(
                    i.get("source_snap", default_snap) == snap_key
                    and i["path"] != dir_path
                    and (i.get("ads_host_path") or i["path"]).startswith(prefix)
                    for snap_key, dir_path, prefix in selected_dir_prefixes
                )
            ]
        # Drop virtual ADS stream rows whose host file is also in items:
        # if include_ads=True, _collect_export_plan expands the host's streams once;
        # if include_ads=False, streams of selected host files must not be exported.
        hosts = {(i.get("source_snap", default_snap), i.get("path"), i.get("inode"))
                 for i in items if i.get("ads_stream") is None}
        items = [
            i for i in items
            if i.get("ads_stream") is None or
            (i.get("source_snap", default_snap), i.get("ads_host_path"), i.get("inode")) not in hosts
        ]

        self.act_export_sel.setEnabled(False)
        self.act_export_all.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.btn_cancel_export.setVisible(True)

        snap_ids = sorted({str(i.get("source_snap") or default_snap) for i in items})
        export_snap_label = ", ".join(snap_ids) if snap_ids else default_snap
        self._last_export_ctx = (part_idx, export_snap_label, dest_dir)
        worker = BufferedExportWorker(
            self.session, part_idx, default_snap, items, dest_dir, export_options
        )
        self._current_export_worker = worker
        token = self.session.session_token
        def current_export():
            return self._current_export_worker is worker and self._is_valid_session_token(token)
        worker.signals.progress.connect(
            lambda c, t: self.progress_bar.setValue(int(c * 100 / max(1, t))) if current_export() else None)
        worker.signals.status.connect(lambda msg: self.status_label.setText(msg) if current_export() else None)
        worker.signals.export_done.connect(
            lambda *args: self._on_export_finished(*args) if current_export() else None)
        worker.signals.error.connect(lambda msg: self._on_export_error(msg) if current_export() else None)
        self._start_task(worker)

    def action_cancel_export(self):
        if self._current_export_worker is not None:
            self._current_export_worker.cancel()
            self.status_label.setText("🛑 Cancelling export operation...")

    def _on_export_finished(self, success_count: int, total_count: int, manifest_path: str, was_cancelled: bool):
        self._current_export_worker = None
        if self.case_store is not None and self._last_export_ctx is not None:
            part_idx, snap_id, dest = self._last_export_ctx
            try:
                self.case_store.log_export(part_idx, snap_id, dest, manifest_path, total_count, success_count, was_cancelled)
            except Exception as e:
                logger.warning(f"Could not record export in case log: {e}")
        self.act_export_sel.setEnabled(True)
        self.act_export_all.setEnabled(True)
        self._hide_progress_bar_if_idle()
        self.btn_cancel_export.setVisible(False)

        if was_cancelled:
            self.status_label.setText(f"⚠️ Export cancelled ({success_count}/{total_count} items processed).")
            msg = f"Export was cancelled after {success_count} of {total_count} items."
            if manifest_path:
                msg += f"\n\nA manifest of the items processed before cancelling was written to:\n{manifest_path}"
            self._show_message("info", "Export Cancelled", msg)
            return

        self.status_label.setText(f"✅ Export complete: {success_count}/{total_count} items (files & subfolders).")
        msg = f"Successfully exported {success_count} out of {total_count} total recursive items."
        if success_count < total_count:
            msg += "\nItems not counted as successful are listed with their status in the CSV manifest."
        if manifest_path:
            msg += f"\n\nCSV Summary Report & Hashes written to:\n{manifest_path}"
        self._show_message("info", "Forensic Export Complete", msg)

    def _on_export_error(self, message: str):
        self._current_export_worker = None
        self.act_export_sel.setEnabled(True)
        self.act_export_all.setEnabled(True)
        self.btn_cancel_export.setVisible(False)
        self._on_worker_error(message)

    def action_run_selftest_ui(self):
        self.status_label.setText("🧪 Running automated forensic self-test suite...")
        QApplication.processEvents()
        passed, report = run_automated_self_tests()
        temp_hex_session = ForensicSession("hex_test", is_demo=True)
        test_viewer = VirtualHexViewer()
        try:
            test_viewer.bind_file(
                temp_hex_session,
                0,
                "Live",
                {"name": "hiberfil.sys", "path": "/hiberfil.sys", "is_dir": False, "size": 40 * 1024 ** 3, "inode": 16},
            )
            hex_ok = (
                test_viewer.verticalScrollBar().maximum() <= VirtualHexViewer.MAX_QT_SCROLL_RANGE
            )
            test_viewer.clear_source()
            hex_ok = hex_ok and test_viewer._session is None
        finally:
            test_viewer.deleteLater()
            temp_hex_session.close()

        report += f"\n{'✅ PASS' if hex_ok else '❌ FAIL'} | 64-Bit >32 GB VirtualHexViewer Scrollbar Scaling (40 GB file)"
        all_ok = passed and hex_ok
        self.status_label.setText("✅ Self-test suite passed!" if all_ok else "⚠️ Self-test suite found issues.")
        QMessageBox.information(
            self,
            "Automated Self-Test Results",
            f"Overall Status: {'ALL TESTS PASSED' if all_ok else 'FAILED'}\n\n{report}",
        )

    def action_show_dependencies(self):
        status_lines = [
            f"Qt GUI Framework : {'PySide6 (Qt6)' if QT_VER == 6 else 'PyQt5'}",
            f"SQLite3 WAL Engine: Available (v{sqlite3.sqlite_version})",
            f"pytsk3 (SleuthKit): {'Available' if TSK_AVAILABLE else 'Missing'}",
            f"pyewf (E01)      : {'Available' if EWF_AVAILABLE else 'Missing'}",
            f"pyvshadow (VSS)  : {'Available' if PYVSHADOW_AVAILABLE else 'Missing'}",
            f"pybde (BitLocker): {'Available' if BITLOCKER_AVAILABLE else 'Missing'}",
            f"pyvhdi (VHD/VHDX): {'Available' if VHDI_AVAILABLE else 'Missing (pip install libvhdi-python)'}",
            f"pyvmdk (VMDK)    : {'Available' if VMDK_AVAILABLE else 'Missing (pip install libvmdk-python)'}",
            f"pywin32 (WinTime): {'Available' if PYWIN32_AVAILABLE else 'Missing'}",
            f"zoneinfo (IANA)  : {'Available' if ZONEINFO_AVAILABLE and available_timezones() else 'Fallback fixed UTC offsets, NO DST (pip install tzdata)'}",
        ]
        QMessageBox.information(self, "Forensic Dependency Status", "\n".join(status_lines))

    def action_show_about(self):
        QMessageBox.about(
            self,
            f"About VSCExplorer v{APP_VERSION}",
            f"VSCExplorer v{APP_VERSION}\n\n"
            "High-Performance Volume Shadow Copy & BitLocker Forensic Explorer.\n"
            "• Persistent SQLite3 WAL Disk Cache (~/.vscexplorer/index_cache/)\n"
            "• 1-to-1 Partition Slot Indexing & TSK Meta Filtering\n"
            "• Custom Python 64-Bit & Tuple SortFilterProxyModel\n"
            "• 64-Bit Virtual Hex Viewer, Collision-Safe Export & BitLocker Inspector",
        )

    def _hide_progress_bar_if_idle(self):
        if (
            self._current_export_worker is None
            and self._image_hash_worker is None
            and self._current_open_worker is None
        ):
            self.progress_bar.setVisible(False)

    def _on_worker_error(self, message: str):
        self._hide_progress_bar_if_idle()
        self.status_label.setText(f"⚠️ {message}")
        self._show_message("warning", "Operation Error", message)

    def closeEvent(self, event):
        self._teardown_active_session()
        super().closeEvent(event)


def main():
    if "--self-test" in sys.argv:
        # Redirected Windows consoles may use cp1252 instead of UTF-8. Keep the
        # report and its exit status usable even when badges cannot be encoded.
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="backslashreplace")
        passed, report = run_automated_self_tests()
        print(f"\n=== VSCExplorer v{APP_VERSION} Automated Self-Test Report ===")
        print(report)
        sys.exit(0 if passed else 1)

    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    window = VSCExplorerMainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
