<div align="center">
  <h1>🧭 Volume Shadow Copy Explorer (VSCExplorer)</h1>
  <h3>Explore Volume Shadow Copies (VSCs) from E01 and RAW Forensic Images including BitLocker Images</h3>

  <p>
    <img src="https://img.shields.io/badge/forensics-VSC%20Analysis-blue?style=flat-square" />
    <img src="https://img.shields.io/github/license/sujayadkesar/vscexplorer?style=flat-square" />
    <img src="https://img.shields.io/github/stars/sujayadkesar/vscexplorer?style=flat-square" />
    <img src="https://img.shields.io/github/issues/sujayadkesar/vscexplorer?style=flat-square" />
    <img src="https://img.shields.io/github/languages/top/sujayadkesar/vscexplorer?style=flat-square" />
  </p>
</div>

---
![image](https://github.com/user-attachments/assets/4526c086-55f1-4ebf-9657-2aea4523158e)
## 🧠 What is VSCExplorer?

**VSCExplorer** is a professional-grade forensic analysis tool that automates the discovery and exploration of **Volume Shadow Copies (VSCs)** from `.E01` or `dd` disk images. Built with forensic professionals and cybercrime investigators in mind, this tool provides a clean and intuitive Qt-based GUI to:

- 🔍 Detect all available Volume Shadow Snapshots within an image
- 📂 Mount and browse each VSC independently
- 🕰️ Recover deleted or historical files with timestamp preservation
- 📊 Perform timeline and artifact analysis over time-based snapshots
- 💾 Export evidence while maintaining forensic integrity
- `Supports Even Bitlocker Encrypted Images`

## ⭐ Preview of the Tool 
### Main Dashboard
<img width="1392" height="609" alt="Screenshot 2025-08-20 012847" src="https://github.com/user-attachments/assets/07efe236-6e8e-46c5-b177-5f119f3179aa" />
<br><br>

### Bitlocker Decryption and Export UI 
<img width="754" height="521" alt="Screenshot 2025-08-20 085119" src="https://github.com/user-attachments/assets/6ebcfe8f-65ef-484a-9814-2133f713f442" />


## 🚀 Features

### Core Functionality

- 🔍 **VSC Detection & Enumeration even for BitLocker Encrypted Images**
  - Automatic discovery of all available Volume Shadow Snapshots
  - Detailed metadata extraction (creation time, size, VSC ID)
  - Support for multiple VSCs within single E01 image

- 📂 **Interactive File Browser**
  - Tree-view navigation through VSC contents
  - File and folder properties display
  - Search and filter capabilities
  - Thumbnail preview for supported file types

- 💾 **Evidence Export**
  - Selective file and folder extraction
  - Maintain original timestamps and metadata
  - Generate hash verification for exported files
  - Batch export capabilities


## Installation and upgrade to v2

V2 replaces the previous application in `vscexplorer.py`. Existing launch commands
continue to work; there is no separate v2 executable.

```bash
git clone https://github.com/sujayadkesar/vscexplorer.git
cd vscexplorer
python -m pip install -r requirements.txt
python vscexplorer.py
```

The requirements install PySide6 and the native libraries for filesystem browsing,
E01, BitLocker and VSS. Native libraries may require platform build tools, including
Microsoft C++ Build Tools on Windows; availability depends on the Python/platform
combination. Python 3.12 with PySide6 is tested for the demo and regression suite;
native-image integration on that configuration remains unverified.

For the built-in demo and tests without native image libraries:

```bash
python -m pip install "PySide6>=6.6,<7"
python vscexplorer.py
```

V2 adds persistent snapshot indexing, ADS browsing/export, hex search, version
history, bookmarks and HTML/PDF case reports. PyQt5 remains a fallback if installed
instead of PySide6, but was not validated in this audit.

Real filesystem browsing requires `pytsk3`. Native backends are `pyewf` (E01),
`pyvshadow` (VSS), `pybde` (BitLocker), `pyvhdi` (VHD/VHDX), and `pyvmdk` (VMDK).
The libyal Python bindings supply these import names. The optional VHD/VMDK
bindings are not included in `requirements.txt`. Windows creation-time
preservation additionally uses `pywin32`.
Use **Help > Forensic Dependency Status** to inspect availability.

Known-answer real-image validation is still pending. Native container, VSS,
BitLocker and physical-drive integration have not been verified by the synthetic
tests.

```bash
python -m unittest -v test_vscexplorer_v2
python vscexplorer.py --self-test
```

## Acknowledgments & Credits
- [Joachim Metz](https://www.linkedin.com/in/jbmetz/)
For essential forensic libraries such as **libewf** and **libbde**.<br>
These libraries form the foundation for E01, BitLocker, and other image handling capabilities in VSCExplorer.

## 🙌 Contributors

- [Akhil Dara](https://www.linkedin.com/in/akhil-dara/) 
- [Jnana Ramakrishna](https://www.linkedin.com/in/jnana-ramakrishna/)
<br>

Additionally i want to special mention [Akhil Dara](https://www.linkedin.com/in/akhil-dara/) for the major contribution supporting `bitlocker encyrption` and  is the key diffrentiator in the volume shadow copy explorer.
