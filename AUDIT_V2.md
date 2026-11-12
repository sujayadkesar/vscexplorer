# VSCExplorer v2 audit — 2026-11-06

Latest verification: 2026-11-12 (publishing review).

## Publishing review — 2026-11-12

Status: suitable for publishing as a preview PR; real forensic-image validation
is still required before treating this as a validated production release.

The initial run had 52/54 regression tests passing and 18/18 self-tests passing.
The physical-device implementation had regressed: alignment expanded a read
beyond the media boundary. Both alignment attempts now cap at media size; tests
cover the final sector and the 512-byte fallback after an alignment error.
Nonfinite numeric timestamps also raised during integer conversion; NaN and
infinities now return unknown, with a regression test.

The other baseline failure was a stale search assertion. ADS-enabled search
correctly returns the matching host plus its two streams. The test now checks
their exact names and verifies that disabling ADS returns only the host.

Final local validation on Windows/Python 3.12/PySide6: **56/56 regression tests,
18/18 self-tests, compilation and Ruff undefined-name/syntax checks passed**.
Added a Windows CI workflow, a separate v2 GUI requirements file and preview
setup instructions. Native-library and real-image limitations below still apply.
The historical audit sections below describe earlier verification rounds.

Audited and updated `vscexplorer_v2.py`. Validation used Windows, Python 3.12.10,
PySide6/Qt6, temporary synthetic raw images, the built-in demo case, and mocks
for native-library failure paths. No user evidence or physical drives were opened.

## Architecture

The single-file application separates media backends from `ForensicSession`,
which owns image access, filesystem mounts, partition/snapshot metadata, locks,
and directory caches. `SnapshotIndexDB` persists listings in SQLite WAL and
supports search and snapshot comparison. Qt workers perform navigation,
indexing, previews, exports, hashing, history, and report preparation. Table
models and the main window present those results; request IDs/session tokens
reject outdated results. `CaseStore` persists bookmarks, case notes, and audit
records separately from the disposable index. PDF rendering runs through Qt.

## Bugs fixed

1. **Export silently omitted selected folders.** A shared ancestor/visited-inode
   set caused a folder to be skipped when another selected item was beneath it.
   Export now tracks ancestors per root and traversal branch, retaining cycle
   protection and exporting each explicit selection.
2. **History could claim removal after a directory read error.** Such rows now
   say `Unknown (unreadable)` rather than `Not present`.
3. **One hash read error discarded all version history.** Errors now remain on
   their individual rows, allowing the remaining snapshots to be processed.
4. **History compared across an unreadable/unhashed version.** It no longer
   carries an older hash forward and labels a later version unchanged against it.
5. **Delayed metadata repopulated a cleared selection.** Preview request IDs are
   invalidated on clearing, navigation, and inspector option changes.
6. **Reveal/open-result cleared the selected hex preview.** Inspector clearing
   now happens before restoring the requested selection.
7. **Container initialization leaked handles on failure.** EWF, VHD/VHDX and
   VMDK constructors now close acquired handles when opening, opening extents,
   or obtaining media size fails.
8. **Physical reads could extend past the last sector.** Alignment expansion is
   capped at actual media size, including devices not divisible by 4096 bytes.
9. **Go-to/search targets could remain offscreen in huge files.** The hex viewer
   now retains the exact target row despite the scaled integer scrollbar.
10. **Concurrency self-test could pass despite thread exceptions.** Exceptions
    are now collected as test failures.

## Validation results

- Original built-in suite: **18/18 passed** after changes.
- Expanded `unittest` suite: **54/54 passed** after the fifth audit.
- Python compilation: passed for the application and new tests.
- The first 16 new tests were also run against a saved copy of the original
  source: they exposed **10 failing assertions/subtests**, confirming the
  regressions. The later large-file go-to test separately failed before its fix.

| Feature | Validation performed |
| --- | --- |
| Raw and split raw media | Actual temporary files, cross-segment reads, EOF, whole-image SHA-256; built-in split-gap rejection |
| Partitions, snapshots, BitLocker | Demo partition alignment and correct/incorrect credentials; real native integration untested |
| Browsing and inspectors | Offscreen Qt navigation, selection, reveal, cleared/stale previews, theme changes |
| Tables and dialogs | 64-bit size sorting and construction/show/close of export, timezone, search, history, bookmark, case-info, and credential dialogs |
| Cache | Existing WAL concurrency, persistence, invalidation and fingerprint tests |
| Snapshot search/diff | Existing contains/wildcard/regex/Unicode/ADS search and demo differences, partial-subtree filtering |
| Exports | Recursive and overlapping selections, cycles, collisions, ADS, exact MD5/SHA1/SHA256, modification-time preservation, partial reads and cancellation cleanup |
| Text and ADS | Existing UTF-16/BOM, stream reads and Mark-of-the-Web tests |
| Hex tools | Existing boundary search; added case-insensitive wrapped search, entropy, and huge-file go-to visibility |
| History | Existing demo chronology plus unreadable directory/hash failure/skipped-hash regressions |
| Bookmarks and reports | Existing persistence/escaping tests; actual HTML and PDF output, PDF signature and matching SHA-256 sidecars |
| Native failure cleanup | Mocked EWF/VHD/VMDK handles and physical-device read boundaries |

## Limits and remaining integration validation

This is not certification that every feature works on real forensic media.
`pytsk3`, `pyewf`, `pyvshadow`, `pybde`, `pyvhdi`, `pyvmdk`, and `pywin32` are
absent in this environment, and the workspace has no forensic image fixtures.
Real partition/filesystem parsing, VSS discovery, BitLocker decryption,
E01/VHD/VHDX/VMDK reading and parent chains, physical-drive permissions and I/O,
and Windows creation-time preservation therefore remain unverified. Native
mock tests establish control flow only. PyQt5 compatibility and interactive
desktop appearance were not tested; GUI tests used Qt6's offscreen platform.

To finish integration validation, run against known-answer images in an
environment containing the native dependencies, compare file/ADS/image hashes
to acquisition records, and verify snapshot contents and decryption results.

## Second audit

The second pass focused on case/partition changes, delayed worker results, and
ADS search/export boundaries. Six added regression tests failed before these
fixes and passed afterward:

1. **Old export completions could contaminate a newly opened case's log.**
   Export completion, error, status, and progress callbacks now check both
   worker identity and session identity. Teardown clears the old export context.
2. **History dialogs could act on a replacement image.** Reveal/export now
   reject actions when the dialog's original session is no longer open.
3. **History export/reveal could use the currently selected partition instead
   of the original partition.** Dialogs retain their source partition and
   activate it before acting; each export item explicitly retains its snapshot.
4. **ADS deduplication could omit a selected stream from another snapshot.**
   The duplicate key now includes snapshot identity as well as host path/inode.
5. **ADS search limits reported completeness incorrectly.** Search now checks
   for an actual extra matching result: omitted ADS matches produce a truncation
   warning, while exactly-full result sets do not.
6. **Root/snapshot navigation resets still accepted old metadata previews.**
   They now invalidate preview requests immediately and cancel active hex tasks.

A seventh added test exercises an actual Qt background export and verifies the
current case's success count and manifest hash. Final validation: **24 unittest
tests, 18 built-in self-tests, and compilation all passed**. The native image
integration limitations above remain unchanged.

## Third audit

Six new regression tests reproduced failures before these fixes:

1. **Exports could overwrite files created after export planning.** Output
   files now use exclusive creation. A collision is recorded as a failed item
   while preserving the existing file. Manifests also use exclusive creation;
   a manifest collision reports an export error without overwriting it.
2. **Hex search reported absence after unexpected EOF.** An incomplete read now
   reports search failure, rather than claiming the pattern was not found.
   Legitimate short reads remain supported, and aborted searches emit no result.
3. **Unreadable content suppressed otherwise available metadata.** The metadata
   panel now retains names, timestamps, allocation and stream information while
   marking the text preview unreadable with its error.
4. **Aborted sessions still served cached directories and demo file bytes.**
   Directory reads now reject an abort before looking in caches, and file reads
   return no data after an abort, including after acquiring the filesystem lock.
5. **Aborted indexing could mark a snapshot complete.** Index and diff workers
   now check the session abort state as well as their individual cancellation
   events, including before marking the index complete or emitting completion.
6. **Sliced streams silently clamped seeks at EOF.** Seeking beyond EOF now
   preserves the requested position, so a later relative seek addresses the
   right bytes. Negative positions and invalid seek origins raise errors.

Three additional tests cover short-read search, cancellation during an index
crawl, and a manifest collision. Final validation: **33 unittest tests,
18 built-in self-tests, and compilation passed**. Native forensic library
integration, including their use of the stream adapter, remains unverified
without the dependencies and image fixtures described above.

## Fourth audit

Seven new regression tests failed before these changes and passed afterward:

1. **A comparison from the previous partition could populate the new
   partition's diff table.** Partition changes cancel the comparison and clear
   its identity; callbacks also check the originating partition.
2. **Selecting identical snapshots did not cancel an earlier comparison.**
   The earlier result could replace the displayed zero-difference result.
   Existing comparisons are now cancelled before handling the identical case.
3. **A superseded image-open error could interfere with the newer request.**
   Starting another open now cancels the previous worker, and error/status/
   progress callbacks check both worker and request identity.
4. **An old hex-search result could replace a newer search on the same file.**
   Search and entropy workers now have separate signal objects and callbacks
   bound to worker identity, in addition to the existing file-generation check.
   This also rejects results queued before cancellation.
5. **Show in Folder could fail to reveal an ADS stream hidden by display
   settings or filters.** Explicit reveal clears the filename filter and enables
   ADS rows when the requested entry is a stream.
6. **An unavailable snapshot silently fell back to the currently open one.**
   Reveal now reports the unavailable snapshot and does not navigate elsewhere.
7. **Reveal selected the first matching path, potentially a different inode.**
   Pending selections now retain and match path, inode, and deletion state.
   Pending selections are cleared on session/partition replacement.

Three additional tests verify real Qt background search/entropy/comparison
completion and rejection of a cancelled entropy result. Final validation:
**43 unittest tests, 18 built-in self-tests, and compilation passed**. Native
forensic-image and physical-drive integration remains unverified as noted above.

## Fifth audit — completed 2026-11-08

This pass addressed cache initialization and search failure paths:

1. **Operational database errors could delete a valid cache.** A simulated
   disk-full error reproduced deletion of an existing database. Rebuilding is
   now restricted to SQLite's corruption/not-a-database error codes; disk-full,
   locked, permission and I/O errors preserve the cache and propagate the error.
2. **Failed initialization leaked SQLite connections.** Connections now close
   when PRAGMA setup or schema initialization fails, including a failed retry.
3. **Wildcard matching missed Unicode filenames containing newlines.** The
   Python wildcard matcher now allows wildcards across newlines and requires
   a true full-string match, consistently with its SQL counterpart for these cases.
4. **Invalid or empty searches left previous requests active.** Every new search
   attempt now invalidates pending results and clears the previous result table.
5. **An old search error could replace the newer search status.** Error callbacks
   now check request and session identity.
6. **A superseded index completion could clear the current indexing worker.**
   Index completion/status/error callbacks now check worker and session identity.
7. **CLI self-tests crashed under a legacy Windows output encoding.** The test
   report now escapes unencodable characters, preserving PASS/FAIL text and the
   correct exit status. A subprocess test explicitly uses `cp1252:strict`.

The initial six new regression tests reproduced failures before their fixes;
the CLI encoding failure was also reproduced separately before its fix.
Additional tests verify actual corrupt-cache rebuilding and persistence, cleanup
after a failed rebuild, rejection of superseded indexing callbacks, and a real
Qt background index-then-search operation.

Final validation: **54 unittest tests, 18 built-in self-tests, and compilation
passed**. These are tested behavior checks, not a claim that all possible bugs
have been eliminated. Native-image integration limitations remain as above.

## Repeat the tests

```powershell
python vscexplorer_v2.py --self-test
python -m unittest -v test_vscexplorer_v2
python -m py_compile vscexplorer_v2.py test_vscexplorer_v2.py
```

The new test suite sets `QT_QPA_PLATFORM=offscreen` unless already configured,
uses temporary output directories, and closes demo sessions after each test.
