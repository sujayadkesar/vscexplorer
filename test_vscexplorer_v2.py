"""Run with python -m unittest -v test_vscexplorer_v2 (no evidence images needed)."""
import csv
import hashlib
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import vscexplorer_v2 as v


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = v.QApplication.instance() or v.QApplication([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vsc_audit_")
        self.addCleanup(self.tmp.cleanup)
        self.session = v.ForensicSession("audit", is_demo=True)
        self.addCleanup(self.session.close)

    def entry(self, name="stage2_beacon.ps1"):
        return next(e for e in self.session.list_directory_sync(0, "Live", "/Users/Analyst") if e["name"] == name)

    def drain(self, window):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.app.processEvents()
            if window.thread_pool.waitForDone(10):
                self.app.processEvents()
                if not window._active_tasks:
                    return
        self.fail("GUI workers did not finish within 10 seconds")

    def window(self):
        win = v.VSCExplorerMainWindow()
        self.addCleanup(win.close)
        win.action_load_demo_case()
        self.drain(win)
        return win

    def export(self, items, **options):
        worker = v.BufferedExportWorker(self.session, 0, "Live", items, self.tmp.name,
                                       dict(generate_csv=True, include_ads=True, **options))
        errors, done = [], []
        worker.signals.error.connect(errors.append)
        worker.signals.export_done.connect(lambda *args: done.append(args))
        worker.run()
        self.assertEqual(errors, [])
        self.assertEqual(len(done), 1)
        with open(done[0][2], encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh)), done[0]

    def test_export_overlapping_selections_keeps_parent_and_children(self):
        parent = next(e for e in self.session.list_directory_sync(0, "Live", "/Users") if e["name"] == "Analyst")
        child = next(e for e in self.session.list_directory_sync(0, "Live", parent["path"]) if e["name"] == "Documents")
        rows, _ = self.export([parent, child])
        self.assertTrue((Path(self.tmp.name) / "Analyst" / "NTUSER.DAT").is_file())
        self.assertTrue((Path(self.tmp.name) / "Analyst" / "Documents" / "incident_notes.txt").is_file())
        self.assertTrue((Path(self.tmp.name) / "Documents" / "incident_notes.txt").is_file())
        self.assertTrue(all(r["Export_Status"] == "Success" for r in rows))

    def test_export_directory_cycle_is_finite(self):
        folder = dict(name="loop", path="/loop", inode=42, is_dir=True, size=0, ads=[])
        worker = v.BufferedExportWorker(self.session, 0, "Live", [folder], self.tmp.name, {})
        with patch.object(self.session, "list_directory_sync", return_value=[folder]):
            plan = worker._collect_export_plan([folder], "Live")
        self.assertEqual(len(plan), 1)

    def test_export_ads_hashes_and_timestamp(self):
        rows, _ = self.export([self.entry()], include_hashes=True, hash_types=["md5", "sha1", "sha256"])
        self.assertEqual(len(rows), 3)
        for row in rows:
            output = Path(self.tmp.name) / row["Exported_Relative_Path"]
            data = output.read_bytes()
            self.assertEqual(len(data), int(row["Size"]))
            for algo in ("md5", "sha1", "sha256"):
                self.assertEqual(row[algo.upper() + "_Hash"], hashlib.new(algo, data).hexdigest())
            self.assertAlmostEqual(output.stat().st_mtime, self.entry()["mtime"], delta=1)

    def test_export_partial_read_is_not_success_or_verified(self):
        with patch.object(self.session, "read_file_slice", return_value=b""):
            rows, done = self.export([self.entry()], include_hashes=True, hash_types=["sha256"])
        self.assertEqual(done[0], 0)
        self.assertTrue(all(r["Export_Status"].startswith("Partial") for r in rows))
        self.assertTrue(all(r["SHA256_Hash"] == "" for r in rows))

    def test_export_cancel_removes_incomplete_file(self):
        worker = v.BufferedExportWorker(self.session, 0, "Live", [self.entry()], self.tmp.name,
                                       {"generate_csv": True, "include_ads": False})
        original = self.session.read_file_slice
        def cancel_after_read(*args):
            data = original(*args[:-1], 1)
            worker.cancel()
            return data
        with patch.object(self.session, "read_file_slice", side_effect=cancel_after_read):
            worker.run()
        self.assertFalse((Path(self.tmp.name) / self.entry()["name"]).exists())
        with open(Path(self.tmp.name) / "export_summary.csv", encoding="utf-8") as fh:
            self.assertEqual(next(csv.DictReader(fh))["Export_Status"], "Cancelled")

    def history(self, locate, hash_fn):
        worker = v.VersionHistoryWorker(self.session, 0, self.entry(), 1)
        rows, errors = [], []
        worker.signals.history_ready.connect(lambda _t, _r, result: rows.extend(result))
        worker.signals.error.connect(errors.append)
        with patch.object(v, "locate_in_snapshot", side_effect=locate), patch.object(worker, "_hash", side_effect=hash_fn):
            worker.run()
        self.assertEqual(errors, [])
        self.assertEqual(len(rows), 4)
        return rows

    def test_history_unreadable_folder_is_unknown_not_removed(self):
        e = self.entry()
        rows = self.history([e, OSError("unreadable"), e, e], [("m", "a", "")] * 3)
        self.assertEqual(rows[1]["state"], "Unknown (unreadable)")
        self.assertEqual(rows[1]["change"], "?")
        self.assertEqual(rows[2]["change"], "?")

    def test_history_hash_error_keeps_other_versions(self):
        rows = self.history([self.entry()] * 4, [("m", "a", ""), OSError("bad sector"), ("m", "a", ""), ("m", "b", "")])
        self.assertIn("bad sector", rows[1]["note"])
        self.assertEqual(rows[2]["change"], "?")
        self.assertEqual(rows[3]["change"], "CHANGED")

    def test_history_skipped_hash_does_not_compare_to_old_version(self):
        rows = self.history([self.entry()] * 4, [("m", "a", ""), ("", "", "too large"), ("m", "a", ""), ("m", "a", "")])
        self.assertEqual(rows[2]["change"], "?")
        self.assertEqual(rows[3]["change"], "unchanged")

    def test_gui_navigation_selection_and_stale_preview(self):
        win = self.window()
        win.act_opt_hex.setChecked(True)
        win.act_opt_meta.setChecked(True)
        win._on_feature_options_toggled()
        win.navigate_to_path("/Users/Analyst")
        self.drain(win)
        row = next(i for i, e in enumerate(win.table_model.get_entries()) if e["name"] == "stage2_beacon.ps1")
        win.file_table.selectRow(win.proxy_model.mapFromSource(win.table_model.index(row, 0)).row())
        self.drain(win)
        self.assertIsNotNone(win.hex_viewer.bound_entry)
        self.assertTrue(win.text_preview.toPlainText())
        old_request = win._preview_request_id
        win.file_table.clearSelection()
        win._on_metadata_ready(win.session.session_token, old_request, "stale result")
        self.assertEqual(win.text_preview.toPlainText(), "")
        self.assertIsNone(win.hex_viewer.bound_entry)
        win.action_navigate_up()
        self.drain(win)
        self.assertEqual(win.current_path, "/Users")

    def test_gui_reveal_keeps_selected_hex_preview(self):
        win = self.window()
        win.act_opt_hex.setChecked(True)
        win._on_feature_options_toggled()
        e = dict(self.entry(), source_snap="Live")
        win.reveal_entry(e)
        self.drain(win)
        self.assertIsNotNone(win.hex_viewer.bound_entry)
        self.assertEqual(win.hex_viewer.bound_entry["path"], e["path"])

    def test_gui_themes_dialogs_and_sorting(self):
        win = self.window()
        for dark in (True, False):
            win.apply_theme(dark)
        dialogs = [v.ExportOptionsDialog(win), v.TimeZoneSelectDialog("UTC", win),
                   v.SnapshotSearchDialog(win), v.VersionHistoryDialog(win, self.entry()),
                   v.BookmarkEditDialog(win, [], 1), v.CaseInfoDialog(win, {}), v.BookmarksDialog(win),
                   v.BitLockerCredentialsDialog(win.session.partitions[1].bitlocker_info, win)]
        for dialog in dialogs:
            dialog.show()
            self.app.processEvents()
            dialog.close()
        model = v.ForensicFileSystemTableModel()
        proxy = v.ForensicSortFilterProxyModel()
        proxy.setSourceModel(model)
        model.set_entries([dict(self.entry(), name="huge", size=2**45), dict(self.entry(), name="small", size=3)])
        size_column = next(i for i in range(model.columnCount()) if "Size" in str(model.headerData(i, v.ORIENT_HORIZONTAL)))
        proxy.sort(size_column, v.SORT_ASCENDING)
        self.assertEqual(proxy.index(0, 0).data(v.ROLE_USER)["name"], "small")

    def test_pdf_html_and_sidecar_reports(self):
        store = v.CaseStore.for_session(self.session)
        self.addCleanup(store.close)
        store.upsert_bookmark(0, "Live", self.entry(), "test", "<script>bad</script>")
        worker = v.CaseReportWorker(self.session, store)
        results = []
        worker.signals.report_ready.connect(lambda _token, data: results.append(data))
        worker.run()
        written = v.write_case_report(self.session, results[0], str(Path(self.tmp.name) / "report.html"))
        self.assertEqual(len(written), 2)
        for path, digest in written:
            self.assertEqual(v.file_sha256(path), digest)
            self.assertTrue(Path(path + ".sha256").read_text().startswith(digest))
        self.assertTrue((Path(self.tmp.name) / "report.pdf").read_bytes().startswith(b"%PDF"))
        self.assertNotIn("<script>bad", (Path(self.tmp.name) / "report.html").read_text(encoding="utf-8"))

    def test_raw_split_reads_and_image_hashes(self):
        data = bytes(range(256)) * 20
        paths = []
        for i, part in enumerate((data[:700], data[700:4000], data[4000:]), 1):
            path = Path(self.tmp.name) / f"disk.{i:03d}"
            path.write_bytes(part)
            paths.append(str(path))
        backend = v.open_media_backend(paths[1])
        self.addCleanup(backend.close)
        for offset, size in ((0, 5120), (699, 4), (3999, 512), (5119, 10), (6000, 10)):
            self.assertEqual(backend.read(offset, size), data[offset:offset + size])
        session = SimpleNamespace(session_token=1, media_size=len(data), media=backend,
                                  is_aborting=False, read_raw=backend.read)
        worker = v.ImageHashWorker(session)
        results = []
        worker.signals.image_hash_ready.connect(lambda _t, r: results.append(r))
        worker.run()
        self.assertEqual(results[0]["sha256"], hashlib.sha256(data).hexdigest())
        raw_path = Path(self.tmp.name) / "disk.raw"
        raw_path.write_bytes(data)
        raw = v.open_media_backend(str(raw_path))
        self.addCleanup(raw.close)
        self.assertEqual(raw.read(200, 700), data[200:900])

    def test_container_failure_closes_native_handle(self):
        for backend, module, flag, factory, failure in (
            (v.EwfBackend, "pyewf", "EWF_AVAILABLE", "handle", "get_media_size"),
            (v.VhdiBackend, "pyvhdi", "VHDI_AVAILABLE", "file", "open"),
            (v.VmdkBackend, "pyvmdk", "VMDK_AVAILABLE", "handle", "open_extent_data_files"),
        ):
            with self.subTest(backend=backend.__name__):
                handle = Mock()
                getattr(handle, failure).side_effect = OSError("failure")
                fake = SimpleNamespace(**{factory: lambda: handle})
                with patch.object(v, module, fake), patch.object(v, flag, True):
                    with self.assertRaises(OSError):
                        backend("image")
                handle.close.assert_called_once()

    def test_device_last_sector_does_not_read_beyond_media(self):
        device = object.__new__(v.PhysicalDeviceBackend)
        device._fd, device.media_size = 123, 4608
        with patch.object(v.os, "lseek"), patch.object(v.os, "read", return_value=b"x" * 512) as read:
            self.assertEqual(device.read(4500, 108), b"x" * 108)
        read.assert_called_once_with(123, 512)

    def test_raw_backends_close_handles_when_size_probe_fails(self):
        for backend, argument in ((v.RawFileBackend, "image.raw"),
                                  (v.SplitRawBackend, ["image.001"])):
            for operation in ("seek", "tell"):
                with self.subTest(backend=backend.__name__, operation=operation):
                    handle = Mock()
                    getattr(handle, operation).side_effect = OSError("size probe failed")
                    with patch("builtins.open", return_value=handle):
                        with self.assertRaises(OSError):
                            backend(argument)
                    handle.close.assert_called_once()

    def test_device_alignment_fallback_stays_within_media(self):
        device = object.__new__(v.PhysicalDeviceBackend)
        device._fd, device.media_size = 123, 4608
        with patch.object(v.os, "lseek") as seek, patch.object(
            v.os, "read", side_effect=[OSError("alignment"), b"x" * 512]
        ) as read:
            self.assertEqual(device.read(4500, 1000), b"x" * 108)
        self.assertEqual([c.args for c in read.call_args_list], [(123, 512), (123, 512)])
        self.assertTrue(all(c.args[1] == 4096 for c in seek.call_args_list))

    def test_nonfinite_timestamps_are_unknown(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                self.assertIsNone(v.coerce_forensic_epoch(value))

    def test_hex_search_wrap_and_entropy(self):
        data = b"prefix" + bytes(range(256)) * 256
        session = SimpleNamespace(is_aborting=False, read_file_slice=lambda _p, _s, _e, off, n: data[off:off+n])
        sig = v._HexToolSignals()
        hits, entropy = [], []
        sig.search_done.connect(lambda _g, offset, _m: hits.append(offset))
        sig.entropy_done.connect(lambda _g, report: entropy.append(report))
        e = {"size": len(data)}
        v.HexSearchWorker(session, 0, "Live", e, b"PREFIX", 50, True, 0, sig).run()
        v.FileEntropyWorker(session, 0, "Live", e, 0, sig).run()
        self.assertEqual(hits, [0])
        self.assertIn("8.000", entropy[0])

    def test_search_ads_limit_reports_actual_omissions(self):
        db = self.session.index_db
        host = dict(self.entry(), name="hit", path="/hit", ads=[{"name": "hit", "size": 1, "id": 1}])
        db.insert_directory_batch(0, "limit", "/", [host])
        rows, truncated = db.search_entries(0, ["limit"], "hit", include_ads=True, limit=1)
        self.assertEqual(len(rows), 1)
        self.assertTrue(truncated, "Matching ADS was omitted without warning")
        rows, truncated = db.search_entries(0, ["limit"], "hit", include_ads=True, limit=2)
        self.assertEqual(len(rows), 2)
        self.assertFalse(truncated, "Exactly full results are not truncated")

    def test_export_ads_dedup_keeps_other_snapshot(self):
        win = self.window()
        host = dict(self.entry(), source_snap="Live")
        stream = dict(v.make_ads_entry(host, v.ads_streams(host)[0]), source_snap="VSS_2")
        options = SimpleNamespace(exec=lambda: v.DLG_ACCEPTED, generate_csv=True,
                                  include_hashes=False, hash_types=[], include_ads=True)
        with patch.object(v, "ExportOptionsDialog", return_value=options), \
             patch.object(v.QFileDialog, "getExistingDirectory", return_value=self.tmp.name), \
             patch.object(win, "_start_task"):
            win._launch_export([host, stream])
        self.assertEqual(len(win._current_export_worker.root_items), 2)

    def test_export_old_session_callback_does_not_touch_new_case(self):
        win = self.window()
        options = SimpleNamespace(exec=lambda: v.DLG_ACCEPTED, generate_csv=True,
                                  include_hashes=False, hash_types=[], include_ads=False)
        with patch.object(v, "ExportOptionsDialog", return_value=options), \
             patch.object(v.QFileDialog, "getExistingDirectory", return_value=self.tmp.name), \
             patch.object(win, "_start_task"):
            win._launch_export([self.entry()])
        old_worker = win._current_export_worker
        win.action_load_demo_case()
        self.drain(win)
        status = win.status_label.text()
        with patch.object(win, "_show_message"):
            old_worker.signals.export_done.emit(1, 1, "old_manifest.csv", False)
            old_worker.signals.error.emit("old error")
            old_worker.signals.status.emit("old progress")
        self.assertEqual(win.case_store.list_exports(), [])
        self.assertEqual(win.status_label.text(), status)

    def test_gui_export_worker_records_current_case(self):
        win = self.window()
        options = SimpleNamespace(exec=lambda: v.DLG_ACCEPTED, generate_csv=True,
                                  include_hashes=True, hash_types=["sha256"], include_ads=True)
        with patch.object(v, "ExportOptionsDialog", return_value=options), \
             patch.object(v.QFileDialog, "getExistingDirectory", return_value=self.tmp.name), \
             patch.object(win, "_show_message"):
            win._launch_export([self.entry()])
            self.drain(win)
        records = win.case_store.list_exports()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["items_success"], 3)
        self.assertEqual(records[0]["manifest_sha256"], v.file_sha256(records[0]["manifest_path"]))
        self.assertIsNone(win._current_export_worker)

    def test_history_dialog_rejects_replaced_session(self):
        win = self.window()
        dlg = v.VersionHistoryDialog(win, self.entry())
        self.addCleanup(dlg.close)
        dlg.rows = [{"entry": self.entry(), "snap_id": "Live"}]
        win.action_load_demo_case()
        self.drain(win)
        with patch.object(win, "_launch_export") as export, patch.object(win, "_show_message"):
            dlg.action_export_all()
        export.assert_not_called()
        with patch.object(win, "reveal_entry") as reveal, patch.object(win, "_show_message"):
            dlg._show_row(0)
        reveal.assert_not_called()

    def test_history_dialog_uses_original_partition(self):
        win = self.window()
        dlg = v.VersionHistoryDialog(win, self.entry())
        self.addCleanup(dlg.close)
        dlg.rows = [{"entry": self.entry(), "snap_id": "Live"}]
        win.combo_partition.setCurrentIndex(1)
        with patch.object(win, "_launch_export") as export:
            dlg.action_export_all()
        self.assertEqual(win.current_part_idx, 0)
        export.assert_called_once()
        self.assertEqual(export.call_args.args[0][0]["source_snap"], "Live")
        self.drain(win)

    def test_reset_navigation_invalidates_preview(self):
        win = self.window()
        win.opt_enable_metadata = True
        old_request = win._preview_request_id
        win._reset_and_load_root()
        win._on_metadata_ready(win.session.session_token, old_request, "old snapshot")
        self.assertEqual(win.text_preview.toPlainText(), "")
        self.drain(win)

    def test_hex_search_unexpected_eof_is_not_no_match(self):
        session = SimpleNamespace(is_aborting=False, read_file_slice=lambda *args: b"")
        sig = v._HexToolSignals()
        results = []
        sig.search_done.connect(lambda _g, off, msg: results.append(msg))
        v.HexSearchWorker(session, 0, "Live", {"size": 100}, b"needle", 0, False, 0, sig).run()
        self.assertIn("Search failed", results[0])
        self.assertIn("EOF", results[0])

    def test_hex_search_accepts_short_reads_and_suppresses_abort_result(self):
        data = b"abcneedlexyz"
        session = SimpleNamespace(is_aborting=False,
                                  read_file_slice=lambda _p, _s, _e, off, n: data[off:off + min(n, 2)])
        sig = v._HexToolSignals()
        results = []
        sig.search_done.connect(lambda _g, off, msg: results.append(off))
        v.HexSearchWorker(session, 0, "Live", {"size": len(data)}, b"needle", 0, False, 0, sig).run()
        self.assertEqual(results, [3])
        session.is_aborting = True
        v.HexSearchWorker(session, 0, "Live", {"size": len(data)}, b"needle", 0, False, 0, sig).run()
        self.assertEqual(results, [3])

    def test_metadata_survives_unreadable_content(self):
        worker = v.MetadataPreviewWorker(self.session, 0, "Live", self.entry(), v.datetime.timezone.utc, "UTC")
        results = []
        worker.signals.metadata_ready.connect(lambda _t, _r, report: results.append(report))
        with patch.object(self.session, "read_file_slice", side_effect=OSError("bad sector")):
            worker.run()
        self.assertEqual(len(results), 1)
        self.assertIn(self.entry()["name"], results[0])
        self.assertIn("bad sector", results[0])

    def test_aborted_session_does_not_serve_cached_directory_or_file(self):
        entry = self.entry()
        self.session.request_abort()
        self.assertEqual(self.session.read_file_slice(0, "Live", entry, 0, 10), b"")
        with self.assertRaises(RuntimeError):
            self.session.list_directory_sync(0, "Live", "/Users/Analyst")

    def test_aborted_index_worker_does_not_mark_snapshot_complete(self):
        self.session.index_db.clear_all()
        self.session.request_abort()
        worker = v.SnapshotIndexWorker(self.session, 0, ["Live"])
        worker.run()
        self.assertFalse(self.session.index_db.is_snapshot_fully_indexed(0, "Live"))

    def test_index_abort_mid_crawl_does_not_emit_completion(self):
        self.session.index_db.clear_all()
        worker = v.SnapshotIndexWorker(self.session, 0, ["Live"])
        completed = []
        worker.signals.indexed.connect(lambda *args: completed.append(args))
        listing = self.session.list_directory_sync
        def abort_after_listing(*args, **kwargs):
            result = listing(*args, **kwargs)
            self.session.request_abort()
            return result
        with patch.object(self.session, "list_directory_sync", side_effect=abort_after_listing):
            worker.run()
        self.assertEqual(completed, [])
        self.assertFalse(self.session.index_db.is_snapshot_fully_indexed(0, "Live"))

    def test_sliced_stream_seek_matches_file_semantics(self):
        import io
        content = b"abcdef"
        stream = v.SlicedStreamAdapter(lambda off, size: content[off:off+size], 1, 3)
        reference = io.BytesIO(content[1:4])
        self.assertEqual(stream.seek(10), reference.seek(10))
        self.assertEqual(stream.read(), reference.read())
        self.assertEqual(stream.tell(), reference.tell())
        self.assertEqual(stream.seek(-9, os.SEEK_CUR), reference.seek(-9, os.SEEK_CUR))
        self.assertEqual(stream.read(), reference.read())
        with self.assertRaises(ValueError):
            stream.seek(-1)
        with self.assertRaises(ValueError):
            stream.seek(0, 99)

    def test_export_does_not_overwrite_file_created_after_planning(self):
        entry = self.entry()
        worker = v.BufferedExportWorker(self.session, 0, "Live", [entry], self.tmp.name,
                                       {"generate_csv": True, "include_ads": False})
        collect = worker._collect_export_plan
        target = Path(self.tmp.name) / entry["name"]
        def race(*args):
            result = collect(*args)
            target.write_bytes(b"existing evidence")
            return result
        with patch.object(worker, "_collect_export_plan", side_effect=race):
            worker.run()
        self.assertEqual(target.read_bytes(), b"existing evidence")
        with open(Path(self.tmp.name) / "export_summary.csv", encoding="utf-8") as fh:
            self.assertEqual(next(csv.DictReader(fh))["Export_Status"], "Failed")

    def test_export_manifest_race_preserves_existing_manifest(self):
        worker = v.BufferedExportWorker(self.session, 0, "Live", [self.entry()], self.tmp.name,
                                       {"generate_csv": True, "include_ads": False})
        collect = worker._collect_export_plan
        target = Path(self.tmp.name) / "export_summary.csv"
        errors = []
        worker.signals.error.connect(errors.append)
        def race(*args):
            result = collect(*args)
            target.write_bytes(b"existing manifest")
            return result
        with patch.object(worker, "_collect_export_plan", side_effect=race), self.assertLogs(v.logger, level="ERROR"):
            worker.run()
        self.assertEqual(target.read_bytes(), b"existing manifest")
        self.assertEqual(len(errors), 1)

    def test_diff_result_rejected_after_partition_switch(self):
        win = self.window()
        win.opt_enable_diff = True
        with patch.object(win, "_start_task"):
            win.action_run_diff()
        worker = win._current_diff_worker
        win.combo_partition.setCurrentIndex(1)
        worker.signals.diff_ready.emit(win.session.session_token, [dict(self.entry(), delta="CREATED")])
        self.assertEqual(win.diff_model.rowCount(), 0)
        self.assertTrue(worker.cancel_event.is_set())

    def test_identical_diff_cancels_previous_comparison(self):
        win = self.window()
        win.opt_enable_diff = True
        with patch.object(win, "_start_task"):
            win.action_run_diff()
            worker = win._current_diff_worker
            win.combo_diff_a.setCurrentIndex(win.combo_diff_b.currentIndex())
            win.action_run_diff()
        worker.signals.diff_ready.emit(win.session.session_token, [dict(self.entry(), delta="CREATED")])
        self.assertEqual(win.diff_model.rowCount(), 0)
        self.assertTrue(worker.cancel_event.is_set())

    def test_superseded_image_open_error_is_ignored(self):
        win = self.window()
        with patch.object(win, "_start_task"):
            win._start_image_open("first.raw")
            old = win._current_open_worker
            win._start_image_open("second.raw")
            current = win._current_open_worker
        with patch.object(win, "_show_message") as message:
            old.signals.error.emit("old error")
            old.signals.status.emit("old progress")
        self.assertIs(win._current_open_worker, current)
        self.assertTrue(old._cancelled.is_set())
        self.assertIn("second.raw", win.status_label.text())
        message.assert_not_called()

    def test_superseded_hex_search_result_is_ignored(self):
        panel = v.HexPanel()
        self.addCleanup(panel.close)
        panel.viewer.bind_file(self.session, 0, "Live", self.entry())
        pool = Mock()
        with patch.object(v.QThreadPool, "globalInstance", return_value=pool):
            panel.find_edit.setText("41")
            panel.action_find_next()
            old = panel._search_worker
            panel.find_edit.setText("42 43")
            panel.action_find_next()
            current = panel._search_worker
        old.signals.search_done.emit(panel.viewer.generation, 100, "old match")
        self.assertIs(panel._search_worker, current)
        self.assertEqual(panel.viewer.highlight_start(), -1)
        current.signals.search_done.emit(panel.viewer.generation, 200, "new match")
        self.assertEqual(panel.viewer.highlight_start(), 200)

    def test_hex_panel_background_search_and_entropy(self):
        win = self.window()
        panel = win.hex_panel
        panel.viewer.bind_file(win.session, 0, "Live", self.entry())
        panel.find_edit.setText("3D 3D 3D")
        panel.action_find_next()
        self.drain(win)
        self.assertEqual(panel.viewer.highlight_start(), 0)
        self.assertIsNone(panel._search_worker)
        panel.action_file_entropy()
        self.drain(win)
        self.assertIn("File entropy", panel.result_label.text())
        self.assertIsNone(panel._entropy_worker)

    def test_cancelled_entropy_result_is_ignored(self):
        panel = v.HexPanel()
        self.addCleanup(panel.close)
        panel.viewer.bind_file(self.session, 0, "Live", self.entry())
        with patch.object(v.QThreadPool, "globalInstance", return_value=Mock()):
            panel.action_file_entropy()
        worker = panel._entropy_worker
        panel.cancel_tasks()
        worker.signals.entropy_done.emit(panel.viewer.generation, "old entropy")
        self.assertEqual(panel.result_label.text(), "")

    def test_gui_background_diff_still_displays_current_results(self):
        win = self.window()
        win.opt_enable_diff = True
        win.action_run_diff()
        self.drain(win)
        self.assertGreater(win.diff_model.rowCount(), 0)
        self.assertIsNone(win._current_diff_worker)
        self.assertIsNotNone(win._shown_diff_worker)

    def test_reveal_stream_enables_rows_and_clears_filter(self):
        win = self.window()
        win.act_show_ads_rows.setChecked(False)
        win.edit_filter.setText("no-such-file")
        stream = v.make_ads_entry(self.entry(), v.ads_streams(self.entry())[0])
        win.reveal_entry(stream)
        self.drain(win)
        selected = win._selected_table_entries()
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["path"], stream["path"])

    def test_reveal_rejects_unavailable_snapshot(self):
        win = self.window()
        with patch.object(win, "navigate_to_path") as navigate, patch.object(win, "_show_message"):
            win.reveal_entry(dict(self.entry(), source_snap="missing"))
        navigate.assert_not_called()

    def test_reveal_selects_inode_not_just_path(self):
        win = self.window()
        original = dict(self.entry(), is_deleted=False)
        deleted = dict(original, inode=9999, is_deleted=True)
        win.session._remember_directory((0, "Live", "/Users/Analyst"), [original, deleted])
        win.reveal_entry(deleted)
        self.drain(win)
        self.assertEqual(win._selected_table_entries()[0]["inode"], 9999)

    def test_cache_operational_failure_preserves_existing_database(self):
        path = Path(self.tmp.name) / "index.sqlite"
        with v.sqlite3.connect(path) as conn:
            conn.execute("CREATE TABLE marker (value TEXT)")
            conn.execute("INSERT INTO marker VALUES ('keep me')")
        conn.close()
        with patch.object(v.SnapshotIndexDB, "_init_schema_and_validate",
                          side_effect=v.sqlite3.OperationalError("database or disk is full")):
            with self.assertRaises(v.sqlite3.OperationalError):
                v.SnapshotIndexDB("audit", 1, custom_db_path=str(path))
        with v.sqlite3.connect(path) as check:
            self.assertEqual(check.execute("SELECT value FROM marker").fetchone()[0], "keep me")
        check.close()

    def test_cache_failed_pragma_closes_connection(self):
        conn = Mock()
        conn.execute.side_effect = v.sqlite3.OperationalError("disk I/O error")
        db = object.__new__(v.SnapshotIndexDB)
        db.db_path = "unused"
        with patch.object(v.sqlite3, "connect", return_value=conn):
            with self.assertRaises(v.sqlite3.OperationalError):
                db._create_connection()
        conn.close.assert_called_once()

    def test_cache_failed_schema_closes_connection_without_retry(self):
        conn = Mock()
        with patch.object(v.SnapshotIndexDB, "_create_connection", return_value=conn) as create, \
             patch.object(v.SnapshotIndexDB, "_init_schema_and_validate",
                          side_effect=v.sqlite3.OperationalError("database is locked")):
            with self.assertRaises(v.sqlite3.OperationalError):
                v.SnapshotIndexDB("audit", 1, custom_db_path=str(Path(self.tmp.name) / "cache"))
        conn.close.assert_called_once()
        create.assert_called_once()

    def test_corrupt_cache_rebuilds_and_persists(self):
        path = Path(self.tmp.name) / "corrupt.sqlite"
        path.write_bytes(b"This is not a SQLite database" * 100)
        with self.assertLogs(v.logger, level="WARNING"):
            db = v.SnapshotIndexDB("audit", 1, is_demo=True, custom_db_path=str(path))
        try:
            db.insert_directory_batch(0, "Live", "/", [dict(self.entry(), path="/file")])
            self.assertEqual(db.get_total_indexed_entries(), 1)
        finally:
            db.close()
        reopened = v.SnapshotIndexDB("audit", 1, is_demo=True, custom_db_path=str(path))
        try:
            self.assertEqual(reopened.get_total_indexed_entries(), 1)
        finally:
            reopened.close()

    def test_cache_failed_rebuild_closes_retry_connection(self):
        first, retry = Mock(), Mock()
        corrupt = v.sqlite3.DatabaseError("database disk image is malformed")
        corrupt.sqlite_errorcode = v.sqlite3.SQLITE_CORRUPT
        with patch.object(v.SnapshotIndexDB, "_create_connection", side_effect=[first, retry]), \
             patch.object(v.SnapshotIndexDB, "_init_schema_and_validate",
                          side_effect=[corrupt, v.sqlite3.OperationalError("disk full")]), \
             self.assertLogs(v.logger, level="WARNING"):
            with self.assertRaises(v.sqlite3.OperationalError):
                v.SnapshotIndexDB("audit", 1, custom_db_path=str(Path(self.tmp.name) / "cache.sqlite"))
        first.close.assert_called_once()
        retry.close.assert_called_once()

    def test_wildcard_search_matches_newline_in_unicode_filename(self):
        entry = dict(self.entry(), name="caf\u00e9\nnotes.txt", path="/caf\u00e9\nnotes.txt", ads=[])
        self.session.index_db.insert_directory_batch(0, "wildcard", "/", [entry])
        for query in ("caf\u00e9*", "caf\u00e9?notes.txt"):
            with self.subTest(query=query):
                rows, _ = self.session.index_db.search_entries(0, ["wildcard"], query, mode="wildcard")
                self.assertEqual([r["path"] for r in rows], [entry["path"]])
        _, matcher = v.SnapshotIndexDB.build_name_matcher("caf\u00e9", "wildcard")
        self.assertFalse(matcher("caf\u00e9\n"))

    def test_invalid_search_supersedes_pending_results(self):
        win = self.window()
        dialog = v.SnapshotSearchDialog(win)
        self.addCleanup(dialog.close)
        with patch.object(win, "_start_task") as start:
            dialog.query_edit.setText("beacon")
            dialog.action_search()
            old = start.call_args.args[0]
            dialog.mode_combo.setCurrentIndex(2)
            dialog.query_edit.setText("[")
            dialog.action_search()
        old.signals.search_ready.emit(win.session.session_token, old.req_id, [self.entry()], False)
        self.assertEqual(dialog.model.rowCount(), 0)
        self.assertIn("Invalid regular expression", dialog.result_label.text())
        dialog.query_edit.clear()
        dialog.action_search()
        old.signals.search_ready.emit(win.session.session_token, old.req_id, [self.entry()], False)
        self.assertEqual(dialog.model.rowCount(), 0)
        self.assertEqual(dialog.result_label.text(), "Type a name and press Search.")

    def test_superseded_search_error_does_not_replace_new_status(self):
        win = self.window()
        dialog = v.SnapshotSearchDialog(win)
        self.addCleanup(dialog.close)
        with patch.object(win, "_start_task") as start:
            dialog.query_edit.setText("first")
            dialog.action_search()
            old = start.call_args.args[0]
            dialog.query_edit.setText("second")
            dialog.action_search()
        status = dialog.result_label.text()
        old.signals.error.emit("old error")
        self.assertEqual(dialog.result_label.text(), status)

    def test_superseded_search_index_completion_is_ignored(self):
        win = self.window()
        dialog = v.SnapshotSearchDialog(win)
        self.addCleanup(dialog.close)
        with patch.object(win, "_start_task"):
            dialog.action_index()
            old = dialog._index_worker
            dialog.action_index()
            current = dialog._index_worker
        status = dialog.result_label.text()
        old.signals.indexed.emit(win.session.session_token, "old completion")
        old.signals.status.emit("old status")
        old.signals.error.emit("old error")
        self.assertIs(dialog._index_worker, current)
        self.assertEqual(dialog.result_label.text(), status)
        current.signals.indexed.emit(win.session.session_token, "current completion")
        self.assertIsNone(dialog._index_worker)
        self.assertIn("current completion", dialog.result_label.text())

    def test_search_dialog_indexes_then_searches_in_background(self):
        win = self.window()
        dialog = v.SnapshotSearchDialog(win)
        self.addCleanup(dialog.close)
        dialog.query_edit.setText("beacon")
        dialog.action_index()
        self.drain(win)
        self.assertIsNone(dialog._index_worker)
        host = next(e for e in win.session.list_directory_sync(0, "Live", "/Users/Analyst")
                    if e["name"] == "stage2_beacon.ps1")
        expected = {host["name"], *(host["name"] + ":" + st["name"] for st in v.ads_streams(host))}
        self.assertEqual({e["name"] for e in dialog.model.rows()}, expected)
        self.assertEqual(dialog.model.rowCount(), 3)
        self.assertIn("3 result(s)", dialog.result_label.text())
        dialog.chk_ads.setChecked(False)
        dialog.action_search()
        self.drain(win)
        self.assertEqual([e["name"] for e in dialog.model.rows()], [host["name"]])

    def test_hex_goto_large_file_keeps_target_visible(self):
        viewer = v.VirtualHexViewer()
        self.addCleanup(viewer.close)
        viewer.resize(800, 300)
        viewer.bind_file(self.session, 0, "Live", dict(self.entry(), size=2**50))
        target = (viewer._scroll_scale * 100 + viewer._scroll_scale - 1) * 16
        viewer.goto_offset(target)
        self.assertLessEqual(viewer.top_offset(), target)
        self.assertLess(target, viewer.top_offset() + viewer.visible_rows() * 16)

    def test_cli_self_test_supports_legacy_console_encoding(self):
        import subprocess
        import sys
        env = dict(os.environ, PYTHONIOENCODING="cp1252:strict")
        result = subprocess.run([sys.executable, str(Path(v.__file__)), "--self-test"],
                                capture_output=True, env=env, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode("cp1252", errors="replace"))
        self.assertIn(b"PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
