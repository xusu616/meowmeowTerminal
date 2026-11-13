import ctypes
from types import SimpleNamespace
import unittest
from unittest import mock

from utils import ime_utils


class ImeIdentityTests(unittest.TestCase):
    def test_exact_candidate_classes_match(self):
        for cls in (
            "Microsoft.IME.UIManager.CandidateWindow.Host",
            "Microsoft.IME.CandidateWindow.View",
            "SoPY_Comp",
            "QQPinyinCompWndTSF",
        ):
            self.assertTrue(
                ime_utils._matches_ime_candidate_identity(cls, lambda: ""),
                msg=f"expected {cls} to match",
            )

    def test_status_bars_and_normal_windows_do_not_match(self):
        for cls in ("SoPY_Status", "IME", "MSCTFIME UI", "Notepad", "Chrome_WidgetWin_1"):
            self.assertFalse(
                ime_utils._matches_ime_candidate_identity(cls, lambda: "explorer.exe"),
                msg=f"expected {cls} not to match",
            )

    def test_modern_core_window_requires_text_input_host_process(self):
        self.assertTrue(
            ime_utils._matches_ime_candidate_identity(
                "Windows.UI.Core.CoreWindow", lambda: "TextInputHost.exe"
            )
        )
        self.assertFalse(
            ime_utils._matches_ime_candidate_identity(
                "Windows.UI.Core.CoreWindow", lambda: "SystemSettings.exe"
            )
        )

    def test_weasel_atl_window_requires_weasel_server(self):
        self.assertTrue(
            ime_utils._matches_ime_candidate_identity(
                "ATL:00007FF12345", lambda: "WeaselServer.exe"
            )
        )
        self.assertFalse(
            ime_utils._matches_ime_candidate_identity(
                "ATL:00007FF12345", lambda: "OtherApp.exe"
            )
        )


class ImeVisibilityTests(unittest.TestCase):
    def setUp(self):
        with ime_utils._discovered_lock:
            ime_utils._discovered_ime_hwnds.clear()

    def tearDown(self):
        with ime_utils._discovered_lock:
            ime_utils._discovered_ime_hwnds.clear()

    def test_rect_on_screen_filtering(self):
        self.assertTrue(ime_utils._is_rect_on_screen(100, 200, 400, 260))
        # 支持主屏左侧的副屏负坐标
        self.assertTrue(ime_utils._is_rect_on_screen(-800, 100, -500, 160))
        # 过滤 0x0 / 极小幽灵窗口与 (-32000, -32000) 最小化停靠窗口
        self.assertFalse(ime_utils._is_rect_on_screen(100, 100, 100, 100))
        self.assertFalse(ime_utils._is_rect_on_screen(100, 100, 105, 105))
        self.assertFalse(ime_utils._is_rect_on_screen(-32000, -32000, -31800, -31900))

    def _make_fake_api(self, windows, cloaked_map=None):
        cloaked_map = cloaked_map or {}

        class FakeUser32:
            def EnumWindows(self, cb, lparam):
                for hwnd, info in windows.items():
                    if info.get("parent"):
                        continue
                    if not cb(hwnd, lparam):
                        return 0
                return 1

            def EnumChildWindows(self, parent, cb, lparam):
                for hwnd, info in windows.items():
                    if info.get("parent") == parent:
                        if not cb(hwnd, lparam):
                            return 0
                return 1

            def FindWindowExW(self, parent, after, cls, title):
                seen_after = after is None
                for hwnd, info in windows.items():
                    if info.get("parent") != parent:
                        continue
                    if not seen_after:
                        if hwnd == after:
                            seen_after = True
                        continue
                    if cls is None or info["class"] == cls:
                        return hwnd
                return 0

            def IsWindow(self, hwnd):
                return 1 if hwnd in windows else 0

            def IsWindowVisible(self, hwnd):
                return 1 if windows[hwnd]["visible"] else 0

            def IsIconic(self, hwnd):
                return 1 if windows[hwnd].get("iconic") else 0

            def GetAncestor(self, hwnd, flags):
                info = windows.get(hwnd)
                if not info:
                    return 0
                return info.get("parent") or hwnd

            def GetClassNameW(self, hwnd, buf, max_len):
                cls = windows[hwnd]["class"]
                buf.value = cls[: max_len - 1]
                return len(buf.value)

            def GetWindowRect(self, hwnd, rect_ptr):
                l, t, r, b = windows[hwnd]["rect"]
                rect = ctypes.cast(rect_ptr, ctypes.POINTER(ime_utils.wintypes.RECT)).contents
                rect.left, rect.top, rect.right, rect.bottom = l, t, r, b
                return 1

            def GetWindowThreadProcessId(self, hwnd, pid_ptr):
                pid = ctypes.cast(pid_ptr, ctypes.POINTER(ime_utils.wintypes.DWORD)).contents
                pid.value = windows[hwnd]["pid"]
                return 1

        class FakeKernel32:
            def OpenProcess(self, access, inherit, pid):
                return pid

            def QueryFullProcessImageNameW(self, handle, flags, buf, size_ptr):
                for info in windows.values():
                    if info["pid"] == handle:
                        buf.value = info["path"]
                        return 1
                return 0

            def CloseHandle(self, handle):
                return 1

        class FakeDwmapi:
            def DwmGetWindowAttribute(self, hwnd, attr, val_ptr, size):
                val = ctypes.cast(val_ptr, ctypes.POINTER(ctypes.c_int)).contents
                val.value = cloaked_map.get(hwnd, 0)
                return 0

        return SimpleNamespace(
            user32=FakeUser32(),
            kernel32=FakeKernel32(),
            dwmapi=FakeDwmapi(),
            WNDENUMPROC=lambda fn: fn,
        )

    def test_cloaked_text_input_host_returns_false(self):
        fake_api = self._make_fake_api(
            windows={
                1: {
                    "visible": True,
                    "class": "Windows.UI.Core.CoreWindow",
                    "rect": (100, 100, 400, 200),
                    "pid": 10,
                    "path": r"C:\Windows\SystemApps\TextInputHost.exe",
                }
            },
            cloaked_map={1: 1},
        )
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", return_value=fake_api), \
             mock.patch.object(ime_utils, "_is_uia_ime_candidate_open", return_value=False):
            self.assertFalse(ime_utils.is_ime_candidate_open())

    def test_uncloaked_text_input_host_returns_true(self):
        fake_api = self._make_fake_api(
            windows={
                1: {
                    "visible": True,
                    "class": "Windows.UI.Core.CoreWindow",
                    "rect": (100, 100, 400, 200),
                    "pid": 10,
                    "path": r"C:\Windows\SystemApps\TextInputHost.exe",
                }
            },
            cloaked_map={1: 0},
        )
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", return_value=fake_api):
            self.assertTrue(ime_utils.is_ime_candidate_open())

    def test_findwindowex_fallback_catches_higher_band_window(self):
        fake_api = self._make_fake_api(
            windows={
                1: {
                    "visible": True,
                    "class": "Windows.UI.Core.CoreWindow",
                    "rect": (100, 100, 400, 200),
                    "pid": 10,
                    "path": r"C:\Windows\SystemApps\TextInputHost.exe",
                }
            },
            cloaked_map={1: 0},
        )
        # 模拟 EnumWindows 跳过高于 ZBID_DESKTOP 的窗口，但 FindWindowExW 可见
        fake_api.user32.EnumWindows = lambda cb, lp: 1
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", return_value=fake_api), \
             mock.patch.object(ime_utils, "_is_uia_ime_candidate_open", return_value=False):
            self.assertTrue(ime_utils.is_ime_candidate_open())

    def test_uia_fallback_catches_when_win32_enumeration_empty(self):
        fake_api = self._make_fake_api(windows={})
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", return_value=fake_api), \
             mock.patch.object(ime_utils, "_is_uia_ime_candidate_open", return_value=True):
            self.assertTrue(ime_utils.is_ime_candidate_open())

    def test_application_frame_reparented_text_input_host_returns_true(self):
        fake_api = self._make_fake_api(
            windows={
                100: {
                    "visible": True,
                    "class": "ApplicationFrameWindow",
                    "rect": (277, 676, 1279, 748),
                    "pid": 1,
                    "path": r"C:\Windows\explorer.exe",
                },
                101: {
                    "parent": 100,
                    "visible": True,
                    "class": "Windows.UI.Core.CoreWindow",
                    "rect": (375, 676, 1279, 748),
                    "pid": 2,
                    "path": r"C:\Windows\SystemApps\TextInputHost.exe",
                },
            },
            cloaked_map={100: 0, 101: 0},
        )
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", return_value=fake_api), \
             mock.patch.object(ime_utils, "_is_uia_ime_candidate_open", return_value=False):
            self.assertTrue(ime_utils.is_ime_candidate_open())

    def test_discovered_hwnd_fast_path_visible_uncloaked_child_and_root_returns_true(self):
        fake_api = self._make_fake_api(
            windows={
                200: {
                    "visible": True,
                    "class": "ApplicationFrameWindow",
                    "rect": (319, 676, 1279, 748),
                    "pid": 1,
                    "path": r"C:\Windows\explorer.exe",
                },
                201: {
                    "parent": 200,
                    "visible": True,
                    "class": "Windows.UI.Core.CoreWindow",
                    "rect": (319, 676, 1279, 748),
                    "pid": 2,
                    "path": r"C:\Windows\SystemApps\TextInputHost.exe",
                },
            },
            cloaked_map={200: 0, 201: 0},
        )
        ime_utils._record_discovered_hwnd(201)
        fake_api.user32.EnumWindows = mock.Mock(side_effect=AssertionError("EnumWindows should not run"))
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", return_value=fake_api), \
             mock.patch.object(ime_utils, "_is_uia_ime_candidate_open", side_effect=AssertionError("UIA fallback should not run")):
            self.assertTrue(ime_utils.is_ime_candidate_open())

    def test_discovered_hwnd_fast_path_cloaked_root_returns_false(self):
        fake_api = self._make_fake_api(
            windows={
                300: {
                    "visible": True,
                    "class": "ApplicationFrameWindow",
                    "rect": (319, 676, 1279, 748),
                    "pid": 1,
                    "path": r"C:\Windows\explorer.exe",
                },
                301: {
                    "parent": 300,
                    "visible": True,
                    "class": "Windows.UI.Core.CoreWindow",
                    "rect": (319, 676, 1279, 748),
                    "pid": 2,
                    "path": r"C:\Windows\SystemApps\TextInputHost.exe",
                },
            },
            cloaked_map={300: 1, 301: 0},
        )
        ime_utils._record_discovered_hwnd(301)
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", return_value=fake_api), \
             mock.patch.object(ime_utils, "_is_uia_ime_candidate_open", return_value=False):
            self.assertFalse(ime_utils.is_ime_candidate_open())
        with ime_utils._discovered_lock:
            self.assertIn(301, ime_utils._discovered_ime_hwnds)

    def test_discovered_hwnd_fast_path_prunes_destroyed_window(self):
        fake_api = self._make_fake_api(windows={})
        ime_utils._record_discovered_hwnd(9999)
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", return_value=fake_api), \
             mock.patch.object(ime_utils, "_is_uia_ime_candidate_open", return_value=False):
            self.assertFalse(ime_utils.is_ime_candidate_open())
        with ime_utils._discovered_lock:
            self.assertNotIn(9999, ime_utils._discovered_ime_hwnds)

    def test_uia_worker_timeout_returns_false(self):
        worker = ime_utils._UiaWorker()
        worker._started = True
        self.assertFalse(worker.is_candidate_open(timeout=0.005))

    def test_api_exception_falls_back_to_false(self):
        with mock.patch.object(ime_utils.sys, "platform", "win32"), \
             mock.patch.object(ime_utils, "_get_win32_api", side_effect=RuntimeError("boom")):
            self.assertFalse(ime_utils.is_ime_candidate_open())

    def test_non_windows_returns_false(self):
        with mock.patch.object(ime_utils.sys, "platform", "darwin"):
            self.assertFalse(ime_utils.is_ime_candidate_open())


if __name__ == "__main__":
    unittest.main()
