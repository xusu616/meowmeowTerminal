"""Windows 输入法候选框检测工具。"""

import ctypes
from ctypes import wintypes
import os
import queue
import sys
import threading
import time
from typing import Callable, List, Optional
import uuid


# 直接对应候选词面板的窗口类名（排除状态栏/工具栏类名，避免常驻悬浮栏误判）
_EXACT_CANDIDATE_CLASSES = frozenset({
    "Microsoft.IME.UIManager.CandidateWindow.Host",
    "Microsoft.IME.CandidateWindow.View",
    "SoPY_Comp",
    "Sogou_Candidate_Window",
    "QQPinyinCompWndTSF",
    "QQPinyinCompWnd",
    "QQPinyin_CandWnd",
})

# Win10/11 现代输入体验（微软拼音等）由 TextInputHost 宿主渲染，平时可能保持
# WS_VISIBLE 但处于 DWM cloaked 状态，且常位于高于 ZBID_DESKTOP 的窗口带中
# （EnumWindows 可能会跳过，需要配合 FindWindowExW / UI Automation 检测）。
_MODERN_IME_HOST_PROCESSES = frozenset({
    "textinputhost.exe",
    "inputapp.exe",
    "windowsinternal.composableshell.experiences.textinput.inputapp.exe",
})
_MODERN_IME_HOST_CLASSES = frozenset({
    "Windows.UI.Core.CoreWindow",
    "PopupHost",
    "Xaml_WindowedPopupClass",
    "InputSiteWindowClass",
    "Windows.UI.Input.InputSite.WindowClass",
})

# 小狼毫 (Rime/Weasel) 候选框由 WeaselServer.exe 创建
_WEASEL_PROCESSES = frozenset({"weaselserver.exe"})

# 通过 UIA 跨窗口带检查的现代微软输入法宿主进程
_UIA_HOST_PROCESSES = _MODERN_IME_HOST_PROCESSES

_DWMWA_CLOAKED = 14
_GA_ROOT = 2
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_MIN_WINDOW_SIZE = 10
_OFFSCREEN_PARKED_THRESHOLD = -30000
_FINDWINDOW_MAX_STEPS = 512
_EVENT_OBJECT_SHOW = 0x8002
_EVENT_OBJECT_IME_SHOW = 0x8027
_WINEVENT_SKIPOWNPROCESS = 0x0002

# UI Automation COM 常量与接口偏移（x64 / x86 通用索引）
_COINIT_MULTITHREADED = 0x0
_CLSCTX_INPROC_SERVER = 0x1
_TREE_SCOPE_CHILDREN = 2
_TREE_SCOPE_DESCENDANTS = 4
_UIA_PROCESS_ID_PROPERTY_ID = 30002
_UIA_CLASS_NAME_PROPERTY_ID = 30012
_VT_I4 = 3
_VT_BSTR = 8
_UIA_QUERY_TIMEOUT_S = 0.15
_APP_FRAME_CLASS = "ApplicationFrameWindow"

_CLSID_CUIAutomation = "{FF48DBA4-60EF-4201-AA87-54103EEF594E}"
_IID_IUIAutomation = "{30CBE57D-D9D0-452A-AB13-7AC5AC4825EE}"


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_str(cls, guid_str: str) -> "_GUID":
        u = uuid.UUID(guid_str)
        return cls(
            u.time_low,
            u.time_mid,
            u.time_hi_version,
            (ctypes.c_ubyte * 8)(*u.bytes[8:]),
        )


class _VARIANT(ctypes.Structure):
    _fields_ = [
        ("vt", wintypes.WORD),
        ("wReserved1", wintypes.WORD),
        ("wReserved2", wintypes.WORD),
        ("wReserved3", wintypes.WORD),
        ("data1", ctypes.c_void_p),
        ("data2", ctypes.c_void_p),
    ]


class _Win32Api:
    """惰性初始化并缓存带精确 argtypes 的 Win32 API 句柄。"""

    def __init__(self):
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        try:
            self.dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        except OSError:
            self.dwmapi = None

        self.WNDENUMPROC = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM
        )

        self.user32.EnumWindows.argtypes = (self.WNDENUMPROC, wintypes.LPARAM)
        self.user32.EnumWindows.restype = wintypes.BOOL

        self.user32.EnumChildWindows.argtypes = (
            wintypes.HWND, self.WNDENUMPROC, wintypes.LPARAM
        )
        self.user32.EnumChildWindows.restype = wintypes.BOOL

        self.user32.FindWindowExW.argtypes = (
            wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR
        )
        self.user32.FindWindowExW.restype = wintypes.HWND

        self.user32.IsWindowVisible.argtypes = (wintypes.HWND,)
        self.user32.IsWindowVisible.restype = wintypes.BOOL

        self.user32.IsWindow.argtypes = (wintypes.HWND,)
        self.user32.IsWindow.restype = wintypes.BOOL

        self.user32.GetAncestor.argtypes = (wintypes.HWND, wintypes.UINT)
        self.user32.GetAncestor.restype = wintypes.HWND

        self.user32.IsIconic.argtypes = (wintypes.HWND,)
        self.user32.IsIconic.restype = wintypes.BOOL

        self.user32.GetClassNameW.argtypes = (
            wintypes.HWND, wintypes.LPWSTR, ctypes.c_int
        )
        self.user32.GetClassNameW.restype = ctypes.c_int

        self.user32.GetWindowTextW.argtypes = (
            wintypes.HWND, wintypes.LPWSTR, ctypes.c_int
        )
        self.user32.GetWindowTextW.restype = ctypes.c_int

        self.user32.GetWindowRect.argtypes = (
            wintypes.HWND, ctypes.POINTER(wintypes.RECT)
        )
        self.user32.GetWindowRect.restype = wintypes.BOOL

        self.user32.GetWindowThreadProcessId.argtypes = (
            wintypes.HWND, ctypes.POINTER(wintypes.DWORD)
        )
        self.user32.GetWindowThreadProcessId.restype = wintypes.DWORD

        if self.dwmapi is not None:
            self.dwmapi.DwmGetWindowAttribute.argtypes = (
                wintypes.HWND,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
            )
            self.dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long

        self.kernel32.OpenProcess.argtypes = (
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
        )
        self.kernel32.OpenProcess.restype = wintypes.HANDLE

        self.kernel32.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        )
        self.kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

        self.kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.kernel32.CloseHandle.restype = wintypes.BOOL


_win32_api: Optional[_Win32Api] = None


def _get_win32_api() -> _Win32Api:
    global _win32_api
    if _win32_api is None:
        _win32_api = _Win32Api()
    return _win32_api


def _needs_process_check(class_name: str) -> bool:
    """判断该窗口类名是否需要进一步校验所属进程名。"""
    if class_name in _MODERN_IME_HOST_CLASSES:
        return True
    return class_name.startswith("ATL:") or class_name.startswith("Weasel")


def _matches_ime_candidate_identity(
    class_name: str, get_process_name: Callable[[], str]
) -> bool:
    """根据窗口类名与所属进程名判断是否为输入法候选窗口。"""
    if not class_name:
        return False
    if class_name in _EXACT_CANDIDATE_CLASSES:
        return True
    if not _needs_process_check(class_name):
        return False

    proc_name = get_process_name().lower()
    if not proc_name:
        return False
    if class_name in _MODERN_IME_HOST_CLASSES and proc_name in _MODERN_IME_HOST_PROCESSES:
        return True
    if (class_name.startswith("ATL:") or class_name.startswith("Weasel")) and proc_name in _WEASEL_PROCESSES:
        return True
    return False


def _is_rect_on_screen(left: int, top: int, right: int, bottom: int) -> bool:
    """过滤 0x0 幽灵窗口以及最小化停靠到 (-32000, -32000) 的窗口。"""
    width = right - left
    height = bottom - top
    if width <= _MIN_WINDOW_SIZE or height <= _MIN_WINDOW_SIZE:
        return False
    if left <= _OFFSCREEN_PARKED_THRESHOLD or top <= _OFFSCREEN_PARKED_THRESHOLD:
        return False
    return True


def _get_process_name_by_pid(api: _Win32Api, pid: int) -> str:
    if not pid:
        return ""
    handle = api.kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(260)
        size = wintypes.DWORD(len(buf))
        if not api.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return ""
        return os.path.basename(buf.value)
    finally:
        api.kernel32.CloseHandle(handle)


def _get_process_name_by_hwnd(api: _Win32Api, hwnd: int) -> str:
    pid = wintypes.DWORD(0)
    api.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return _get_process_name_by_pid(api, pid.value)


def _is_hwnd_cloaked(api: _Win32Api, hwnd: int) -> bool:
    if api.dwmapi is None or not hwnd:
        return False
    cloaked = ctypes.c_int(0)
    hr = api.dwmapi.DwmGetWindowAttribute(
        hwnd, _DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked)
    )
    return hr == 0 and cloaked.value != 0


def _is_window_uncloaked_and_visible(api: _Win32Api, hwnd: int) -> bool:
    if not api.user32.IsWindowVisible(hwnd):
        return False
    if api.user32.IsIconic(hwnd):
        return False
    if _is_hwnd_cloaked(api, hwnd):
        return False

    rect = wintypes.RECT()
    if not api.user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return False
    return _is_rect_on_screen(rect.left, rect.top, rect.right, rect.bottom)


def _check_window_matches(api: _Win32Api, hwnd: int) -> bool:
    if not hwnd or not api.user32.IsWindowVisible(hwnd):
        return False
    cls_buf = ctypes.create_unicode_buffer(256)
    cls_len = api.user32.GetClassNameW(hwnd, cls_buf, len(cls_buf))
    if cls_len <= 0:
        return False
    class_name = cls_buf.value
    if not _matches_ime_candidate_identity(
        class_name, lambda: _get_process_name_by_hwnd(api, hwnd)
    ):
        return False
    return _is_window_uncloaked_and_visible(api, hwnd)


def _collect_visible_app_frames(api: _Win32Api) -> List[int]:
    """收集当前可见且未遮蔽的 ApplicationFrameWindow（Win11 微软拼音候选窗宿主容器）。"""
    frames: List[int] = []
    seen = set()
    after = None
    for _ in range(_FINDWINDOW_MAX_STEPS):
        hwnd = api.user32.FindWindowExW(None, after, _APP_FRAME_CLASS, None)
        if not hwnd or hwnd in seen:
            break
        seen.add(hwnd)
        after = hwnd
        if _is_window_uncloaked_and_visible(api, hwnd):
            frames.append(int(hwnd))
    return frames


def _find_candidate_in_app_frames(api: _Win32Api, app_frames: List[int]) -> bool:
    """用 EnumChildWindows 检查 ApplicationFrameWindow 内部托管的 TextInputHost 子窗口。"""
    for app_hwnd in app_frames:
        found = False

        def _child_cb(child_hwnd, _lparam):
            nonlocal found
            try:
                if _check_window_matches(api, child_hwnd):
                    found = True
                    return False
            except Exception:
                return True
            return True

        api.user32.EnumChildWindows(app_hwnd, api.WNDENUMPROC(_child_cb), 0)
        if found:
            return True
    return False


def _find_candidate_via_findwindowex(api: _Win32Api) -> bool:
    """补充 EnumWindows：针对指定类名用 FindWindowExW 检索顶层窗口。"""
    for class_name in _EXACT_CANDIDATE_CLASSES | _MODERN_IME_HOST_CLASSES:
        hwnd_after = None
        for _ in range(_FINDWINDOW_MAX_STEPS):
            hwnd = api.user32.FindWindowExW(None, hwnd_after, class_name, None)
            if not hwnd:
                break
            if _check_window_matches(api, hwnd):
                return True
            hwnd_after = hwnd
    return False


def _com_vtable_fn(ptr: ctypes.c_void_p, idx: int, restype, *argtypes):
    vt = ctypes.cast(ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
    return ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)(vt[idx])


def _com_release(ptr: ctypes.c_void_p) -> None:
    if ptr and ptr.value:
        _com_vtable_fn(ptr, 2, ctypes.c_ulong)(ptr)


def _find_pids_by_names(target_names: frozenset) -> List[int]:
    """用 psutil（已在项目依赖中）枚举匹配进程 PID。"""
    import psutil

    pids: List[int] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in target_names:
                pids.append(int(proc.info["pid"]))
        except (psutil.Error, OSError, ValueError):
            continue
    return pids


class _UiaWorker:
    """在独立 MTA COM 线程上执行 UIA 查询，隔离钩子线程且支持严格超时。"""

    def __init__(self):
        self._req_queue: queue.Queue = queue.Queue(maxsize=1)
        self._started = False
        self._start_lock = threading.Lock()
        self._ole32 = None
        self._oleaut32 = None
        self._oleaut32_raw = None
        self._uia = ctypes.c_void_p()
        self._root = ctypes.c_void_p()
        self._pid_conds: dict = {}
        self._app_frame_cond = ctypes.c_void_p()
        self._cached_pids: List[int] = []
        self._cached_pids_at: float = 0.0

    def _ensure_started(self) -> None:
        if self._started:
            return
        with self._start_lock:
            if self._started:
                return
            t = threading.Thread(target=self._loop, name="ime-uia-worker", daemon=True)
            t.start()
            self._started = True

    def _init_com(self) -> bool:
        try:
            self._ole32 = ctypes.OleDLL("ole32")
            self._oleaut32 = ctypes.OleDLL("oleaut32")
            self._oleaut32_raw = ctypes.WinDLL("oleaut32")
            self._oleaut32_raw.SysAllocString.argtypes = (wintypes.LPCWSTR,)
            self._oleaut32_raw.SysAllocString.restype = ctypes.c_void_p
            self._oleaut32_raw.SysFreeString.argtypes = (ctypes.c_void_p,)
            self._ole32.CoInitializeEx(None, _COINIT_MULTITHREADED)
            clsid = _GUID.from_str(_CLSID_CUIAutomation)
            iid = _GUID.from_str(_IID_IUIAutomation)
            hr = self._ole32.CoCreateInstance(
                ctypes.byref(clsid),
                None,
                _CLSCTX_INPROC_SERVER,
                ctypes.byref(iid),
                ctypes.byref(self._uia),
            )
            if hr != 0 or not self._uia.value:
                return False
            hr = _com_vtable_fn(
                self._uia, 5, ctypes.HRESULT, ctypes.POINTER(ctypes.c_void_p)
            )(self._uia, ctypes.byref(self._root))
            return hr == 0 and bool(self._root.value)
        except Exception:
            return False

    def _get_pid_condition(self, pid: int) -> ctypes.c_void_p:
        cond = self._pid_conds.get(pid)
        if cond and cond.value:
            return cond
        var = _VARIANT()
        var.vt = _VT_I4
        var.data1 = pid
        cond = ctypes.c_void_p()
        arg_var = ctypes.POINTER(_VARIANT) if ctypes.sizeof(ctypes.c_void_p) == 8 else _VARIANT
        fn = _com_vtable_fn(
            self._uia,
            23,
            ctypes.HRESULT,
            wintypes.INT,
            arg_var,
            ctypes.POINTER(ctypes.c_void_p),
        )
        arg = ctypes.byref(var) if ctypes.sizeof(ctypes.c_void_p) == 8 else var
        hr = fn(self._uia, _UIA_PROCESS_ID_PROPERTY_ID, arg, ctypes.byref(cond))
        if hr == 0 and cond.value:
            self._pid_conds[pid] = cond
            return cond
        return ctypes.c_void_p()

    def _get_app_frame_condition(self) -> ctypes.c_void_p:
        if self._app_frame_cond.value:
            return self._app_frame_cond
        if self._oleaut32_raw is None:
            return ctypes.c_void_p()
        bstr = self._oleaut32_raw.SysAllocString(_APP_FRAME_CLASS)
        if not bstr:
            return ctypes.c_void_p()
        try:
            var = _VARIANT()
            var.vt = _VT_BSTR
            var.data1 = bstr
            cond = ctypes.c_void_p()
            arg_var = ctypes.POINTER(_VARIANT) if ctypes.sizeof(ctypes.c_void_p) == 8 else _VARIANT
            fn = _com_vtable_fn(
                self._uia,
                23,
                ctypes.HRESULT,
                wintypes.INT,
                arg_var,
                ctypes.POINTER(ctypes.c_void_p),
            )
            arg = ctypes.byref(var) if ctypes.sizeof(ctypes.c_void_p) == 8 else var
            hr = fn(self._uia, _UIA_CLASS_NAME_PROPERTY_ID, arg, ctypes.byref(cond))
            if hr == 0 and cond.value:
                self._app_frame_cond = cond
                return cond
            return ctypes.c_void_p()
        finally:
            self._oleaut32_raw.SysFreeString(bstr)

    def _collect_uia_app_frames(self, api: _Win32Api) -> List[ctypes.c_void_p]:
        """直接从 UIA Desktop Children 查找可见 ApplicationFrameWindow（跨 Z-order 带）。"""
        cond = self._get_app_frame_condition()
        if not cond.value:
            return []
        find_all = _com_vtable_fn(
            self._root,
            6,
            ctypes.HRESULT,
            wintypes.INT,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        arr = ctypes.c_void_p()
        hr = find_all(self._root, _TREE_SCOPE_CHILDREN, cond, ctypes.byref(arr))
        if hr != 0 or not arr.value:
            return []
        result: List[ctypes.c_void_p] = []
        try:
            length = wintypes.INT(0)
            _com_vtable_fn(arr, 3, ctypes.HRESULT, ctypes.POINTER(wintypes.INT))(
                arr, ctypes.byref(length)
            )
            get_elem = _com_vtable_fn(
                arr, 4, ctypes.HRESULT, wintypes.INT, ctypes.POINTER(ctypes.c_void_p)
            )
            for idx in range(length.value):
                elem = ctypes.c_void_p()
                if get_elem(arr, idx, ctypes.byref(elem)) == 0 and elem.value:
                    if self._is_uia_element_visible(api, elem):
                        result.append(elem)
                    else:
                        _com_release(elem)
        finally:
            _com_release(arr)
        return result

    def _is_uia_element_visible(self, api: _Win32Api, elem: ctypes.c_void_p) -> bool:
        offscreen = wintypes.BOOL(1)
        hr_off = _com_vtable_fn(
            elem, 38, ctypes.HRESULT, ctypes.POINTER(wintypes.BOOL)
        )(elem, ctypes.byref(offscreen))
        if hr_off == 0 and offscreen.value:
            return False

        hwnd_val = wintypes.HWND()
        hr_hwnd = _com_vtable_fn(
            elem, 36, ctypes.HRESULT, ctypes.POINTER(wintypes.HWND)
        )(elem, ctypes.byref(hwnd_val))
        if hr_hwnd == 0 and hwnd_val.value:
            hwnd = int(hwnd_val.value)
            if not api.user32.IsWindowVisible(hwnd) or api.user32.IsIconic(hwnd):
                return False
            if _is_hwnd_cloaked(api, hwnd):
                return False
        else:
            hwnd = 0

        rect = wintypes.RECT()
        hr_rect = _com_vtable_fn(
            elem, 43, ctypes.HRESULT, ctypes.POINTER(wintypes.RECT)
        )(elem, ctypes.byref(rect))
        if hr_rect != 0:
            return False
        if not _is_rect_on_screen(rect.left, rect.top, rect.right, rect.bottom):
            return False
        if hwnd:
            _record_discovered_hwnd(hwnd)
        return True

    def _find_visible_in_scope(
        self, api: _Win32Api, target_elem: ctypes.c_void_p, scope: int, cond: ctypes.c_void_p
    ) -> bool:
        find_all = _com_vtable_fn(
            target_elem,
            6,
            ctypes.HRESULT,
            wintypes.INT,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        )
        arr = ctypes.c_void_p()
        hr = find_all(target_elem, scope, cond, ctypes.byref(arr))
        if hr != 0 or not arr.value:
            return False
        try:
            length = wintypes.INT(0)
            _com_vtable_fn(arr, 3, ctypes.HRESULT, ctypes.POINTER(wintypes.INT))(
                arr, ctypes.byref(length)
            )
            get_elem = _com_vtable_fn(
                arr, 4, ctypes.HRESULT, wintypes.INT, ctypes.POINTER(ctypes.c_void_p)
            )
            for idx in range(length.value):
                elem = ctypes.c_void_p()
                if get_elem(arr, idx, ctypes.byref(elem)) == 0 and elem.value:
                    try:
                        if self._is_uia_element_visible(api, elem):
                            return True
                    finally:
                        _com_release(elem)
        finally:
            _com_release(arr)
        return False

    def _probe_now(self, app_frames: Optional[List[int]] = None) -> bool:
        if not self._uia.value and not self._init_com():
            return False
        api = _get_win32_api()
        now = time.monotonic()
        if not self._cached_pids or (now - self._cached_pids_at) > 2.0:
            self._cached_pids = _find_pids_by_names(_UIA_HOST_PROCESSES)
            self._cached_pids_at = now
        pids = self._cached_pids
        if not pids:
            return False

        # 清理已退出的 PID 条件对象，防止缓存泄漏
        live_set = set(pids)
        for stale_pid in list(self._pid_conds):
            if stale_pid not in live_set:
                _com_release(self._pid_conds.pop(stale_pid))

        # 优先直接从 UIA Desktop Children 查可见 ApplicationFrameWindow（可跨 Z-order 带），
        # 再检查其内部托管的 TextInputHost 子树（节点极少，不会遍历 Chrome/QQ）
        frame_elems: List[ctypes.c_void_p] = self._collect_uia_app_frames(api)
        if not frame_elems and app_frames:
            elem_from_hwnd = _com_vtable_fn(
                self._uia, 6, ctypes.HRESULT, wintypes.HWND, ctypes.POINTER(ctypes.c_void_p)
            )
            for app_hwnd in app_frames:
                fe = ctypes.c_void_p()
                if elem_from_hwnd(self._uia, app_hwnd, ctypes.byref(fe)) == 0 and fe.value:
                    frame_elems.append(fe)

        try:
            for pid in pids:
                cond = self._get_pid_condition(pid)
                if not cond.value:
                    continue
                if self._find_visible_in_scope(api, self._root, _TREE_SCOPE_CHILDREN, cond):
                    return True
                for fe in frame_elems:
                    if self._find_visible_in_scope(api, fe, _TREE_SCOPE_CHILDREN, cond):
                        return True
                    if self._find_visible_in_scope(api, fe, _TREE_SCOPE_DESCENDANTS, cond):
                        return True
        finally:
            for fe in frame_elems:
                _com_release(fe)
        return False

    def _loop(self) -> None:
        try:
            self._probe_now()
        except Exception:
            pass
        while True:
            done_event, result_box, app_frames = self._req_queue.get()
            try:
                result_box[0] = self._probe_now(app_frames)
            except Exception:
                result_box[0] = False
            finally:
                done_event.set()

    def is_candidate_open(
        self,
        app_frames: Optional[List[int]] = None,
        timeout: float = _UIA_QUERY_TIMEOUT_S,
    ) -> bool:
        self._ensure_started()
        done_event = threading.Event()
        result_box = [False]
        try:
            self._req_queue.put_nowait((done_event, result_box, app_frames or []))
        except queue.Full:
            return False
        if not done_event.wait(timeout=timeout):
            return False
        return bool(result_box[0])


_uia_worker: Optional[_UiaWorker] = None
_discovered_ime_hwnds: set = set()
_discovered_lock = threading.Lock()


def _record_discovered_hwnd(hwnd: int) -> None:
    if not hwnd:
        return
    with _discovered_lock:
        _discovered_ime_hwnds.add(int(hwnd))


def _is_hwnd_and_root_visible(api: _Win32Api, hwnd: int) -> bool:
    if not hwnd or not api.user32.IsWindow(hwnd):
        return False
    if not _is_window_uncloaked_and_visible(api, hwnd):
        return False
    root = api.user32.GetAncestor(hwnd, _GA_ROOT)
    if root and int(root) != int(hwnd):
        if not _is_window_uncloaked_and_visible(api, int(root)):
            return False
    return True


def _check_discovered_hwnds(api: _Win32Api) -> bool:
    """微秒级快路径：直接校验已捕获到的输入法候选框 HWND 当前是否仍可见且未遮蔽。"""
    with _discovered_lock:
        candidates = list(_discovered_ime_hwnds)
    if not candidates:
        return False

    stale = []
    matched = False
    for hwnd in candidates:
        if not api.user32.IsWindow(hwnd):
            stale.append(hwnd)
            continue
        if _is_hwnd_and_root_visible(api, hwnd):
            matched = True
            break
    if stale:
        with _discovered_lock:
            for hwnd in stale:
                _discovered_ime_hwnds.discard(hwnd)
    return matched


class _WinEventTracker:
    """后台监听系统窗口显示事件，实时捕获高窗口带中的输入法候选窗 HWND。"""

    def __init__(self):
        self._started = False
        self._lock = threading.Lock()
        self._cb_ref = None

    def ensure_started(self) -> None:
        if self._started:
            return
        with self._lock:
            if self._started:
                return
            t = threading.Thread(target=self._loop, name="ime-winevent-tracker", daemon=True)
            t.start()
            self._started = True

    def _loop(self) -> None:
        try:
            api = _get_win32_api()
            WINEVENTPROC = ctypes.WINFUNCTYPE(
                None,
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.HWND,
                wintypes.LONG,
                wintypes.LONG,
                wintypes.DWORD,
                wintypes.DWORD,
            )

            def _cb(_hook, _event, hwnd, id_obj, _id_child, _tid, _ms):
                if not hwnd or id_obj != 0:
                    return
                try:
                    hv = int(hwnd)
                    cls_buf = ctypes.create_unicode_buffer(256)
                    if api.user32.GetClassNameW(hv, cls_buf, len(cls_buf)) <= 0:
                        return
                    if _matches_ime_candidate_identity(
                        cls_buf.value, lambda: _get_process_name_by_hwnd(api, hv)
                    ):
                        _record_discovered_hwnd(hv)
                except Exception:
                    pass

            self._cb_ref = WINEVENTPROC(_cb)
            api.user32.SetWinEventHook.restype = wintypes.HANDLE
            h1 = api.user32.SetWinEventHook(
                _EVENT_OBJECT_SHOW, _EVENT_OBJECT_SHOW, None, self._cb_ref, 0, 0, _WINEVENT_SKIPOWNPROCESS
            )
            h2 = api.user32.SetWinEventHook(
                _EVENT_OBJECT_IME_SHOW, _EVENT_OBJECT_IME_SHOW, None, self._cb_ref, 0, 0, _WINEVENT_SKIPOWNPROCESS
            )
            if not h1 and not h2:
                return
            msg = wintypes.MSG()
            while api.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                api.user32.TranslateMessage(ctypes.byref(msg))
                api.user32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            pass


_win_event_tracker: Optional[_WinEventTracker] = None


def warmup_ime_detector() -> None:
    """预热后台 WinEvent 与 UIA 检测线程，避免首次按 Enter 时触发初始化耗时。"""
    if not sys.platform.startswith("win"):
        return
    global _uia_worker, _win_event_tracker
    try:
        if _win_event_tracker is None:
            _win_event_tracker = _WinEventTracker()
        _win_event_tracker.ensure_started()
        if _uia_worker is None:
            _uia_worker = _UiaWorker()
        _uia_worker._ensure_started()
    except Exception:
        pass


def _is_uia_ime_candidate_open(app_frames: Optional[List[int]] = None) -> bool:
    global _uia_worker
    if _uia_worker is None:
        _uia_worker = _UiaWorker()
    return _uia_worker.is_candidate_open(app_frames=app_frames)


def is_ime_candidate_open() -> bool:
    """检测当前是否存在可见且未被遮蔽（uncloaked）的输入法候选框。

    设计为在低级键盘钩子 (WH_KEYBOARD_LL) 中同步调用：
    1. 微秒级快路径：直接校验后台 WinEvent/UIA 已捕获到的候选窗 HWND 实时可见性；
    2. EnumWindows / FindWindowExW / ApplicationFrameWindow 检查桌面与宿主容器；
    3. UI Automation 跨 Z-order 带兜底，并在独立线程设严格超时。
    """
    if not sys.platform.startswith("win"):
        return False

    try:
        api = _get_win32_api()
        if _check_discovered_hwnds(api):
            return True

        found = False

        def _enum_cb(hwnd, _lparam):
            nonlocal found
            try:
                if _check_window_matches(api, hwnd):
                    _record_discovered_hwnd(int(hwnd))
                    found = True
                    return False
            except Exception:
                return True
            return True

        api.user32.EnumWindows(api.WNDENUMPROC(_enum_cb), 0)
        if found:
            return True

        app_frames = _collect_visible_app_frames(api)
        if app_frames and _find_candidate_in_app_frames(api, app_frames):
            return True

        if _find_candidate_via_findwindowex(api):
            return True

        return _is_uia_ime_candidate_open(app_frames)
    except Exception:
        return False


def _dump_diagnostic_snapshot() -> None:
    """交互桌面排障用：监听 WinEvent 并采样可见窗口、FindWindowEx 与 UIA 节点。"""
    api = _get_win32_api()
    warmup_ime_detector()
    time.sleep(0.15)
    t0 = time.perf_counter()
    res = is_ime_candidate_open()
    print(f"is_ime_candidate_open() -> {res} ({(time.perf_counter() - t0) * 1000:.2f}ms)")

    fg = api.user32.GetForegroundWindow()
    fg_cls = ctypes.create_unicode_buffer(256)
    if fg:
        api.user32.GetClassNameW(fg, fg_cls, 256)
    print(f"ForegroundWindow: hwnd={fg:#x} cls={fg_cls.value!r} proc={_get_process_name_by_hwnd(api, fg)!r}")

    # 1. EnumWindows 中所有可见且带 TOPMOST / NOACTIVATE / TOOLWINDOW 或输入法相关窗口
    print("\n--- [1] EnumWindows (visible topmost/noactivate/toolwindow/IME) ---")
    def _diag_enum(hwnd, _lp):
        if not api.user32.IsWindowVisible(hwnd):
            return True
        ex_style = api.user32.GetWindowLongW(hwnd, -20)  # GWL_EXSTYLE
        proc = _get_process_name_by_hwnd(api, hwnd)
        cls_buf = ctypes.create_unicode_buffer(256)
        api.user32.GetClassNameW(hwnd, cls_buf, 256)
        title_buf = ctypes.create_unicode_buffer(256)
        api.user32.GetWindowTextW(hwnd, title_buf, 256)
        is_interesting = (
            bool(ex_style & 0x08000008)  # WS_EX_NOACTIVATE | WS_EX_TOPMOST
            or bool(ex_style & 0x00000080)  # WS_EX_TOOLWINDOW
            or any(k in (proc + " " + cls_buf.value + " " + title_buf.value).lower()
                   for k in ("ime", "textinput", "ctfmon", "candidate", "input", "输入"))
        )
        if is_interesting:
            rect = wintypes.RECT()
            api.user32.GetWindowRect(hwnd, ctypes.byref(rect))
            cloaked = _is_hwnd_cloaked(api, hwnd)
            print(
                f"  hwnd={hwnd:#x} proc={proc!r} cls={cls_buf.value!r} title={title_buf.value!r} "
                f"ex={ex_style:#x} cloaked={cloaked} rect=({rect.left},{rect.top},{rect.right},{rect.bottom})"
            )
        return True
    api.user32.EnumWindows(api.WNDENUMPROC(_diag_enum), 0)

    # 2. FindWindowExW(None, after, None, None) 跨带枚举
    print("\n--- [2] FindWindowExW (IME/TextInputHost/NOACTIVATE) ---")
    after = None
    seen = set()
    for _ in range(1000):
        hwnd = api.user32.FindWindowExW(None, after, None, None)
        if not hwnd or hwnd in seen:
            break
        seen.add(hwnd)
        after = hwnd
        if not api.user32.IsWindowVisible(hwnd):
            continue
        proc = _get_process_name_by_hwnd(api, hwnd)
        cls_buf = ctypes.create_unicode_buffer(256)
        api.user32.GetClassNameW(hwnd, cls_buf, 256)
        if any(k in (proc + " " + cls_buf.value).lower() for k in ("ime", "textinput", "ctfmon", "candidate", "corewindow")):
            rect = wintypes.RECT()
            api.user32.GetWindowRect(hwnd, ctypes.byref(rect))
            cloaked = _is_hwnd_cloaked(api, hwnd)
            print(
                f"  hwnd={hwnd:#x} proc={proc!r} cls={cls_buf.value!r} cloaked={cloaked} "
                f"rect=({rect.left},{rect.top},{rect.right},{rect.bottom})"
            )

    # 3. UIA: 检查所有可见 Desktop 子节点 + IME 宿主进程 Descendants
    print("\n--- [3] UIA Snapshot ---")
    pids = _find_pids_by_names(_UIA_HOST_PROCESSES | _WEASEL_PROCESSES | frozenset({"ctfmon.exe"}))
    print(f"IME host PIDs: {pids}")
    worker = _UiaWorker()
    worker._init_com()
    if worker._uia.value and worker._root.value:
        frames = worker._collect_uia_app_frames(api)
        t_probe = time.perf_counter()
        probe_res = worker._probe_now()
        print(
            f"UIA app_frames={len(frames)} direct_probe={probe_res} "
            f"({(time.perf_counter() - t_probe) * 1000:.2f}ms)"
        )
        for fe in frames:
            _com_release(fe)
        worker._oleaut32_raw.SysFreeString.argtypes = (ctypes.c_void_p,)
        worker._oleaut32_raw.SysFreeString.restype = None

        def _print_elem(prefix, elem):
            off = wintypes.BOOL()
            rect = wintypes.RECT()
            hwnd = wintypes.HWND()
            epid = wintypes.INT()
            cls_bstr = ctypes.c_void_p()
            name_bstr = ctypes.c_void_p()
            _com_vtable_fn(elem, 20, ctypes.HRESULT, ctypes.POINTER(wintypes.INT))(elem, ctypes.byref(epid))
            _com_vtable_fn(elem, 38, ctypes.HRESULT, ctypes.POINTER(wintypes.BOOL))(elem, ctypes.byref(off))
            _com_vtable_fn(elem, 43, ctypes.HRESULT, ctypes.POINTER(wintypes.RECT))(elem, ctypes.byref(rect))
            _com_vtable_fn(elem, 36, ctypes.HRESULT, ctypes.POINTER(wintypes.HWND))(elem, ctypes.byref(hwnd))
            _com_vtable_fn(elem, 30, ctypes.HRESULT, ctypes.POINTER(ctypes.c_void_p))(elem, ctypes.byref(cls_bstr))
            _com_vtable_fn(elem, 23, ctypes.HRESULT, ctypes.POINTER(ctypes.c_void_p))(elem, ctypes.byref(name_bstr))
            cls_str = ctypes.wstring_at(cls_bstr.value) if cls_bstr.value else ""
            name_str = ctypes.wstring_at(name_bstr.value) if name_bstr.value else ""
            proc = _get_process_name_by_pid(api, epid.value)
            hv = int(hwnd.value) if hwnd.value else 0
            vis = bool(api.user32.IsWindowVisible(hv)) if hv else None
            cloaked = _is_hwnd_cloaked(api, hv) if hv else False
            print(
                f"{prefix} pid={epid.value}({proc}) cls={cls_str!r} name={name_str!r} "
                f"offscreen={off.value} hwnd={hv:#x} vis={vis} cloaked={cloaked} "
                f"rect=({rect.left},{rect.top},{rect.right},{rect.bottom})"
            )
            if cls_bstr.value:
                worker._oleaut32_raw.SysFreeString(cls_bstr)
            if name_bstr.value:
                worker._oleaut32_raw.SysFreeString(name_bstr)

        # 3a. Root -> TrueCondition -> Children (全部桌面顶层 UIA 节点中的相关项)
        true_cond = ctypes.c_void_p()
        hr_tc = _com_vtable_fn(worker._uia, 21, ctypes.HRESULT, ctypes.POINTER(ctypes.c_void_p))(
            worker._uia, ctypes.byref(true_cond)
        )
        if hr_tc == 0 and true_cond.value:
            arr = ctypes.c_void_p()
            hr = _com_vtable_fn(
                worker._root, 6, ctypes.HRESULT, wintypes.INT, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
            )(worker._root, _TREE_SCOPE_CHILDREN, true_cond, ctypes.byref(arr))
            if hr == 0 and arr.value:
                length = wintypes.INT(0)
                _com_vtable_fn(arr, 3, ctypes.HRESULT, ctypes.POINTER(wintypes.INT))(arr, ctypes.byref(length))
                print(f"  UIA Desktop total children: {length.value}")
                get_elem = _com_vtable_fn(arr, 4, ctypes.HRESULT, wintypes.INT, ctypes.POINTER(ctypes.c_void_p))
                for idx in range(length.value):
                    elem = ctypes.c_void_p()
                    if get_elem(arr, idx, ctypes.byref(elem)) == 0 and elem.value:
                        try:
                            _print_elem(f"    child[{idx}]", elem)
                        finally:
                            _com_release(elem)
                _com_release(arr)
            _com_release(true_cond)

        # 3b. 对每个 IME 宿主 PID 查 TreeScope_Descendants (scope=4)
        for pid in pids:
            cond = worker._get_pid_condition(pid)
            if not cond.value:
                continue
            arr = ctypes.c_void_p()
            hr = _com_vtable_fn(
                worker._root, 6, ctypes.HRESULT, wintypes.INT, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
            )(worker._root, 4, cond, ctypes.byref(arr))
            if hr == 0 and arr.value:
                length = wintypes.INT(0)
                _com_vtable_fn(arr, 3, ctypes.HRESULT, ctypes.POINTER(wintypes.INT))(arr, ctypes.byref(length))
                print(f"  UIA descendants for pid={pid} ({_get_process_name_by_pid(api, pid)}): {length.value}")
                get_elem = _com_vtable_fn(arr, 4, ctypes.HRESULT, wintypes.INT, ctypes.POINTER(ctypes.c_void_p))
                for idx in range(min(length.value, 15)):
                    elem = ctypes.c_void_p()
                    if get_elem(arr, idx, ctypes.byref(elem)) == 0 and elem.value:
                        try:
                            _print_elem(f"    desc[{idx}]", elem)
                        finally:
                            _com_release(elem)
                _com_release(arr)


def _run_winevent_probe(duration_s: float = 5.0) -> None:
    """在采样窗口期间监听 EVENT_OBJECT_IME_SHOW/HIDE/CHANGE 与 EVENT_OBJECT_SHOW。"""
    api = _get_win32_api()
    events_log = []

    WINEVENTPROC = ctypes.WINFUNCTYPE(
        None,
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.HWND,
        wintypes.LONG,
        wintypes.LONG,
        wintypes.DWORD,
        wintypes.DWORD,
    )

    def _cb(_hook, event, hwnd, id_obj, id_child, _tid, _time_ms):
        if hwnd:
            proc = _get_process_name_by_hwnd(api, hwnd)
            cls_buf = ctypes.create_unicode_buffer(256)
            api.user32.GetClassNameW(hwnd, cls_buf, 256)
            cls = cls_buf.value
        else:
            proc, cls = "", ""
        if event in (0x8027, 0x8028, 0x8029) or any(
            k in (proc + " " + cls).lower() for k in ("ime", "textinput", "ctfmon", "candidate", "corewindow")
        ):
            events_log.append(
                f"  ev={event:#x} hwnd={hwnd or 0:#x} obj={id_obj} child={id_child} proc={proc!r} cls={cls!r}"
            )

    cb_ref = WINEVENTPROC(_cb)
    api.user32.SetWinEventHook.restype = wintypes.HANDLE
    h1 = api.user32.SetWinEventHook(0x8002, 0x8003, None, cb_ref, 0, 0, 0x0002)  # SHOW/HIDE
    h2 = api.user32.SetWinEventHook(0x8027, 0x8029, None, cb_ref, 0, 0, 0x0002)  # IME_SHOW/HIDE/CHANGE
    timer_id = api.user32.SetTimer(None, 0, int(duration_s * 1000), None)
    msg = wintypes.MSG()
    while api.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        if msg.message == 0x0113:  # WM_TIMER
            break
        api.user32.TranslateMessage(ctypes.byref(msg))
        api.user32.DispatchMessageW(ctypes.byref(msg))
    if timer_id:
        api.user32.KillTimer(None, timer_id)
    if h1:
        api.user32.UnhookWinEvent(h1)
    if h2:
        api.user32.UnhookWinEvent(h2)
    print("\n--- [0] WinEvents captured while typing ---")
    if not events_log:
        print("  (none)")
    for line in events_log[-30:]:
        print(line)


if __name__ == "__main__":
    print("请在 5 秒内切到输入框并打出拼音让候选框保持显示（不要关闭候选框）...")
    _run_winevent_probe(5.0)
    _dump_diagnostic_snapshot()
