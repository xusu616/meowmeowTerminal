"""加喵发送器 - 终端版入口"""
import ctypes
import sys
import threading
import traceback
import keyboard

from core import ManosabaCore
from utils.ime_utils import is_ime_candidate_open, warmup_ime_detector


# 两个实例会互相把对方注入的回车当成真回车，无限互相触发（顺带互抢剪贴板），
# 所以启动时用命名互斥体把第二个实例挡在注册热键之前。
_MUTEX_NAME = "Local\\meowmeowTerminal.main"
_ERROR_ALREADY_EXISTS = 183
_ERROR_ACCESS_DENIED = 5

# 句柄必须一直持有到进程退出（不能 CloseHandle），退出时系统自动释放
_instance_mutex = None


def acquire_single_instance() -> bool:
    """拿到单实例锁返回 True，已有实例在跑返回 False。"""
    global _instance_mutex

    if not sys.platform.startswith("win"):
        return True

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p)

    handle = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    err = ctypes.get_last_error()

    if not handle:
        # 打不开多半是已有一个提权实例占着：跨权限访问会直接报拒绝访问
        if err == _ERROR_ACCESS_DENIED:
            return False
        print(f"[加喵] 单实例检查失败（错误码 {err}），跳过检查继续启动")
        return True

    if err == _ERROR_ALREADY_EXISTS:
        return False

    _instance_mutex = handle
    return True


if not acquire_single_instance():
    print("=" * 40)
    print("  已经有一个加喵发送器在运行了，请先关掉它")
    print("  （两个实例会互相触发回车，还会互抢剪贴板）")
    print("  查进程:  tasklist | findstr python")
    print("  结束它:  Stop-Process -Id <PID> -Force")
    print("=" * 40)
    sys.exit(1)


core = ManosabaCore()
_enabled = True
_lock = threading.Lock()


def _run():
    try:
        print("[加喵] 正在处理…")
        result = core.send_text()
        print(f"[加喵] {result}")
    except Exception:
        print("[加喵] 处理异常：")
        traceback.print_exc()
    finally:
        _lock.release()


def on_enter():
    """Run one conversion without ever blocking the global keyboard hook."""
    try:
        allowed = core._active_process_allowed() if _enabled else False
        if not _enabled or not allowed:
            keyboard.send("enter")
            return

        # A hung native call used to keep this lock forever while every later
        # Enter created another blocked daemon thread.  Do not build that queue.
        if not _lock.acquire(blocking=False):
            print("[加喵] 上一次处理尚未结束，本次 Enter 已忽略")
            return
        try:
            threading.Thread(target=_run, daemon=True).start()
        except Exception:
            _lock.release()
            raise
    except Exception:
        print("[加喵] Enter 回调异常：")
        traceback.print_exc()


def toggle():
    """Ctrl+Alt+X 暂停/恢复"""
    global _enabled
    _enabled = not _enabled
    print(f"[加喵] {'已恢复' if _enabled else '已暂停（Enter 恢复原始行为）'}")


_intercepted_enters = set()


def _handle_enter(event):
    # Match the physical key directly: a missed key-up in keyboard's cached
    # pressed-key set must not disable Enter interception.
    if event.event_type == keyboard.KEY_DOWN:
        if (
            any(
                ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000
                for vk in (0x10, 0x11, 0x12, 0x5B, 0x5C)
            )
            or is_ime_candidate_open()
        ):
            _intercepted_enters.discard(event.scan_code)
            return True
        _intercepted_enters.add(event.scan_code)
        on_enter()
        return False
    if event.scan_code in _intercepted_enters:
        _intercepted_enters.remove(event.scan_code)
        return False
    return True


def _handle_pause(event):
    # Use Windows' current modifier state, not keyboard's cached combinations.
    if (event.event_type == keyboard.KEY_DOWN
            and ctypes.windll.user32.GetAsyncKeyState(0x11) & 0x8000
            and ctypes.windll.user32.GetAsyncKeyState(0x12) & 0x8000):
        toggle()
    return True


warmup_ime_detector()
keyboard.hook_key('enter', _handle_enter, suppress=True)
keyboard.hook_key('p', _handle_pause, suppress=True)

print("=" * 40)
print("  加喵发送器已启动")
print("  Enter       → 加喵处理后发送")
print("  Ctrl+Alt+P  → 暂停 / 恢复")
print("  Ctrl+C      → 退出")
print("=" * 40)

try:
    keyboard.wait()
except KeyboardInterrupt:
    print("\n[加喵] 已退出")
    sys.exit(0)
