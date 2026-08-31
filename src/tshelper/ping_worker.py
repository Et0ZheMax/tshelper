"""Изолированный процесс для параллельной проверки доступности компьютеров."""

from __future__ import annotations

import multiprocessing
import platform
import queue
import re
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor


def ping_host(host: str, timeout_ms: int = 1200) -> tuple[bool, str]:
    try:
        if platform.system() == "Windows":
            command = ["ping", "-n", "1", "-w", str(timeout_ms), host]
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            command = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host]
            creationflags = 0
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            creationflags=creationflags,
            timeout=max(1.0, timeout_ms / 1000 + 0.25),
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", output)
        return completed.returncode == 0, match.group(1) if match else ""
    except Exception:
        return False, ""


def ping_candidates(candidates: list[str], timeout_ms: int = 1200) -> dict:
    last_ip = ""
    for host in candidates:
        host = str(host or "").strip()
        if not host:
            continue
        ok, ip = ping_host(host, timeout_ms=timeout_ms)
        if ok:
            return {"completed": True, "ok": True, "host": host, "ip": ip}
        if ip:
            last_ip = ip
    fallback_host = candidates[0] if candidates else ""
    return {"completed": True, "ok": False, "host": fallback_host, "ip": last_ip}


def _ping_process_main(request_queue, result_queue, max_workers: int):
    executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ping-helper")

    def finish(task_id, future):
        try:
            payload = future.result()
        except Exception as exc:
            payload = {"completed": False, "error": str(exc)}
        payload["task_id"] = task_id
        try:
            result_queue.put(payload)
        except Exception:
            pass

    try:
        while True:
            request = request_queue.get()
            if request is None:
                break
            task_id = request["task_id"]
            future = executor.submit(
                ping_candidates,
                request.get("candidates") or [],
                int(request.get("timeout_ms") or 1200),
            )
            future.add_done_callback(lambda done, current_id=task_id: finish(current_id, done))
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


class PingProcessClient:
    """Неблокирующий мост между Tk и постоянным ping-процессом."""

    def __init__(self, master, max_workers: int = 8, poll_ms: int = 20):
        self.master = master
        self.max_workers = max(1, int(max_workers))
        self.poll_ms = max(10, int(poll_ms))
        self.result_batch_size = 8
        self._context = multiprocessing.get_context("spawn")
        self._request_queue = None
        self._result_queue = None
        self._process = None
        self._callbacks = {}
        self._poll_job = None
        self._closed = False
        self._start_process()

    @property
    def is_alive(self) -> bool:
        return bool(self._process and self._process.is_alive())

    def _start_process(self):
        if self._closed or self.is_alive:
            return
        self._request_queue = self._context.Queue(maxsize=max(64, self.max_workers * 16))
        self._result_queue = self._context.Queue(maxsize=max(64, self.max_workers * 16))
        self._process = self._context.Process(
            target=_ping_process_main,
            args=(self._request_queue, self._result_queue, self.max_workers),
            name="TSHelper Ping Helper",
            daemon=True,
        )
        self._process.start()

    def submit(self, candidates: list[str], callback, timeout_ms: int = 1200) -> str:
        if self._closed:
            return ""
        if not self.is_alive:
            self._start_process()
        task_id = uuid.uuid4().hex
        self._callbacks[task_id] = callback
        try:
            self._request_queue.put_nowait({
                "task_id": task_id,
                "candidates": list(candidates),
                "timeout_ms": int(timeout_ms),
            })
        except Exception:
            self._callbacks.pop(task_id, None)
            return ""
        self._schedule_poll()
        return task_id

    def cancel(self, task_id: str):
        self._callbacks.pop(task_id, None)

    def _schedule_poll(self):
        if self._poll_job is None and self._callbacks and not self._closed:
            self._poll_job = self.master.after(self.poll_ms, self._poll_results)

    def _poll_results(self):
        self._poll_job = None
        if self._closed:
            return
        processed = 0
        while processed < self.result_batch_size:
            try:
                result = self._result_queue.get_nowait()
            except queue.Empty:
                break
            except Exception:
                break
            processed += 1
            callback = self._callbacks.pop(result.get("task_id", ""), None)
            if callback:
                callback(result)

        if self._callbacks:
            if not self.is_alive:
                pending = list(self._callbacks.values())
                self._callbacks.clear()
                for callback in pending:
                    callback({"completed": False, "error": "ping-helper завершился"})
            else:
                self._schedule_poll()

    def shutdown(self):
        if self._closed:
            return
        self._closed = True
        if self._poll_job:
            try:
                self.master.after_cancel(self._poll_job)
            except Exception:
                pass
            self._poll_job = None
        self._callbacks.clear()
        try:
            self._request_queue.put_nowait(None)
        except Exception:
            pass
        process = self._process
        if process and process.is_alive():
            process.join(timeout=0.25)
            if process.is_alive():
                process.terminate()
        for channel in (self._request_queue, self._result_queue):
            try:
                channel.close()
                channel.cancel_join_thread()
            except Exception:
                pass
