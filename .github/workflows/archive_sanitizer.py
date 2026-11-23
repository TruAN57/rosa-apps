#!/usr/bin/env python3
import os
import shutil
import subprocess
import threading
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext, messagebox

class ArchiveSanitizerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Санитар Архива — Антивирусная проверка целостности")
        self.root.geometry("760x540")
        self.root.resizable(True, True)

        self.is_running = False
        self.stop_requested = False

        self.source_var = tk.StringVar()
        self.quarantine_var = tk.StringVar(value=os.path.expanduser("~/Archive_Quarantine"))

        self._build_ui()

    def _build_ui(self):
        pad = {'padx': 10, 'pady': 5}

        frame_paths = ttk.LabelFrame(self.root, text="Параметры сканирования")
        frame_paths.pack(fill="x", **pad)

        ttk.Label(frame_paths, text="Проверяемый диск / папка:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(frame_paths, textvariable=self.source_var, width=55).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame_paths, text="Обзор...", command=self.select_source).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(frame_paths, text="Папка карантина (битые):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(frame_paths, textvariable=self.quarantine_var, width=55).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame_paths, text="Обзор...", command=self.select_quarantine).grid(row=1, column=2, padx=5, pady=5)

        frame_ctrl = ttk.Frame(self.root)
        frame_ctrl.pack(fill="x", **pad)

        self.btn_start = ttk.Button(frame_ctrl, text="▶ Запустить проверку", command=self.start_scan)
        self.btn_start.pack(side="left", padx=5)

        self.btn_stop = ttk.Button(frame_ctrl, text="⏹ Остановить", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=5)

        self.stats_label = ttk.Label(frame_ctrl, text="Проверено: 0 | Дефектных: 0", font=("Sans", 10, "bold"))
        self.stats_label.pack(side="right", padx=10)

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=2)

        frame_log = ttk.LabelFrame(self.root, text="Журнал проверки (найденные дефекты и сбойные сектора)")
        frame_log.pack(fill="both", expand=True, **pad)

        self.log_area = scrolledtext.ScrolledText(frame_log, state="disabled", font=("Monospace", 9))
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)

    def select_source(self):
        path = filedialog.askdirectory(title="Выберите диск или папку для проверки")
        if path:
            self.source_var.set(path)

    def select_quarantine(self):
        path = filedialog.askdirectory(title="Выберите папку для карантина")
        if path:
            self.quarantine_var.set(path)

    def log(self, message):
        self.log_area.configure(state="normal")
        self.log_area.insert("end", message + "\n")
        self.log_area.see("end")
        self.log_area.configure(state="disabled")

    def start_scan(self):
        src = self.source_var.get().strip()
        dst = self.quarantine_var.get().strip()
        if not src or not os.path.isdir(src):
            messagebox.showerror("Ошибка", "Укажите существующий каталог или диск для проверки!")
            return
        os.makedirs(dst, exist_ok=True)

        self.is_running = True
        self.stop_requested = False
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.progress.start(10)

        threading.Thread(target=self.scan_worker, args=(src, dst), daemon=True).start()

    def stop_scan(self):
        self.stop_requested = True
        self.log("[!] Запрошена остановка проверки...")

    def check_file(self, filepath):
        if os.path.getsize(filepath) == 0:
            return "Пустой файл (0 байт)"

        try:
            with open(filepath, "rb") as f:
                while f.read(1024 * 1024):
                    pass
        except OSError as e:
            return f"Сбойный сектор / Ошибка чтения ({e.strerror})"

        _, raw_ext = os.path.splitext(filepath)
        ext = raw_ext.lower()

        try:
            mime = subprocess.check_output(["file", "-b", "--mime-type", filepath], stderr=subprocess.DEVNULL).decode().strip()
        except Exception:
            mime = ""

        if ext in (".jpg", ".jpeg"):
            if mime and mime != "image/jpeg":
                return f"Подмена формата: расширение {ext}, внутри {mime}"
            if subprocess.call(["jpeginfo", "-c", filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                return "Поврежденный или обрезанный JPEG"

        elif ext in (".png", ".webp", ".tif", ".tiff", ".bmp"):
            if mime and not mime.startswith("image/"):
                return f"Подмена формата: расширение {ext}, внутри {mime}"
            if subprocess.call(["identify", "-regard-warnings", filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                return f"Поврежденное изображение ({ext})"

        elif ext == ".mp3":
            res = subprocess.run(["mp3val", filepath], capture_output=True, text=True)
            for line in (res.stdout + res.stderr).splitlines():
                if "WARNING" in line or "PROBLEM" in line:
                    return f"Дефект MP3 (мешанина/обрыв): {line.strip()}"

        elif ext == ".flac":
            if subprocess.call(["flac", "-t", "-s", filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                return "Битый поток FLAC"

        elif ext in (".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".m4a", ".ogg", ".wav"):
            if subprocess.call(["ffmpeg", "-v", "error", "-i", filepath, "-f", "null", "-"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                return f"Поврежденный медиапоток ({ext})"

        elif ext in (".zip", ".rar", ".7z"):
            if subprocess.call(["7z", "t", filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                return f"Битый архив ({ext})"

        elif ext == ".pdf":
            if subprocess.call(["pdfinfo", filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                return "Поврежденный PDF"

        return None

    def quarantine(self, filepath, src_root, dst_root, reason, report_path):
        rel_path = os.path.relpath(filepath, src_root)
        target_path = os.path.join(dst_root, rel_path)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        try:
            shutil.copy2(filepath, target_path)
        except Exception:
            subprocess.call(["dd", f"if={filepath}", f"of={target_path}", "conv=noerror,sync", "status=none"])

        with open(report_path, "a", encoding="utf-8") as rep:
            rep.write(f"{filepath}  --->  [{reason}]\n")

    def scan_worker(self, src, dst):
        report_path = os.path.join(dst, f"defect_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(report_path, "w", encoding="utf-8") as rep:
            rep.write(f"=== ОТЧЕТ ПРОВЕРКИ ЦЕЛОСТНОСТИ ===\nИсточник: {src}\nДата: {datetime.now()}\n==================================\n")

        total = 0
        bad = 0
        self.root.after(0, self.log, f"Старт проверки: {src}\nОтчет: {report_path}\n" + "-"*50)

        for root_dir, _, files in os.walk(src):
            if self.stop_requested:
                break
            for fname in files:
                if self.stop_requested:
                    break
                fpath = os.path.join(root_dir, fname)
                total += 1
                reason = self.check_file(fpath)
                if reason:
                    bad += 1
                    self.quarantine(fpath, src, dst, reason, report_path)
                    self.root.after(0, self.log, f"[ДЕФЕКТ] {fpath}\n   └─ Причина: {reason}")

                if total % 50 == 0 or reason:
                    self.root.after(0, self.stats_label.configure, {"text": f"Проверено: {total} | Дефектных: {bad}"})

        self.root.after(0, self.finish_scan, total, bad, report_path)

    def finish_scan(self, total, bad, report_path):
        self.progress.stop()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.is_running = False
        self.stats_label.configure(text=f"Проверено: {total} | Дефектных: {bad}")
        self.log("-" * 50 + f"\nГотово! Всего: {total} | Дефектных: {bad}\nПолный отчет сохранен в: {report_path}")
        messagebox.showinfo("Проверка завершена", f"Проверено файлов: {total}\nНайдено дефектных: {bad}\n\nОтчет: {report_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ArchiveSanitizerApp(root)
    root.mainloop()
