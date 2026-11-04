from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

# Make the src-layout package importable when launched from source and by PyInstaller.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from antivir.core import analyze_file, quarantine_file, restore_file
from antivir.network import (
    NetworkEvent, NetworkMonitor, block_process_outbound, is_admin,
    unblock_process_outbound,
)
from antivir.threat_intel import COMMON_BEHAVIORS, TRACKED_FAMILIES, SOURCES

APP = "LEDERG ANTIVIR"
BASE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "LEDERG ANTIVIR"
QUARANTINE = BASE / "Quarantine"
BG = "#08090c"
PANEL = "#11141b"
PANEL_ALT = "#171b24"
RED = "#e21d36"
RED_DARK = "#98162a"
TEXT = "#f3f4f6"
MUTED = "#9299a8"
GREEN = "#42d392"
AMBER = "#f2b84b"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP)
        self.geometry("1180x760")
        self.minsize(980, 650)
        self.configure(bg=BG)
        self.records: dict[str, object] = {}
        self.network_count = 0
        self.alert_count = 0
        self.monitor = NetworkMonitor(self._on_network_event, interval=2.5)
        self.monitor.auto_block = False
        self._build_styles()
        self._build_header()
        self._build_stats()
        self._build_actions()
        self._build_tabs()
        self._build_footer()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.monitor.start()
        self.after(900, self._refresh_status)
        self.refresh_quarantine()

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=PANEL, foreground=TEXT, fieldbackground=PANEL,
                        rowheight=31, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=PANEL_ALT, foreground="#c7ccd6",
                        relief="flat", font=("Segoe UI Semibold", 9))
        style.map("Treeview", background=[("selected", RED_DARK)], foreground=[("selected", "white")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL_ALT, foreground=MUTED,
                        padding=(18, 10), font=("Segoe UI Semibold", 9))
        style.map("TNotebook.Tab", background=[("selected", RED_DARK)], foreground=[("selected", "white")])

    def _build_header(self):
        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=24, pady=(18, 10))
        brand = tk.Frame(top, bg=BG)
        brand.pack(side="left")
        tk.Label(brand, text="LEDERG", fg=RED, bg=BG, font=("Segoe UI Black", 23)).pack(anchor="w")
        tk.Label(brand, text="ANTIVIR  /  ENDPOINT DEFENSE", fg=MUTED, bg=BG,
                 font=("Segoe UI Semibold", 9)).pack(anchor="w")
        right = tk.Frame(top, bg=BG)
        right.pack(side="right", anchor="e")
        self.live_label = tk.Label(right, text="● REAL-TIME MONITORING", fg=GREEN, bg=BG,
                                   font=("Segoe UI Semibold", 10))
        self.live_label.pack(anchor="e")
        tk.Label(right, text="Windows 10 / 11  •  x64  •  Local-first", fg=MUTED, bg=BG,
                 font=("Segoe UI", 9)).pack(anchor="e")
        tk.Frame(self, bg=RED, height=2).pack(fill="x", padx=24)

    def _card(self, parent, caption, value, hint, accent):
        card = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground="#242a35")
        tk.Label(card, text=caption.upper(), fg=MUTED, bg=PANEL,
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=14, pady=(12, 2))
        v = tk.Label(card, text=value, fg=accent, bg=PANEL,
                     font=("Segoe UI Semibold", 22))
        v.pack(anchor="w", padx=14)
        tk.Label(card, text=hint, fg=MUTED, bg=PANEL,
                 font=("Segoe UI", 8)).pack(anchor="w", padx=14, pady=(1, 12))
        return card, v

    def _build_stats(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=24, pady=(14, 12))
        cards = [
            ("Сетевые события", "0", "Новые внешние соединения", "#f3f4f6"),
            ("Подозрительные", "0", "Средний и высокий риск", AMBER),
            ("Критические", "0", "Требуют немедленной проверки", RED),
            ("Карантин", "0", "Файлы в изоляции", GREEN),
        ]
        self.stat_values = []
        for i, item in enumerate(cards):
            card, value = self._card(bar, *item)
            card.pack(side="left", fill="both", expand=True, padx=(0 if i == 0 else 9, 0))
            self.stat_values.append(value)

    def _button(self, parent, label, command, primary=False):
        return tk.Button(parent, text=label, command=command, cursor="hand2",
                         bg=RED if primary else PANEL_ALT, fg="white",
                         activebackground="#ff334e" if primary else "#242b38",
                         activeforeground="white", relief="flat", bd=0,
                         font=("Segoe UI Semibold", 9), padx=14, pady=9)

    def _build_actions(self):
        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=24, pady=(0, 12))
        self._button(row, "Быстрая проверка", self.quick_scan, True).pack(side="left", padx=(0, 7))
        self._button(row, "Проверить папку", self.scan_folder).pack(side="left", padx=4)
        self._button(row, "Карантин выбранного", self.quarantine_selected).pack(side="left", padx=4)
        self._button(row, "Блокировать процесс", self.block_selected).pack(side="left", padx=4)
        self._button(row, "Снять блокировку", self.unblock_selected).pack(side="left", padx=4)
        self.auto_var = tk.BooleanVar(value=False)
        self.auto_check = tk.Checkbutton(
            row, text="Автоизоляция известных IOC", variable=self.auto_var,
            command=self._toggle_auto_block, bg=BG, fg=AMBER, selectcolor=PANEL,
            activebackground=BG, activeforeground=AMBER, font=("Segoe UI Semibold", 9),
        )
        self.auto_check.pack(side="right", padx=(8, 0))

    def _build_tabs(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        net_tab = tk.Frame(self.tabs, bg=BG)
        quarantine_tab = tk.Frame(self.tabs, bg=BG)
        intel_tab = tk.Frame(self.tabs, bg=BG)
        self.tabs.add(net_tab, text="  СЕТЕВОЙ МОНИТОР  ")
        self.tabs.add(quarantine_tab, text="  КАРАНТИН  ")
        self.tabs.add(intel_tab, text="  БАЗА УГРОЗ  ")

        tk.Label(net_tab, text="Внешние соединения по процессам", fg=TEXT, bg=BG,
                 font=("Segoe UI Semibold", 12)).pack(anchor="w", padx=4, pady=(8, 3))
        tk.Label(net_tab, text="Отображаются метаданные соединений: PID, приложение, IP и порт. Содержимое HTTPS не читается.",
                 fg=MUTED, bg=BG, font=("Segoe UI", 9)).pack(anchor="w", padx=4, pady=(0, 8))
        cols = ("time", "process", "pid", "destination", "risk", "status", "action")
        self.net_tree = ttk.Treeview(net_tab, columns=cols, show="headings")
        headers = [("time", "Время", 75), ("process", "Процесс", 170), ("pid", "PID", 65),
                   ("destination", "Удалённый адрес", 190), ("risk", "Риск", 85),
                   ("status", "Статус", 100), ("action", "Действие", 300)]
        for key, title, width in headers:
            self.net_tree.heading(key, text=title)
            self.net_tree.column(key, width=width, anchor="w")
        self.net_tree.tag_configure("critical", foreground="#ff586d")
        self.net_tree.tag_configure("high", foreground="#ffbd59")
        self.net_tree.tag_configure("normal", foreground="#d9e0ea")
        self.net_tree.pack(fill="both", expand=True, padx=4, pady=(0, 8))
        self.net_tree.bind("<<TreeviewSelect>>", lambda _e: self._update_action_hint())

        qhead = tk.Frame(quarantine_tab, bg=BG)
        qhead.pack(fill="x", padx=4, pady=8)
        tk.Label(qhead, text="Изолированные объекты", fg=TEXT, bg=BG,
                 font=("Segoe UI Semibold", 12)).pack(side="left")
        self._button(qhead, "Обновить", self.refresh_quarantine).pack(side="right")
        self._button(qhead, "Восстановить выбранное", self.restore_selected).pack(side="right", padx=6)
        qcols = ("file", "hash", "state", "original")
        self.q_tree = ttk.Treeview(quarantine_tab, columns=qcols, show="headings")
        for key, title, width in [("file", "Объект", 250), ("hash", "SHA256", 280),
                                  ("state", "Проверка", 130), ("original", "Исходный путь", 470)]:
            self.q_tree.heading(key, text=title)
            self.q_tree.column(key, width=width, anchor="w")
        self.q_tree.pack(fill="both", expand=True, padx=4, pady=(0, 8))
        self.q_records = {}

        tk.Label(intel_tab, text="Покрытие семейств стиллеров", fg=TEXT, bg=BG,
                 font=("Segoe UI Semibold", 12)).pack(anchor="w", padx=4, pady=(8, 5))
        tk.Label(intel_tab, text="Семейства отслеживаются по открытым отчётам. Это не означает наличие точных сигнатур для каждого образца.",
                 fg=MUTED, bg=BG, font=("Segoe UI", 9), wraplength=1000, justify="left").pack(anchor="w", padx=4, pady=(0, 8))
        intel_box = tk.Text(intel_tab, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat",
                            font=("Segoe UI", 9), wrap="word", padx=14, pady=12)
        intel_box.pack(fill="both", expand=True, padx=4, pady=(0, 8))
        intel_box.insert("end", "СЕМЕЙСТВА\n")
        for family in TRACKED_FAMILIES:
            intel_box.insert("end", f"• {family['name']}  |  {family['platform']}\n  {family['note']}\n  Источник: {family['source']}\n\n")
        intel_box.insert("end", "ПОВЕДЕНЧЕСКИЕ ПРИЗНАКИ\n")
        for behavior in COMMON_BEHAVIORS:
            intel_box.insert("end", f"• {behavior}\n")
        intel_box.insert("end", "\nИСТОЧНИКИ\n")
        for source in SOURCES:
            intel_box.insert("end", f"• {source['name']}: {source['url']}\n")
        intel_box.configure(state="disabled")

    def _build_footer(self):
        self.status = tk.StringVar(value="Мониторинг запускается. Автоблокировка выключена.")
        tk.Label(self, textvariable=self.status, anchor="w", bg="#0f1218", fg=MUTED,
                 padx=14, pady=9, font=("Segoe UI", 9)).pack(fill="x", side="bottom")

    def _toggle_auto_block(self):
        enabled = self.auto_var.get()
        if enabled and not is_admin():
            messagebox.showwarning(APP, "Автоизоляция требует запуска от имени администратора.\nОбычный мониторинг продолжит работать.")
            self.auto_var.set(False)
            return
        self.monitor.auto_block = enabled
        self.status.set("Автоизоляция включена: только точные IOC + активное внешнее соединение." if enabled
                        else "Автоизоляция выключена. Мониторинг продолжает работать.")

    def _on_network_event(self, event: NetworkEvent):
        try:
            self.after(0, lambda e=event: self._insert_network_event(e))
        except RuntimeError:
            pass

    def _insert_network_event(self, event: NetworkEvent):
        self.network_count += 1
        destination = f"{event.remote_address}:{event.remote_port}"
        reasons = "; ".join(event.reasons) if event.reasons else "Внешнее соединение"
        if event.auto_block_eligible:
            reasons += " | IOC: совпадение сильных индикаторов"
        iid = self.net_tree.insert(
            "", "end",
            values=(event.timestamp, event.process_name, event.pid, destination,
                    f"{event.score}/100", event.status, f"{event.action} — {reasons}"),
            tags=("critical" if event.score >= 80 else "high" if event.score >= 35 else "normal",),
        )
        self.records[iid] = event
        children = self.net_tree.get_children()
        if len(children) > 300:
            old = children[0]
            self.net_tree.delete(old)
            self.records.pop(old, None)
        self.net_tree.yview_moveto(1)
        suspicious = sum(1 for item in self.records.values() if isinstance(item, NetworkEvent) and item.score >= 35)
        critical = sum(1 for item in self.records.values() if isinstance(item, NetworkEvent) and item.score >= 80)
        self.stat_values[0].configure(text=str(self.network_count))
        self.stat_values[1].configure(text=str(suspicious))
        self.stat_values[2].configure(text=str(critical))
        self._update_action_hint()
        if event.score >= 80:
            self.status.set(f"КРИТИЧЕСКИЙ СИГНАЛ: {event.process_name} → {destination}. {reasons}")

    def _update_action_hint(self):
        selected = self.net_tree.selection()
        if selected:
            event = self.records.get(selected[0])
            if isinstance(event, NetworkEvent):
                self.status.set(f"Выбран процесс {event.process_name} (PID {event.pid}); файл: {event.process_path or 'путь недоступен'}")

    def _refresh_status(self):
        if not self.winfo_exists():
            return
        if self.monitor.last_error:
            self.live_label.configure(text="● МОНИТОРИНГ: ОГРАНИЧЕН", fg=AMBER)
            self.status.set(f"Нет полного доступа к сетевой таблице: {self.monitor.last_error}. Запусти приложение с правами администратора.")
        else:
            self.live_label.configure(text="● REAL-TIME MONITORING", fg=GREEN)
        self.after(3000, self._refresh_status)

    def _scan_add(self, result):
        iid = self.net_tree.insert(
            "", "end",
            values=("SCAN", result.path.name, "—", result.sha256[:20] + "…",
                    f"{result.score}/100", "Файл",
                    "; ".join(result.reasons) or "Явных индикаторов по локальным правилам не найдено"),
            tags=("critical" if result.score >= 80 else "high" if result.score >= 35 else "normal",),
        )
        self.records[iid] = result
        self.net_tree.yview_moveto(1)

    def quick_scan(self):
        candidates = [
            Path.home() / "Desktop",
            Path.home() / "Downloads",
            Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Temp",
            Path(os.environ.get("APPDATA", Path.home())),
        ]
        self._scan_roots(candidates)

    def scan_folder(self):
        folder = filedialog.askdirectory(title="Выберите папку для проверки")
        if folder:
            self._scan_roots([Path(folder)])

    def _scan_roots(self, roots):
        def worker():
            count = 0
            for root in roots:
                if not root.exists():
                    continue
                for current, dirs, files in os.walk(root):
                    dirs[:] = [d for d in dirs if d.lower() not in {"node_modules", ".git", "__pycache__"}]
                    for name in files:
                        if Path(name).suffix.lower() not in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1"}:
                            continue
                        try:
                            result = analyze_file(Path(current) / name)
                            self.after(0, lambda r=result: self._scan_add(r))
                            count += 1
                        except (OSError, ValueError):
                            continue
            self.after(0, lambda n=count: self.status.set(f"Проверка завершена. Файлов проверено: {n}. Автоматического удаления нет."))
        threading.Thread(target=worker, name="LEDERG-FileScan", daemon=True).start()
        self.status.set("Идёт проверка файлов…")

    def _selected_record(self):
        selected = self.net_tree.selection()
        return self.records.get(selected[0]) if selected else None

    def quarantine_selected(self):
        record = self._selected_record()
        if not hasattr(record, "sha256") or not hasattr(record, "path"):
            messagebox.showinfo(APP, "Выбери строку сканирования файла, а не сетевое соединение.")
            return
        if not messagebox.askyesno(APP, f"Переместить файл в карантин?\n\n{record.path}\nSHA256: {record.sha256}"):
            return
        try:
            item = quarantine_file(record.path, QUARANTINE)
            self.status.set(f"Файл изолирован и проверен по SHA256: {item.sha256}")
            self.refresh_quarantine()
        except Exception as exc:
            messagebox.showerror(APP, str(exc))

    def block_selected(self):
        event = self._selected_record()
        if not isinstance(event, NetworkEvent) or not event.process_path:
            messagebox.showinfo(APP, "Выбери сетевое событие, для которого доступен путь процесса.")
            return
        if not messagebox.askyesno(APP, f"Заблокировать ВСЕ исходящие соединения этого приложения?\n\n{event.process_path}\n\nБудет добавлено точечное правило Windows Firewall."):
            return
        try:
            message = block_process_outbound(Path(event.process_path))
            event.action = message
            self.status.set(message)
            self._insert_action_update(event)
        except Exception as exc:
            messagebox.showerror(APP, str(exc))

    def unblock_selected(self):
        event = self._selected_record()
        if not isinstance(event, NetworkEvent) or not event.process_path:
            messagebox.showinfo(APP, "Выбери сетевое событие с доступным путём процесса.")
            return
        if not messagebox.askyesno(APP, f"Снять созданное LEDERG ANTIVIR правило блокировки для:\n{event.process_path}?"):
            return
        try:
            message = unblock_process_outbound(Path(event.process_path))
            event.action = message
            self.status.set(message)
            self._insert_action_update(event)
        except Exception as exc:
            messagebox.showerror(APP, str(exc))

    def _insert_action_update(self, event):
        for iid, record in self.records.items():
            if record is event:
                values = list(self.net_tree.item(iid, "values"))
                values[6] = event.action
                self.net_tree.item(iid, values=values)
                break

    def refresh_quarantine(self):
        QUARANTINE.mkdir(parents=True, exist_ok=True)
        for iid in self.q_tree.get_children():
            self.q_tree.delete(iid)
        self.q_records.clear()
        import hashlib
        import json
        for metadata in QUARANTINE.glob("*.quarantined.json"):
            try:
                data = json.loads(metadata.read_text(encoding="utf-8"))
                item_path = Path(data.get("quarantined_path", ""))
                if not item_path.is_file():
                    continue
                digest_obj = hashlib.sha256()
                with item_path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest_obj.update(chunk)
                digest = digest_obj.hexdigest()
                valid = digest == data.get("sha256")
                iid = self.q_tree.insert("", "end", values=(
                    item_path.name, digest[:26] + "…",
                    "Хеш подтверждён" if valid else "ОШИБКА ХЕША",
                    data.get("original_path", ""),
                ))
                self.q_records[iid] = (item_path, metadata, Path(data.get("original_path", "")), valid)
            except Exception:
                continue
        self.stat_values[3].configure(text=str(len(self.q_records)))

    def restore_selected(self):
        selected = self.q_tree.selection()
        if not selected:
            messagebox.showinfo(APP, "Выбери объект в карантине.")
            return
        item_path, metadata, original, valid = self.q_records[selected[0]]
        if not valid:
            messagebox.showerror(APP, "Хеш не совпадает. Восстановление запрещено.")
            return
        if original.exists():
            destination = filedialog.asksaveasfilename(title="Выбери новое место восстановления",
                                                       initialfile=original.name)
            if not destination:
                return
            destination = Path(destination)
        else:
            destination = original
        if not messagebox.askyesno(APP, f"Восстановить файл?\n\n{item_path.name}\nВ: {destination}\n\nЗапускай восстановленный файл только если полностью ему доверяешь."):
            return
        try:
            restore_file(item_path, metadata, destination)
            self.status.set(f"Объект восстановлен: {destination}")
            self.refresh_quarantine()
        except Exception as exc:
            messagebox.showerror(APP, str(exc))

    def _close(self):
        self.monitor.stop()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
