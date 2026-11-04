from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

# Make the src-layout package importable from source and the PyInstaller executable.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from antivir.core import ScanResult, analyze_file, is_exact_ioc_file, quarantine_file, restore_file
from antivir.defender import get_defender_status, start_defender_scan
from antivir.network import (
    TRUSTED_APP_RULES, NetworkEvent, NetworkMonitor, block_process_outbound,
    is_admin, unblock_process_outbound,
)
from antivir.protection import ProtectionCheck, get_security_posture
from antivir.threat_intel import (
    ATTACK_TECHNIQUES, COMMON_BEHAVIORS, PROTECTION_GUIDANCE,
    COMMON_SERVICE_DOMAINS, SOURCES, THREAT_FEEDS, TRACKED_FAMILIES,
)

APP = "LEDERG ANTIVIR"
BASE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "LEDERG ANTIVIR"
QUARANTINE = BASE / "Quarantine"

BG = "#080a0f"
SIDEBAR = "#0b0e15"
PANEL = "#111722"
PANEL_ALT = "#171e2a"
PANEL_SOFT = "#0e131c"
BORDER = "#242e3d"
RED = "#ed233e"
RED_HOVER = "#ff3d55"
RED_DARK = "#681b2b"
TEXT = "#f4f6fa"
MUTED = "#8e99aa"
GREEN = "#43d99a"
AMBER = "#f2b84b"
BLUE = "#79a7ff"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP)
        self.geometry("1360x860")
        self.minsize(1080, 720)
        self.configure(bg=BG)

        self.network_events: list[NetworkEvent] = []
        self.scan_results: list[ScanResult] = []
        self.network_count = 0
        self.auto_protect_enabled = False
        self.net_rows: dict[str, NetworkEvent] = {}
        self.scan_rows: dict[str, ScanResult] = {}
        self.q_records: dict[str, tuple[Path, Path, Path, bool]] = {}
        self.nav_buttons: dict[str, tk.Button] = {}
        self.stat_values: list[tk.Label] = []
        self.monitor = NetworkMonitor(self._on_network_event, interval=2.5, quarantine_dir=QUARANTINE)
        self.monitor.auto_block = False
        self.monitor.auto_quarantine = False

        self._build_styles()
        self._build_shell()
        self.show_page("home")
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.monitor.start()
        self.after(800, self._refresh_status)
        self.after(1400, self._refresh_defender_status_async)
        self.after(1800, self._refresh_quarantine_count)

    def _build_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Treeview", background=PANEL_SOFT, foreground=TEXT, fieldbackground=PANEL_SOFT,
            rowheight=34, borderwidth=0, font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading", background=PANEL_ALT, foreground="#c8d0dc",
            relief="flat", borderwidth=0, font=("Segoe UI Semibold", 9), padding=(10, 9),
        )
        style.map(
            "Treeview",
            background=[("selected", RED_DARK)],
            foreground=[("selected", "white")],
        )
        style.configure("TProgressbar", troughcolor=PANEL_ALT, background=RED, bordercolor=PANEL_ALT)
        style.configure(
            "Vertical.TScrollbar", background=PANEL_ALT, troughcolor=PANEL_SOFT,
            bordercolor=PANEL_SOFT, arrowcolor=MUTED,
        )

    def _button(self, parent, label, command, primary=False, compact=False, danger=False):
        background = RED if primary else RED_DARK if danger else PANEL_ALT
        active = RED_HOVER if primary else "#86283a" if danger else "#263244"
        return tk.Button(
            parent, text=label, command=command, cursor="hand2",
            bg=background, fg="white", activebackground=active, activeforeground="white",
            relief="flat", bd=0, highlightthickness=0,
            font=("Segoe UI Semibold", 10 if not compact else 9),
            padx=18 if not compact else 13, pady=12 if not compact else 8,
        )

    def _shield(self, parent, size=74, background=PANEL):
        canvas = tk.Canvas(parent, width=size, height=size, bg=background, highlightthickness=0)
        pad = size * 0.12
        points = [
            size * .5, pad,
            size * .82, size * .25,
            size * .77, size * .62,
            size * .5, size * .88,
            size * .23, size * .62,
            size * .18, size * .25,
        ]
        canvas.create_polygon(points, fill="#24101a", outline=RED, width=max(2, int(size * .035)))
        canvas.create_line(size*.32, size*.49, size*.44, size*.61, size*.69, size*.35,
                           fill=RED_HOVER, width=max(3, int(size*.055)), capstyle="round", joinstyle="round")
        return canvas

    def _build_shell(self):
        self.shell = tk.Frame(self, bg=BG)
        self.shell.pack(fill="both", expand=True)

        sidebar = tk.Frame(self.shell, bg=SIDEBAR, width=228, highlightthickness=1, highlightbackground="#1a202b")
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        brand = tk.Frame(sidebar, bg=SIDEBAR)
        brand.pack(fill="x", padx=18, pady=(22, 28))
        self._shield(brand, 58, SIDEBAR).pack(side="left", padx=(0, 11))
        brand_text = tk.Frame(brand, bg=SIDEBAR)
        brand_text.pack(side="left", anchor="center")
        tk.Label(brand_text, text="LEDERG", bg=SIDEBAR, fg=RED,
                 font=("Segoe UI Black", 20)).pack(anchor="w")
        tk.Label(brand_text, text="ANTIVIR", bg=SIDEBAR, fg=TEXT,
                 font=("Segoe UI Semibold", 9)).pack(anchor="w")
        tk.Label(sidebar, text="ПАНЕЛЬ УПРАВЛЕНИЯ", bg=SIDEBAR, fg="#596577",
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=20, pady=(0, 9))

        nav_items = [
            ("home", "◈", "Обзор"),
            ("network", "⌁", "Сеть и процессы"),
            ("quarantine", "▣", "Карантин"),
            ("protection", "⬟", "Центр защиты"),
            ("threats", "⌘", "База угроз"),
            ("trusted", "✓", "Доверенные приложения"),
        ]
        for key, icon, title in nav_items:
            button = tk.Button(
                sidebar, text=f"  {icon}    {title}", anchor="w",
                command=lambda page=key: self.show_page(page),
                bg=SIDEBAR, fg="#aeb8c8", activebackground=PANEL_ALT, activeforeground=TEXT,
                relief="flat", bd=0, padx=17, pady=14, cursor="hand2",
                font=("Segoe UI Semibold", 10),
            )
            button.pack(fill="x", padx=9, pady=2)
            self.nav_buttons[key] = button

        spacer = tk.Frame(sidebar, bg=SIDEBAR)
        spacer.pack(fill="both", expand=True)
        profile = tk.Frame(sidebar, bg="#101722", highlightthickness=1, highlightbackground=BORDER)
        profile.pack(fill="x", padx=12, pady=16)
        avatar = tk.Canvas(profile, width=38, height=38, bg="#101722", highlightthickness=0)
        avatar.pack(side="left", padx=10, pady=10)
        avatar.create_oval(2, 2, 36, 36, fill="#25101a", outline=RED, width=2)
        avatar.create_text(19, 19, text="L", fill=TEXT, font=("Segoe UI Black", 18))
        profile_text = tk.Frame(profile, bg="#101722")
        profile_text.pack(side="left")
        tk.Label(profile_text, text="LEDERG SHIELD", bg="#101722", fg=TEXT,
                 font=("Segoe UI Semibold", 8)).pack(anchor="w")
        tk.Label(profile_text, text="LOCAL PROTECTION", bg="#101722", fg=MUTED,
                 font=("Segoe UI", 7)).pack(anchor="w")

        workspace = tk.Frame(self.shell, bg=BG)
        workspace.pack(side="left", fill="both", expand=True)
        header = tk.Frame(workspace, bg=BG)
        header.pack(fill="x", padx=28, pady=(22, 14))
        left = tk.Frame(header, bg=BG)
        left.pack(side="left")
        self.page_title = tk.Label(left, text="ОБЗОР СИСТЕМЫ", bg=BG, fg=TEXT,
                                   font=("Segoe UI Semibold", 20))
        self.page_title.pack(anchor="w")
        self.page_subtitle = tk.Label(left, text="Главная панель безопасности", bg=BG, fg=MUTED,
                                      font=("Segoe UI", 9))
        self.page_subtitle.pack(anchor="w", pady=(3, 0))
        right = tk.Frame(header, bg=BG)
        right.pack(side="right", anchor="e")
        self.live_label = tk.Label(right, text="● МОНИТОРИНГ АКТИВЕН", bg=BG, fg=GREEN,
                                   font=("Segoe UI Semibold", 9))
        self.live_label.pack(anchor="e")
        self.defender_label = tk.Label(right, text="Microsoft Defender: проверка статуса…",
                                       bg=BG, fg=MUTED, font=("Segoe UI", 9))
        self.defender_label.pack(anchor="e", pady=(5, 0))

        tk.Frame(workspace, bg=RED, height=2).pack(fill="x", padx=28, pady=(0, 16))
        self.page_host = tk.Frame(workspace, bg=BG)
        self.page_host.pack(fill="both", expand=True, padx=28, pady=(0, 14))
        footer = tk.Frame(workspace, bg="#0e131c", height=38)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        self.status = tk.StringVar(value="Защита запущена. Нажми «Проверить систему» для анализа.")
        tk.Label(footer, textvariable=self.status, anchor="w", bg="#0e131c", fg=MUTED,
                 padx=14, font=("Segoe UI", 9)).pack(fill="both", expand=True)

    def show_page(self, page: str):
        for child in self.page_host.winfo_children():
            child.destroy()
        for key, button in self.nav_buttons.items():
            button.configure(bg=RED_DARK if key == page else SIDEBAR,
                             fg="white" if key == page else "#aeb8c8")
        headings = {
            "home": ("ОБЗОР СИСТЕМЫ", "Проверка, состояние защиты и последние результаты"),
            "network": ("СЕТЬ И ПРОЦЕССЫ", "Контроль внешних соединений и действий приложений"),
            "quarantine": ("КАРАНТИН", "Изолированные файлы с проверкой целостности SHA-256"),
            "protection": ("ЦЕНТР ЗАЩИТЫ", "Состояние встроенных механизмов безопасности Windows"),
            "threats": ("БАЗА УГРОЗ", "Семейства стиллеров, техники атак и источники данных"),
            "trusted": ("ДОВЕРЕННЫЕ ПРИЛОЖЕНИЯ", "Проверка издателя и пути вместо слепого доверия имени или домену"),
        }
        title, subtitle = headings[page]
        self.page_title.configure(text=title)
        self.page_subtitle.configure(text=subtitle)
        builders = {
            "home": self._build_home_page,
            "network": self._build_network_page,
            "quarantine": self._build_quarantine_page,
            "protection": self._build_protection_page,
            "threats": self._build_threat_page,
            "trusted": self._build_trusted_page,
        }
        builders[page]()
        if page == "protection":
            self._refresh_protection_async()

    def _build_home_page(self):
        self.stat_values = []
        hero = tk.Frame(self.page_host, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        hero.pack(fill="x", pady=(0, 15))
        hero.grid_columnconfigure(0, weight=1)
        hero.grid_columnconfigure(1, weight=0)
        left = tk.Frame(hero, bg=PANEL)
        left.grid(row=0, column=0, sticky="nsew", padx=25, pady=22)
        tk.Label(left, text="LEDERG  /  ENDPOINT DEFENSE", bg=PANEL, fg=RED,
                 font=("Segoe UI Semibold", 9)).pack(anchor="w")
        self.hero_status = tk.Label(left, text="СИСТЕМА ГОТОВА К ПРОВЕРКЕ", bg=PANEL, fg=TEXT,
                                    font=("Segoe UI Black", 22))
        self.hero_status.pack(anchor="w", pady=(9, 4))
        tk.Label(left, text="Одна кнопка проверит важные пользовательские папки и запустит\n"
                            "быструю проверку Microsoft Defender. Критические точные IOC\n"
                            "можно автоматически остановить и отправить в карантин.",
                 bg=PANEL, fg=MUTED, justify="left", font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 16))
        actions = tk.Frame(left, bg=PANEL)
        actions.pack(anchor="w")
        self.scan_button = self._button(actions, "⛨  ПРОВЕРИТЬ СИСТЕМУ", self.quick_scan, primary=True)
        self.scan_button.pack(side="left", padx=(0, 10))
        self.auto_button = self._button(actions, "АВТОЗАЩИТА: ВЫКЛ", self._toggle_auto_protection)
        self.auto_button.pack(side="left")
        self.scan_progress = ttk.Progressbar(left, mode="indeterminate", length=450)
        self.scan_progress.pack(anchor="w", fill="x", pady=(15, 0))
        self.scan_progress.stop()

        right = tk.Frame(hero, bg=PANEL)
        right.grid(row=0, column=1, sticky="e", padx=28, pady=20)
        shield = tk.Canvas(right, width=150, height=150, bg=PANEL, highlightthickness=0)
        shield.pack()
        points = [75, 12, 126, 33, 119, 92, 75, 136, 31, 92, 24, 33]
        shield.create_polygon(points, fill="#25101a", outline=RED, width=3)
        shield.create_oval(43, 44, 107, 108, fill="#111722", outline="#612233", width=2)
        shield.create_text(75, 75, text="L", fill=TEXT, font=("Segoe UI Black", 42))
        tk.Label(right, text="SHIELD ACTIVE", bg=PANEL, fg=GREEN,
                 font=("Segoe UI Semibold", 9)).pack()

        metrics = tk.Frame(self.page_host, bg=BG)
        metrics.pack(fill="x", pady=(0, 15))
        items = [
            ("СЕТЕВЫЕ СОБЫТИЯ", "0", "Новые внешние подключения", TEXT),
            ("СИГНАЛЫ", "0", "Требуют внимания", AMBER),
            ("КРИТИЧЕСКИЕ", "0", "Точные совпадения IOC", RED),
            ("КАРАНТИН", "0", "Изолированные объекты", GREEN),
        ]
        for index, (caption, value, hint, accent) in enumerate(items):
            card = tk.Frame(metrics, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
            card.pack(side="left", fill="both", expand=True, padx=(0 if index == 0 else 10, 0))
            tk.Label(card, text=caption, bg=PANEL, fg=MUTED,
                     font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=15, pady=(12, 3))
            value_label = tk.Label(card, text=value, bg=PANEL, fg=accent,
                                   font=("Segoe UI Semibold", 23))
            value_label.pack(anchor="w", padx=15)
            tk.Label(card, text=hint, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 8)).pack(anchor="w", padx=15, pady=(0, 12))
            self.stat_values.append(value_label)
        self._update_stats_display()

        lower = tk.Frame(self.page_host, bg=BG)
        lower.pack(fill="both", expand=True)
        lower.grid_columnconfigure(0, weight=3)
        lower.grid_columnconfigure(1, weight=2)
        result_panel = tk.Frame(lower, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        result_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        result_head = tk.Frame(result_panel, bg=PANEL)
        result_head.pack(fill="x", padx=16, pady=(14, 10))
        tk.Label(result_head, text="РЕЗУЛЬТАТЫ ПРОВЕРКИ", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 10)).pack(side="left")
        self._button(result_head, "Поместить выбранное в карантин", self.quarantine_selected, compact=True).pack(side="right")
        columns = ("time", "file", "risk", "state", "details")
        self.scan_tree = ttk.Treeview(result_panel, columns=columns, show="headings", height=7)
        for key, title, width in [
            ("time", "Время", 64), ("file", "Файл", 160), ("risk", "Риск", 65),
            ("state", "Состояние", 95), ("details", "Что найдено", 330),
        ]:
            self.scan_tree.heading(key, text=title)
            self.scan_tree.column(key, width=width, anchor="w")
        self.scan_tree.tag_configure("critical", foreground="#ff5b71")
        self.scan_tree.tag_configure("warning", foreground=AMBER)
        self.scan_tree.tag_configure("clean", foreground="#c7d2df")
        self.scan_tree.pack(fill="both", expand=True, padx=10, pady=(0, 12))
        self.scan_rows = {}
        for result in self.scan_results[-250:]:
            self._insert_scan_row(result)

        quick = tk.Frame(lower, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        quick.grid(row=0, column=1, sticky="nsew")
        tk.Label(quick, text="БЫСТРЫЕ ДЕЙСТВИЯ", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 10)).pack(anchor="w", padx=16, pady=(14, 12))
        self._button(quick, "Полная проверка Microsoft Defender", self.full_defender_scan).pack(fill="x", padx=14, pady=5)
        self._button(quick, "Проверить выбранную папку", self.scan_folder).pack(fill="x", padx=14, pady=5)
        self._button(quick, "Открыть сетевой монитор", lambda: self.show_page("network")).pack(fill="x", padx=14, pady=5)
        self._button(quick, "Открыть карантин", lambda: self.show_page("quarantine")).pack(fill="x", padx=14, pady=5)
        tk.Label(quick, text="Защита не удаляет файлы по одному\nслабому признаку. Автоизоляция\nсрабатывает только на точные IOC.",
                 bg=PANEL, fg=MUTED, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(15, 10))
        self._sync_auto_button()

    def _build_network_page(self):
        panel = tk.Frame(self.page_host, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        panel.pack(fill="both", expand=True)
        head = tk.Frame(panel, bg=PANEL)
        head.pack(fill="x", padx=16, pady=(14, 8))
        tk.Label(head, text="ЖИВЫЕ СОЕДИНЕНИЯ", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 11)).pack(side="left")
        tk.Label(panel, text="Показываются адреса, порты и процессы. Содержимое HTTPS и пароли не перехватываются.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 8))
        columns = ("time", "process", "pid", "destination", "risk", "status", "action")
        self.net_tree = ttk.Treeview(panel, columns=columns, show="headings")
        for key, title, width in [
            ("time", "Время", 75), ("process", "Приложение", 170), ("pid", "PID", 65),
            ("destination", "Удалённый IP:порт", 185), ("risk", "Риск", 75),
            ("status", "Статус", 95), ("action", "Оценка / действие", 410),
        ]:
            self.net_tree.heading(key, text=title)
            self.net_tree.column(key, width=width, anchor="w")
        self.net_tree.tag_configure("critical", foreground="#ff5b71")
        self.net_tree.tag_configure("high", foreground=AMBER)
        self.net_tree.tag_configure("trusted", foreground=GREEN)
        self.net_tree.tag_configure("normal", foreground="#d5deeb")
        self.net_tree.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.net_rows = {}
        for event in self.network_events[-300:]:
            self._insert_network_row(event)
        actions = tk.Frame(panel, bg=PANEL)
        actions.pack(fill="x", padx=12, pady=(0, 12))
        self._button(actions, "Блокировать приложение", self.block_selected, danger=True, compact=True).pack(side="left", padx=(0, 8))
        self._button(actions, "Снять LEDERG-блокировку", self.unblock_selected, compact=True).pack(side="left")
        self._button(actions, "Обновить список", lambda: self.show_page("network"), compact=True).pack(side="right")

    def _build_quarantine_page(self):
        panel = tk.Frame(self.page_host, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        panel.pack(fill="both", expand=True)
        head = tk.Frame(panel, bg=PANEL)
        head.pack(fill="x", padx=16, pady=(14, 6))
        tk.Label(head, text="ИЗОЛИРОВАННЫЕ ОБЪЕКТЫ", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 11)).pack(side="left")
        self._button(head, "Обновить", self.refresh_quarantine, compact=True).pack(side="right")
        tk.Label(panel, text="Файлы не запускаются из карантина. Перед восстановлением проверяется совпадение SHA-256.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 9))
        columns = ("file", "hash", "state", "original")
        self.q_tree = ttk.Treeview(panel, columns=columns, show="headings")
        for key, title, width in [
            ("file", "Объект", 245), ("hash", "SHA-256", 255),
            ("state", "Целостность", 140), ("original", "Исходное расположение", 470),
        ]:
            self.q_tree.heading(key, text=title)
            self.q_tree.column(key, width=width, anchor="w")
        self.q_tree.tag_configure("bad", foreground=RED_HOVER)
        self.q_tree.tag_configure("good", foreground=GREEN)
        self.q_tree.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self._button(panel, "Восстановить выбранный файл", self.restore_selected, compact=False).pack(anchor="e", padx=14, pady=(0, 14))
        self.refresh_quarantine()

    def _build_protection_page(self):
        tk.Label(self.page_host, text="СОСТОЯНИЕ ЗАЩИТЫ WINDOWS", bg=BG, fg=TEXT,
                 font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(0, 8))
        tk.Label(self.page_host, text="Эти параметры только читаются. LEDERG ANTIVIR не отключает и не перенастраивает защиту Windows.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 12))
        self.protection_body = tk.Frame(self.page_host, bg=BG)
        self.protection_body.pack(fill="both", expand=True)
        self._button(self.page_host, "Проверить состояние заново", self._refresh_protection_async, compact=True).pack(anchor="e", pady=(8, 0))
        self._render_protection_checks([])

    def _render_protection_checks(self, checks: list[ProtectionCheck]):
        for child in self.protection_body.winfo_children():
            child.destroy()
        if not checks:
            tk.Label(self.protection_body, text="Проверяем настройки безопасности Windows…",
                     bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=10)
            return
        for check in checks:
            card = tk.Frame(self.protection_body, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
            card.pack(fill="x", pady=5)
            row = tk.Frame(card, bg=PANEL)
            row.pack(fill="x", padx=15, pady=(11, 4))
            color = GREEN if check.state == "ON" else AMBER if check.state in {"REVIEW", "ATTENTION", "OPTIONAL"} else MUTED
            tk.Label(row, text=check.name, bg=PANEL, fg=TEXT,
                     font=("Segoe UI Semibold", 10)).pack(side="left")
            tk.Label(row, text=check.state, bg=PANEL, fg=color,
                     font=("Segoe UI Semibold", 9)).pack(side="right")
            tk.Label(card, text=check.detail, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9), wraplength=860, justify="left").pack(anchor="w", padx=15, pady=(0, 4))
            if check.recommendation:
                tk.Label(card, text=check.recommendation, bg=PANEL, fg=AMBER,
                         font=("Segoe UI", 8), wraplength=860, justify="left").pack(anchor="w", padx=15, pady=(0, 11))
            else:
                tk.Frame(card, bg=PANEL, height=5).pack()

    def _build_threat_page(self):
        summary = tk.Frame(self.page_host, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        summary.pack(fill="x", pady=(0, 12))
        tk.Label(summary, text=f"{len(TRACKED_FAMILIES)} семейств и вариантов в справочной базе",
                 bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 13)).pack(anchor="w", padx=16, pady=(13, 4))
        tk.Label(summary, text="Это база контекста и техник атак, а не 25 отдельных сигнатур детектирования.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 13))
        body = tk.Frame(self.page_host, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        body.pack(fill="both", expand=True)
        text = tk.Text(body, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat",
                       font=("Segoe UI", 9), wrap="word", padx=18, pady=14)
        scroll = ttk.Scrollbar(body, orient="vertical", command=text.yview, style="Vertical.TScrollbar")
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)

        text.insert("end", "ОТСЛЕЖИВАЕМЫЕ СЕМЕЙСТВА\n", "heading")
        for family in TRACKED_FAMILIES:
            text.insert("end", f"• {family['name']}  ·  {family['platform']}\n", "family")
            text.insert("end", f"  {family['note']}\n")
            text.insert("end", f"  Источник: {family['source']}\n\n", "link")
        text.insert("end", "\nПОВЕДЕНЧЕСКИЕ ТЕХНИКИ\n", "heading")
        for behavior in COMMON_BEHAVIORS:
            text.insert("end", f"• {behavior}\n")
        text.insert("end", "\nMITRE ATT&CK\n", "heading")
        for item in ATTACK_TECHNIQUES:
            text.insert("end", f"• {item['id']} — {item['name']}  {item['url']}\n", "link")
        text.insert("end", "\nДОПОЛНИТЕЛЬНЫЕ МЕРЫ ЗАЩИТЫ\n", "heading")
        for item in PROTECTION_GUIDANCE:
            text.insert("end", f"• {item['title']}\n", "family")
            text.insert("end", f"  {item['detail']}\n  {item['source']}\n\n", "link")
        text.insert("end", "\nОТКРЫТЫЕ THREAT-INTEL FEEDS\n", "heading")
        for feed in THREAT_FEEDS:
            text.insert("end", f"• {feed['name']} — {feed['type']}\n", "family")
            text.insert("end", f"  {feed['auth']} · {feed['url']}\n\n", "link")
        text.insert("end", "\nВАЖНО: внешние feed API требуют регистрации / API-ключа. В этой версии ссылки и схема источников добавлены, но автоматическое получение их IOCs ещё не подключено.\n", "note")
        text.tag_configure("heading", foreground=RED_HOVER, font=("Segoe UI Semibold", 11))
        text.tag_configure("family", foreground=TEXT, font=("Segoe UI Semibold", 9))
        text.tag_configure("link", foreground=BLUE)
        text.tag_configure("note", foreground=AMBER)
        text.configure(state="disabled")
        text.bind("<Double-Button-1>", lambda _event: self._open_selected_url(text))

    def _open_selected_url(self, widget):
        try:
            index = widget.index("insert")
            line = widget.get(f"{index} linestart", f"{index} lineend")
            for token in line.split():
                if token.startswith("https://"):
                    webbrowser.open(token.rstrip(".,)"))
                    return
        except Exception:
            pass

    def _build_trusted_page(self):
        intro = tk.Frame(self.page_host, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        intro.pack(fill="x", pady=(0, 12))
        tk.Label(intro, text="НЕ ДОВЕРЯЕМ ТОЛЬКО ИМЕНИ ФАЙЛА", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 12)).pack(anchor="w", padx=16, pady=(13, 5))
        tk.Label(intro, text="Opera.exe или Discord.exe считаются обычными только если подпись Windows действительна, издатель ожидаемый и путь совпадает с типовой установкой.",
                 bg=PANEL, fg=MUTED, wraplength=900, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=16, pady=(0, 13))
        panel = tk.Frame(self.page_host, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        panel.pack(fill="x", pady=(0, 12))
        for name, rule in TRUSTED_APP_RULES.items():
            row = tk.Frame(panel, bg=PANEL)
            row.pack(fill="x", padx=16, pady=8)
            tk.Label(row, text=name, bg=PANEL, fg=TEXT,
                     font=("Segoe UI Semibold", 10), width=17, anchor="w").pack(side="left")
            tk.Label(row, text="Издатель: " + ", ".join(rule["publishers"]),
                     bg=PANEL, fg=GREEN, font=("Segoe UI", 9)).pack(side="left", padx=(0, 15))
            tk.Label(panel, text="Ожидаемые пути: " + " / ".join(rule["paths"]),
                     bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=950,
                     justify="left").pack(anchor="w", padx=16, pady=(0, 5))
            tk.Frame(panel, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(2, 0))

        domains_panel = tk.Frame(self.page_host, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        domains_panel.pack(fill="x", pady=(0, 12))
        tk.Label(domains_panel, text="СПРАВОЧНИК ОБЫЧНЫХ СЕРВИСОВ И ДОМЕНОВ",
                 bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 10)).pack(anchor="w", padx=16, pady=(12, 6))
        for service in COMMON_SERVICE_DOMAINS:
            tk.Label(
                domains_panel,
                text=f"{service['service']}:  " + "  ·  ".join(service["domains"]),
                bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=950,
                justify="left",
            ).pack(anchor="w", padx=16, pady=3)
        tk.Label(
            domains_panel,
            text="Это справочник, а не безусловный whitelist: текущий датчик видит IP:порт и не может надёжно связать IP с доменом и конкретным процессом.",
            bg=PANEL, fg=AMBER, font=("Segoe UI", 8), wraplength=950,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(7, 12))

        warning = tk.Frame(self.page_host, bg="#1b1720", highlightthickness=1, highlightbackground="#5d2634")
        warning.pack(fill="x", pady=(0, 10))
        tk.Label(warning, text="ПОЧЕМУ НЕТ ГЛОБАЛЬНОГО СПИСКА «БЕЗОПАСНЫХ ДОМЕНОВ»",
                 bg="#1b1720", fg=AMBER, font=("Segoe UI Semibold", 9)).pack(anchor="w", padx=15, pady=(11, 5))
        tk.Label(warning, text="Общие CDN, облака и IP-адреса часто используются одновременно обычными программами и вредоносной инфраструктурой. "
                              "Кроме того, текущий сетевой датчик видит IP:порт, а не достоверное имя сайта. Поэтому LEDERG снижает ложные тревоги по проверенной подписи приложения, "
                              "но не объявляет весь Cloudflare / Google / Microsoft или любой общий домен безопасным.",
                 bg="#1b1720", fg=MUTED, font=("Segoe UI", 9), wraplength=960,
                 justify="left").pack(anchor="w", padx=15, pady=(0, 12))

    def _sync_auto_button(self):
        try:
            if self.auto_protect_enabled:
                self.auto_button.configure(text="АВТОЗАЩИТА: ВКЛ", bg="#176548", activebackground="#21875f")
            else:
                self.auto_button.configure(text="АВТОЗАЩИТА: ВЫКЛ", bg=PANEL_ALT, activebackground="#263244")
        except (AttributeError, tk.TclError):
            pass

    def _toggle_auto_protection(self):
        if not self.auto_protect_enabled and not is_admin():
            messagebox.showwarning(
                APP,
                "Для автоизоляции нужны права администратора.\n"
                "Обычный мониторинг продолжит работать. Перезапусти LEDERG ANTIVIR от имени администратора.",
            )
            return
        self.auto_protect_enabled = not self.auto_protect_enabled
        self.monitor.auto_block = self.auto_protect_enabled
        self.monitor.auto_quarantine = self.auto_protect_enabled
        self._sync_auto_button()
        if self.auto_protect_enabled:
            self.status.set("АВТОЗАЩИТА ВКЛ: точные IOC → блокировка сети → остановка процесса → карантин файла.")
        else:
            self.status.set("Автозащита выключена. Мониторинг продолжает работать.")

    def _update_stats_display(self):
        suspicious = sum(1 for event in self.network_events if event.score >= 35)
        critical = sum(1 for event in self.network_events if event.score >= 80)
        critical += sum(1 for result in self.scan_results if result.score >= 80)
        values = [self.network_count, suspicious, critical, self._count_quarantine()]
        for label, value in zip(self.stat_values, values):
            try:
                if label.winfo_exists():
                    label.configure(text=str(value))
            except tk.TclError:
                pass

    def _count_quarantine(self):
        try:
            return sum(1 for item in QUARANTINE.glob("*.quarantined.json"))
        except OSError:
            return 0

    def _on_network_event(self, event: NetworkEvent):
        try:
            self.after(0, lambda e=event: self._insert_network_event(e))
        except RuntimeError:
            pass

    def _insert_network_event(self, event: NetworkEvent):
        self.network_count += 1
        self.network_events.append(event)
        self.network_events = self.network_events[-300:]
        if hasattr(self, "net_tree"):
            try:
                if self.net_tree.winfo_exists():
                    self._insert_network_row(event)
            except tk.TclError:
                pass
        self._update_stats_display()
        if event.score >= 80:
            self.hero_status.configure(text="ОБНАРУЖЕН КРИТИЧЕСКИЙ СИГНАЛ", fg=RED_HOVER) if hasattr(self, "hero_status") and self.hero_status.winfo_exists() else None
            self.status.set(f"КРИТИЧЕСКИЙ СИГНАЛ: {event.process_name} → {event.remote_address}:{event.remote_port}")
        elif event.trusted_application:
            self.status.set(f"Доверенное приложение: {event.process_name}. Подпись и путь подтверждены.")
        if "карантин" in event.action.lower():
            self.after(0, self._refresh_quarantine_count)

    def _insert_network_row(self, event: NetworkEvent):
        destination = f"{event.remote_address}:{event.remote_port}"
        reasons = "; ".join(event.reasons) if event.reasons else (
            "Действительная подпись и ожидаемый путь" if event.trusted_application else "Внешнее соединение"
        )
        iid = self.net_tree.insert(
            "", "end",
            values=(event.timestamp, event.process_name, event.pid, destination,
                    f"{event.score}/100", event.status, f"{event.action} — {reasons}"),
            tags=("trusted" if event.trusted_application else "critical" if event.score >= 80
                  else "high" if event.score >= 35 else "normal",),
        )
        self.net_rows[iid] = event
        children = self.net_tree.get_children()
        if len(children) > 300:
            old = children[0]
            self.net_tree.delete(old)
            self.net_rows.pop(old, None)
        self.net_tree.yview_moveto(1)

    def _insert_scan_row(self, result: ScanResult):
        state = "В карантине" if result.quarantined_path else "Найдено" if result.score >= 35 else "Проверено"
        details = "; ".join(result.reasons) if result.reasons else "Явных локальных IOC не найдено"
        iid = self.scan_tree.insert(
            "", "end",
            values=(datetime.now().strftime("%H:%M"),
                    result.path.name, f"{result.score}/100", state, details),
            tags=("critical" if result.score >= 80 else "warning" if result.score >= 35 else "clean",),
        )
        self.scan_rows[iid] = result

    def _scan_add(self, result: ScanResult):
        self.scan_results.append(result)
        self.scan_results = self.scan_results[-300:]
        if hasattr(self, "scan_tree"):
            try:
                if self.scan_tree.winfo_exists():
                    self._insert_scan_row(result)
            except tk.TclError:
                pass
        self._update_stats_display()

    def _refresh_status(self):
        if not self.winfo_exists():
            return
        if self.monitor.last_error:
            self.live_label.configure(text="● МОНИТОРИНГ ОГРАНИЧЕН", fg=AMBER)
            self.status.set(f"Нет полного доступа к сетевым соединениям: {self.monitor.last_error}")
        else:
            self.live_label.configure(text="● МОНИТОРИНГ АКТИВЕН", fg=GREEN)
        self.after(3000, self._refresh_status)

    def quick_scan(self):
        self.scan_button.configure(state="disabled", text="ПРОВЕРКА ВЫПОЛНЯЕТСЯ…")
        self.hero_status.configure(text="ИДЁТ ПРОВЕРКА СИСТЕМЫ", fg=AMBER)
        self.scan_progress.start(12)
        try:
            pid = start_defender_scan("QuickScan")
            self.status.set(f"Microsoft Defender: быстрая проверка запущена (PID {pid}).")
        except Exception as exc:
            self.status.set(f"Defender Quick Scan недоступен: {exc}. Продолжаю локальную проверку.")
        local_appdata = Path(os.environ.get("LOCALAPPDATA", Path.home()))
        appdata = Path(os.environ.get("APPDATA", Path.home()))
        program_data = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
        candidates = [
            Path.home() / "Desktop",
            Path.home() / "Downloads",
            local_appdata / "Temp",
            appdata,
            appdata / "Microsoft/Windows/Start Menu/Programs/Startup",
            program_data / "Microsoft/Windows/Start Menu/Programs/Startup",
        ]
        self._scan_roots(candidates)

    def scan_folder(self):
        folder = filedialog.askdirectory(title="Выберите папку для проверки")
        if not folder:
            return
        selected = Path(folder)
        self.scan_progress.start(12)
        self._scan_roots([selected])
        if messagebox.askyesno(APP, "Дополнительно запустить проверку этой папки Microsoft Defender?"):
            try:
                pid = start_defender_scan("CustomScan", selected)
                self.status.set(f"Microsoft Defender: выборочная проверка запущена (PID {pid}).")
            except Exception as exc:
                messagebox.showerror(APP, f"Не удалось запустить Defender: {exc}")

    def full_defender_scan(self):
        if not messagebox.askyesno(
            APP,
            "Запустить полную проверку Microsoft Defender?\n\n"
            "Она может занять продолжительное время и временно нагрузить компьютер.",
        ):
            return
        try:
            pid = start_defender_scan("FullScan")
            self.status.set(f"Microsoft Defender: полная проверка запущена (PID {pid}).")
        except Exception as exc:
            messagebox.showerror(APP, f"Не удалось запустить Defender: {exc}")

    def _refresh_defender_status_async(self):
        if not self.winfo_exists():
            return

        def worker():
            try:
                status = get_defender_status()
                label = (
                    f"Microsoft Defender: {'ON' if status.antivirus_enabled else 'OFF'} · "
                    f"Real-time: {'ON' if status.realtime_enabled else 'OFF'}"
                )
                color = GREEN if status.antivirus_enabled and status.realtime_enabled else AMBER
            except Exception as exc:
                label, color = f"Microsoft Defender: статус недоступен ({exc})", AMBER
            try:
                self.after(0, lambda: self.defender_label.configure(text=label, fg=color))
            except RuntimeError:
                pass

        threading.Thread(target=worker, name="LEDERG-DefenderStatus", daemon=True).start()
        self.after(60000, self._refresh_defender_status_async)

    def _refresh_protection_async(self):
        self._render_protection_checks([])

        def worker():
            try:
                checks = get_security_posture()
            except Exception as exc:
                checks = [ProtectionCheck("Центр защиты", "UNKNOWN", str(exc))]
            try:
                self.after(0, lambda: self._render_protection_checks(checks))
            except RuntimeError:
                pass

        threading.Thread(target=worker, name="LEDERG-SecurityPosture", daemon=True).start()

    def _scan_roots(self, roots):
        self.status.set("Сканирование файлов… Подозрительные объекты будут показаны в результатах.")
        self._seen_scan_paths = set()

        def worker():
            count = 0
            isolated = 0
            critical = 0
            for root in roots:
                try:
                    root = Path(root)
                    if not root.exists():
                        continue
                    if root.is_file():
                        candidates = [root]
                    else:
                        candidates = None
                    if candidates is not None:
                        file_iter = candidates
                        walker = None
                    else:
                        walker = os.walk(root)
                        file_iter = None

                    def inspect(path: Path):
                        nonlocal count, isolated, critical
                        if path.suffix.lower() not in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1"}:
                            return
                        path_key = str(path.resolve()).casefold()
                        if path_key in self._seen_scan_paths:
                            return
                        self._seen_scan_paths.add(path_key)
                        try:
                            result = analyze_file(path)
                        except (OSError, ValueError):
                            return
                        count += 1
                        if result.score >= 80:
                            critical += 1
                        if self.auto_protect_enabled and is_exact_ioc_file(path):
                            try:
                                item = quarantine_file(path, QUARANTINE)
                                result.quarantined_path = item.path
                                result.reasons.append("АВТОЗАЩИТА: точный IOC перемещён в карантин")
                                isolated += 1
                            except Exception as exc:
                                result.reasons.append(f"Автоизоляция не выполнена: {exc}")
                        try:
                            self.after(0, lambda r=result: self._scan_add(r))
                        except RuntimeError:
                            pass

                    if file_iter is not None:
                        for path in file_iter:
                            inspect(path)
                    else:
                        for current, dirs, files in walker:
                            dirs[:] = [d for d in dirs if d.lower() not in {
                                "node_modules", ".git", "__pycache__", ".venv", "venv",
                            }]
                            for name in files:
                                inspect(Path(current) / name)
                except (OSError, PermissionError):
                    continue
            try:
                self.after(0, lambda n=count, q=isolated, c=critical: self._finish_scan(n, q, c))
            except RuntimeError:
                pass

        threading.Thread(target=worker, name="LEDERG-FileScan", daemon=True).start()

    def _finish_scan(self, count: int, isolated: int, critical: int):
        try:
            if self.scan_progress.winfo_exists():
                self.scan_progress.stop()
            if self.scan_button.winfo_exists():
                self.scan_button.configure(state="normal", text="⛨  ПРОВЕРИТЬ СИСТЕМУ")
            if self.hero_status.winfo_exists():
                self.hero_status.configure(
                    text=f"ОБНАРУЖЕНО КРИТИЧЕСКИХ ОБЪЕКТОВ: {critical}" if critical else "ПРОВЕРКА ЗАВЕРШЕНА",
                    fg=RED_HOVER if critical else GREEN,
                )
        except tk.TclError:
            pass
        self.status.set(f"Проверка завершена. Файлов: {count} · критических: {critical} · автоматически изолировано: {isolated}.")
        self._refresh_quarantine_count()
        if count:
            detail = (
                f"Проверено файлов: {count}\n"
                f"Критических совпадений: {critical}\n"
                f"Автоматически помещено в карантин: {isolated}\n\n"
                + ("Открой результаты и проверь оставшиеся сигналы." if critical > isolated
                   else "Критических совпадений не обнаружено.")
            )
            messagebox.showinfo(APP, detail)
        else:
            messagebox.showinfo(APP, "В выбранных папках не найдено поддерживаемых файлов для локального анализа. Microsoft Defender работает отдельно.")

    def _selected_network_event(self):
        if not hasattr(self, "net_tree"):
            return None
        selection = self.net_tree.selection()
        return self.net_rows.get(selection[0]) if selection else None

    def quarantine_selected(self):
        if not hasattr(self, "scan_tree"):
            messagebox.showinfo(APP, "Открой обзор и выбери файл из результатов проверки.")
            return
        selection = self.scan_tree.selection()
        if not selection:
            messagebox.showinfo(APP, "Сначала выбери файл в результатах проверки.")
            return
        result = self.scan_rows.get(selection[0])
        if not result:
            return
        if result.quarantined_path:
            messagebox.showinfo(APP, f"Файл уже изолирован:\n{result.quarantined_path}")
            return
        if not result.path.is_file():
            messagebox.showerror(APP, "Исходный файл больше не найден.")
            return
        if not messagebox.askyesno(APP, f"Переместить файл в карантин?\n\n{result.path}\nSHA256: {result.sha256}"):
            return
        try:
            item = quarantine_file(result.path, QUARANTINE)
            result.quarantined_path = item.path
            result.reasons.append("Перемещён в карантин вручную")
            self.status.set(f"Файл изолирован и проверен по SHA256: {item.sha256}")
            self.show_page("home")
        except Exception as exc:
            messagebox.showerror(APP, str(exc))

    def block_selected(self):
        event = self._selected_network_event()
        if not event or not event.process_path:
            messagebox.showinfo(APP, "Выбери сетевое событие с доступным путём процесса.")
            return
        if not messagebox.askyesno(
            APP,
            f"Заблокировать ВСЕ исходящие соединения этого приложения?\n\n{event.process_path}\n\n"
            "Будет создано отдельное правило Windows Firewall.",
        ):
            return
        try:
            event.action = block_process_outbound(Path(event.process_path))
            self.status.set(event.action)
            self.show_page("network")
        except Exception as exc:
            messagebox.showerror(APP, str(exc))

    def unblock_selected(self):
        event = self._selected_network_event()
        if not event or not event.process_path:
            messagebox.showinfo(APP, "Выбери сетевое событие с доступным путём процесса.")
            return
        if not messagebox.askyesno(APP, f"Снять LEDERG-правило блокировки для:\n{event.process_path}?"):
            return
        try:
            event.action = unblock_process_outbound(Path(event.process_path))
            self.status.set(event.action)
            self.show_page("network")
        except Exception as exc:
            messagebox.showerror(APP, str(exc))

    def _refresh_quarantine_count(self):
        try:
            QUARANTINE.mkdir(parents=True, exist_ok=True)
            self._update_stats_display()
            if hasattr(self, "q_tree"):
                try:
                    if self.q_tree.winfo_exists():
                        self.refresh_quarantine()
                except tk.TclError:
                    pass
        except OSError:
            pass

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
                iid = self.q_tree.insert(
                    "", "end",
                    values=(
                        item_path.name, digest[:26] + "…",
                        "Хеш подтверждён" if valid else "ОШИБКА ХЕША",
                        data.get("original_path", ""),
                    ),
                    tags=("good" if valid else "bad",),
                )
                self.q_records[iid] = (item_path, metadata, Path(data.get("original_path", "")), valid)
            except Exception:
                continue
        self._update_stats_display()

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
            destination = filedialog.asksaveasfilename(
                title="Выбери новое место восстановления",
                initialfile=original.name,
            )
            if not destination:
                return
            destination = Path(destination)
        else:
            destination = original
        if not messagebox.askyesno(
            APP,
            f"Восстановить файл?\n\n{item_path.name}\nВ: {destination}\n\n"
            "Запускай восстановленный файл только если полностью ему доверяешь.",
        ):
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
