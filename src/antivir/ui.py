from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from collections.abc import Callable


def blend_hex(start: str, end: str, amount: float) -> str:
    """Linearly interpolate two #RRGGBB colors."""
    amount = max(0.0, min(1.0, float(amount)))
    left = tuple(int(start[index:index + 2], 16) for index in (1, 3, 5))
    right = tuple(int(end[index:index + 2], 16) for index in (1, 3, 5))
    channels = [round(a + (b - a) * amount) for a, b in zip(left, right)]
    return "#" + "".join(f"{channel:02x}" for channel in channels)


def rounded_rectangle_points(
    width: int,
    height: int,
    radius: int = 14,
    inset: int = 1,
) -> list[float]:
    """Return a smooth-polygon outline for a rounded rectangle."""
    x0 = max(0, int(inset))
    y0 = max(0, int(inset))
    x1 = max(x0, int(width) - int(inset))
    y1 = max(y0, int(height) - int(inset))
    corner = max(0, min(int(radius), (x1 - x0) // 2, (y1 - y0) // 2))
    return [
        x0 + corner, y0,
        x1 - corner, y0,
        x1, y0 + corner,
        x1, y1 - corner,
        x1 - corner, y1,
        x0 + corner, y1,
        x0, y1 - corner,
        x0, y0 + corner,
    ]


class PillButton(tk.Canvas):
    """Lightweight rounded Tk button with hover animation and keyboard support."""

    def __init__(
        self,
        parent,
        text: str,
        command: Callable[[], object] | None = None,
        *,
        background: str = "#171e2a",
        foreground: str = "#f4f6fa",
        hover_background: str = "#263244",
        font=("Segoe UI Semibold", 10),
        anchor: str = "center",
        padding_x: int = 18,
        padding_y: int = 10,
        width: int | None = None,
        height: int | None = None,
        radius: int = 15,
    ):
        self._font = tkfont.Font(font=font)
        measured_width = self._font.measure(text) + padding_x * 2
        measured_height = self._font.metrics("linespace") + padding_y * 2
        self._button_height = int(height or measured_height)
        self._auto_width = width is None
        self._button_width = int(width or measured_width)
        try:
            canvas_background = parent.cget("bg")
        except (tk.TclError, AttributeError):
            canvas_background = "#080a0f"
        super().__init__(
            parent,
            width=self._button_width,
            height=self._button_height,
            bg=canvas_background,
            highlightthickness=0,
            bd=0,
            takefocus=1,
        )
        self._text = text
        self._command = command
        self._normal = background
        self._hover = hover_background
        self._foreground = foreground
        self._current = background
        self._anchor = anchor
        self._padding_x = int(padding_x)
        self._padding_y = int(padding_y)
        self._radius = int(radius)
        self._state = "normal"
        self._hovered = False
        self._pressed = False
        self._animation_id = None
        self.bind("<Configure>", self._draw)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Return>", lambda _event: self.invoke())
        self.bind("<space>", lambda _event: self.invoke())
        self.bind("<FocusIn>", self._on_enter)
        self.bind("<FocusOut>", self._on_leave)
        self._draw()

    def configure(self, cnf=None, **kwargs):
        if cnf is not None:
            if isinstance(cnf, dict):
                kwargs = {**cnf, **kwargs}
            else:
                return super().configure(cnf, **kwargs)
        background = kwargs.pop("background", kwargs.pop("bg", None))
        foreground = kwargs.pop("foreground", kwargs.pop("fg", None))
        hover = kwargs.pop("hover_background", kwargs.pop("activebackground", None))
        text = kwargs.pop("text", None)
        command = kwargs.pop("command", None)
        state = kwargs.pop("state", None)
        font = kwargs.pop("font", None)
        anchor = kwargs.pop("anchor", None)
        if background is not None:
            self._normal = background
        if foreground is not None:
            self._foreground = foreground
        if hover is not None:
            self._hover = hover
        if text is not None:
            self._text = str(text)
        if command is not None:
            self._command = command
        if state is not None:
            self._state = str(state)
        if font is not None:
            self._font = tkfont.Font(font=font)
        if anchor is not None:
            self._anchor = anchor
        if self._auto_width and (text is not None or font is not None):
            self._button_width = self._font.measure(self._text) + self._padding_x * 2
            super().configure(width=self._button_width)
        if background is not None or hover is not None:
            self._animate_to(self._hover if self._hovered else self._normal)
        elif foreground is not None or text is not None or font is not None or state is not None or anchor is not None:
            self._draw()
        if kwargs:
            return super().configure(**kwargs)
        return None

    config = configure

    def invoke(self):
        if self._state != "normal" or self._command is None:
            return None
        return self._command()

    def _on_enter(self, _event=None):
        if self._state == "normal":
            self._hovered = True
            self._animate_to(self._hover)

    def _on_leave(self, _event=None):
        self._hovered = False
        self._pressed = False
        self._animate_to(self._normal if self._state == "normal" else "#202633")

    def _on_press(self, event):
        if self._state == "normal":
            self._pressed = True
            self._animate_to(self._hover)

    def _on_release(self, event):
        was_pressed = self._pressed
        self._pressed = False
        inside = 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height()
        if was_pressed and inside:
            self.invoke()
        self._animate_to(self._hover if self._hovered else self._normal)

    def _animate_to(self, target: str):
        if self._animation_id is not None:
            try:
                self.after_cancel(self._animation_id)
            except tk.TclError:
                pass
            self._animation_id = None
        start = self._current
        if start == target:
            self._draw()
            return
        step = 0

        def animate():
            nonlocal step
            step += 1
            self._current = blend_hex(start, target, step / 5)
            self._draw()
            if step < 5:
                self._animation_id = self.after(16, animate)
            else:
                self._animation_id = None

        animate()

    def _draw(self, _event=None):
        if not self.winfo_exists():
            return
        self.delete("all")
        width = max(2, self.winfo_width())
        height = max(2, self.winfo_height())
        color = self._current if self._state == "normal" else "#202633"
        points = rounded_rectangle_points(width, height, self._radius, 1)
        self.create_polygon(*points, smooth=True, splinesteps=20, fill=color, outline="")
        x = self._padding_x if self._anchor == "w" else width / 2
        self.create_text(
            x,
            height / 2,
            text=self._text,
            fill=self._foreground if self._state == "normal" else "#748093",
            font=self._font,
            anchor="w" if self._anchor == "w" else "center",
        )

    def destroy(self):
        if self._animation_id is not None:
            try:
                self.after_cancel(self._animation_id)
            except tk.TclError:
                pass
        super().destroy()
