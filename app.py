import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import os
from antivir.core import analyze_file, quarantine_file

APP = "LEDERG ANTIVIR"
BASE = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "LEDERG ANTIVIR"
QUARANTINE = BASE / "Quarantine"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP)
        self.geometry("900x580")
        self.minsize(760, 480)
        self.configure(bg="#090909")
        style=ttk.Style(self); style.theme_use("clam")
        style.configure("Treeview",background="#171717",foreground="#eee",fieldbackground="#171717",rowheight=28)
        style.configure("Treeview.Heading",background="#b51220",foreground="white")
        tk.Label(self,text="LEDERG  /  ANTIVIR",font=("Segoe UI",22,"bold"),fg="#e31b32",bg="#090909").pack(anchor="w",padx=22,pady=(18,4))
        tk.Label(self,text="Защита от стиллеров • локальный анализ • SHA-256 карантин",font=("Segoe UI",10),fg="#aaa",bg="#090909").pack(anchor="w",padx=24)
        bar=tk.Frame(self,bg="#090909");bar.pack(fill="x",padx=20,pady=18)
        self.btn(bar,"Проверить файл",self.scan_file).pack(side="left",padx=5)
        self.btn(bar,"Проверить папку",self.scan_folder).pack(side="left",padx=5)
        self.btn(bar,"Карантин",self.quarantine_selected).pack(side="left",padx=5)
        self.btn(bar,"Открыть карантин",self.open_quarantine).pack(side="left",padx=5)
        self.tree=ttk.Treeview(self,columns=("score","hash","reason"),show="headings")
        for col,title,width in [("score","Риск",70),("hash","SHA256",260),("reason","Причины",450)]:
            self.tree.heading(col,text=title);self.tree.column(col,width=width)
        self.tree.pack(fill="both",expand=True,padx=22,pady=(0,12))
        self.status=tk.StringVar(value="Готов. Сканирование ничего не удаляет автоматически.")
        tk.Label(self,textvariable=self.status,fg="#ddd",bg="#111",anchor="w",padx=12,pady=9).pack(fill="x",side="bottom")
        self.results={}
    def btn(self,parent,text,command):
        return tk.Button(parent,text=text,command=command,bg="#b51220",fg="white",activebackground="#e31b32",activeforeground="white",relief="flat",padx=14,pady=10)
    def add_result(self,r):
        iid=self.tree.insert("", "end",values=(r.score,r.sha256[:24]+"…","; ".join(r.reasons) or "Явных индикаторов нет"))
        self.results[iid]=r
    def scan_file(self):
        p=filedialog.askopenfilename(title="Выберите файл для проверки")
        if not p:return
        try:r=analyze_file(Path(p));self.add_result(r);self.status.set(f"Проверен: {p} • риск {r.score}/100")
        except Exception as e:messagebox.showerror(APP,str(e))
    def scan_folder(self):
        folder=filedialog.askdirectory(title="Папка для проверки")
        if not folder:return
        count=0
        for root,dirs,files in os.walk(folder):
            dirs[:]=[d for d in dirs if d.lower() not in {"node_modules",".git"}]
            for name in files:
                if Path(name).suffix.lower() not in {".exe",".dll",".scr",".bat",".cmd",".ps1"}:continue
                try:self.add_result(analyze_file(Path(root)/name));count+=1
                except Exception:pass
        self.status.set(f"Проверено файлов: {count}. Сканирование не удаляет файлы.")
    def quarantine_selected(self):
        selected=self.tree.selection()
        if not selected:messagebox.showinfo(APP,"Выберите результат сканирования.");return
        r=self.results[selected[0]]
        if r.score<50:
            if not messagebox.askyesno(APP,"Риск ниже 50. Поместить файл в карантин вручную?"):return
        if not messagebox.askyesno(APP,f"Переместить файл в карантин?\n{r.path}\nSHA256: {r.sha256}"):return
        try:item=quarantine_file(r.path,QUARANTINE);self.status.set(f"Карантин: {item.path}");self.tree.delete(selected[0])
        except Exception as e:messagebox.showerror(APP,str(e))
    def open_quarantine(self):
        QUARANTINE.mkdir(parents=True,exist_ok=True)
        os.startfile(QUARANTINE)
if __name__=="__main__":App().mainloop()
