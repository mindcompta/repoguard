"""Windows launcher: open the local RepoGuard browser interface without a console."""
import sys
sys.dont_write_bytecode = True

try:
    from repoguard.web import run_web
    run_web()
except Exception:
    message = ('RepoGuard n’a pas pu démarrer. Vérifiez que toute l’archive a été extraite. '
               'Pour la version source, Python 3.10 ou plus récent est nécessaire. '
               'Essayez Diagnostic-RepoGuard.bat pour voir le détail.')
    try:
        from tkinter import messagebox
        messagebox.showerror('RepoGuard', message)
    except Exception:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, 'RepoGuard', 0x10)
        except Exception:
            pass
