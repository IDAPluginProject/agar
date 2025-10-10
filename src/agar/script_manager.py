import idaapi, idc
import ida_kernwin
import os
import json
import secrets
try:
    from PySide6.QtWidgets import QDialog, QVBoxLayout, QPushButton, QKeySequenceEdit
    from PySide6.QtCore import Qt
except ImportError:
    from PyQt5.QtWidgets import QDialog, QVBoxLayout, QPushButton, QKeySequenceEdit
    from PyQt5.QtCore import Qt

cur_dir = os.path.dirname(os.path.abspath(__file__))
script_dir = os.path.join(cur_dir, "scripts")


def load_script_manager():
    try:
        scripts = json.loads(open(os.path.join(script_dir, "scripts.json"), "r").read())
    except Exception as e:
        ida_kernwin.warning(f"Error loading scripts: {e}")
        return None
    return scripts

def load_keybinds():
    try:
        keybinds = json.loads(open(os.path.join(script_dir, "keybinds.json"), "r").read())
    except Exception as e:
        json.dump({}, open(os.path.join(script_dir, "keybinds.json"), "w"), indent=4)
        return {}
    return keybinds

scripts = load_script_manager()
keybinds = load_keybinds()
for script_name, keybind in keybinds.items():
    for script in scripts:
        if script.get("name") == script_name:
            script["keybind"] = keybind

registered_keybinds = set()

def register_keybinds():
    global registered_keybinds
    for keybind in registered_keybinds:
        if keybind == "Ctrl+Shift+G":
            print("Illegal keybind", keybind)
            continue
        idc.del_idc_hotkey(keybind)
    registered_keybinds = set()
    for script_name, keybind in keybinds.items():
        if not keybind:
            continue
        func_name = f"script_manager_keybind_{secrets.token_hex(8)}"
        idaapi.compile_idc_text(f'static  {func_name}() {{ RunPythonStatement("__import__(\\"script_manager\\").execute_script(\\"{script_name}\\")"); }}')
        idc.add_idc_hotkey(keybind, func_name)
        registered_keybinds.add(keybind)

def execute_script(script_name):
    script_path = next((scripts[i]["path"] for i in range(len(scripts)) if scripts[i]["name"] == script_name), None)
    if not script_path:
        ida_kernwin.warning(f"Script {script_name} not found!")
        return
    print(f"[AGAR] Executing script: {script_name}")
    script_path = os.path.join(script_dir, script_path)
    if not os.path.exists(script_path):
        ida_kernwin.warning(f"Script file {script_path} does not exist!")
        return
    idaapi.execute_sync(
        lambda: idaapi.IDAPython_ExecScript(script_path, {
            "__name__": "__main__"
        }),
        idaapi.MFF_WRITE
    )

class ScriptsChooser(ida_kernwin.Choose):
    def __init__(self, scripts):
        self.scripts = scripts or []
        self.filtered_scripts = self.scripts.copy()
        self.search_text = ""
        ida_kernwin.Choose.__init__(
            self,
            "AGAR Scripts",
            [ ["Name", 20], ["Description", 40], ["Keybind", 12] ],
            flags=ida_kernwin.Choose.CH_MODAL
        )
        self.refresh_items()

    def refresh_items(self):
        text = self.search_text.strip()
        self.filtered_scripts = [
            s for s in self.scripts
            if text.lower() in s.get("name", "").lower()
            or text.lower() in s.get("description", "").lower()
            or text.lower() in s.get("keybind", "").lower()
        ]
        self.items = [
            [
                s.get("name", ""),
                s.get("description", ""),
                s.get("keybind", "")
            ]
            for s in self.filtered_scripts
        ]

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnEditLine(self, n):
        script_name = self.items[n][0]
        class KeySequenceDialog(QDialog):
            def __init__(self, parent=None):
                super().__init__(parent)
                self.setWindowTitle(f"Set Shortcut for {script_name}")
                self.setWindowModality(Qt.ApplicationModal)
                self.key_edit = QKeySequenceEdit(self)
                self.ok_btn = QPushButton("OK", self)
                self.ok_btn.clicked.connect(self.accept)
                layout = QVBoxLayout(self)
                layout.addWidget(self.key_edit)
                layout.addWidget(self.ok_btn)
                self.setLayout(layout)

            def get_keysequence(self):
                return self.key_edit.keySequence().toString()
        dlg = KeySequenceDialog()
        if dlg.exec() == QDialog.Accepted:
            keyseq = dlg.get_keysequence()
            if keyseq == "Ctrl+Shift+G":
                ida_kernwin.warning("Ctrl+Shift+G is reserved for the AGAR plugin and cannot be used as a script keybind.")
                return
            scripts[n]["keybind"] = keyseq
            if not keyseq:
                del keybinds[script_name]
            else:
                keybinds[script_name] = keyseq
            json.dump(keybinds, open(os.path.join(script_dir, "keybinds.json"), "w"), indent=4)
            self.refresh_items()
            register_keybinds()
            self.Refresh()

    def OnFilter(self, text):
        self.search_text = text
        self.refresh_items()
        return len(self.filtered_scripts)

def show_scripts_chooser(scripts):
    chooser = ScriptsChooser(scripts)
    res = chooser.Show(modal=True)
    if res == -1:
        return
    script = chooser.filtered_scripts[res]
    execute_script(script['name'])
