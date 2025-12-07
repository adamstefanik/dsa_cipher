"""
gui.py
Digital Signature GUI - elektronicky podpis suborov
- Styl zhodny s RSA cipher GUI (zelene bordery, темная tema)
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import zipfile
import shutil

from dsacipher import (
    generate_keys,
    sign_file,
    verify_signature,
    export_private_key,
    export_public_key,
    import_private_key,
    import_public_key,
    get_file_info,
    save_signature,
    load_signature,
)

# Theme konstanty - zhodne s RSA cipher
DARK_BG = "#222026"
FIELD_BG = "#222026"
LIGHT_TXT = "#9bf08f"
BUTTON_BG = "#2b2b2b"
ACCENT = "#08AC2C"

FONT_SIZE = 10
FONT = ("Consolas", FONT_SIZE)
LABEL_FONT = ("Consolas", 11, "bold")
SMALL_LABEL_FONT = ("Consolas", 9, "bold")
BUTTON_FONT = ("Consolas", 10, "bold")

WINDOW_W = 900
WINDOW_H = 750


class DigitalSignatureGUI:
    def __init__(self, root):
        self.root = root
        root.title("< Digital Signature - RSA + SHA3-512 >")
        root.geometry(f"{WINDOW_W}x{WINDOW_H}")
        root.minsize(850, 700)
        root.resizable(True, True)
        root.configure(bg=DARK_BG)

        # Stav aplikacie
        self.public_key = None
        self.private_key = None
        self.selected_file = None
        self.signature_str = None

        self._build_ui()

    def _build_ui(self):
        """Vytvorenie hlavneho layoutu."""
        main = tk.Frame(self.root, bg=DARK_BG)
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        # Lavy stlpec - Podpisovanie
        left = tk.Frame(main, bg=DARK_BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 12))

        # Pravy stlpec - Overovanie
        right = tk.Frame(main, bg=DARK_BG)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(13, 0))

        self._build_left_panel(left)
        self._build_right_panel(right)

        # Styling tlacidiel
        self._setup_button_style()

    def _setup_button_style(self):
        """Styling pre ttk tlacidla."""
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Custom.TButton",
            background=BUTTON_BG,
            foreground=LIGHT_TXT,
            font=BUTTON_FONT,
            borderwidth=1,
            relief="flat",
            padding=(10, 6),
        )
        style.map(
            "Custom.TButton",
            background=[("active", ACCENT), ("pressed", ACCENT)],
            foreground=[("active", DARK_BG), ("pressed", DARK_BG)],
            relief=[("pressed", "flat"), ("active", "flat")],
        )

    def _build_left_panel(self, parent):
        """Lavy panel pre podpisovanie suborov."""
        tk.Label(
            parent,
            text="SIGN DOCUMENT",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=("Consolas", 14, "bold"),
        ).pack(anchor=tk.W, pady=(0, 10))

        # Generovanie klucov
        key_frame = tk.Frame(parent, bg=DARK_BG)
        key_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            key_frame,
            text="Key bits (each prime):",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=SMALL_LABEL_FONT,
        ).pack(anchor=tk.W, pady=(0, 2))

        bits_row = tk.Frame(key_frame, bg=DARK_BG)
        bits_row.pack(fill=tk.X, pady=(0, 4))

        self.key_bits_var = tk.IntVar(value=512)
        self.key_bits_spin = tk.Spinbox(
            bits_row,
            from_=64,
            to=2048,
            increment=64,
            width=8,
            textvariable=self.key_bits_var,
            font=FONT,
            bg=FIELD_BG,
            fg=LIGHT_TXT,
            buttonbackground=BUTTON_BG,
            insertbackground=ACCENT,
        )
        self.key_bits_spin.pack(side=tk.LEFT, padx=(0, 6))

        self.generate_keys_btn = ttk.Button(
            key_frame,
            text="GENERATE KEYS",
            style="Custom.TButton",
            command=self.on_generate_keys,
        )
        self.generate_keys_btn.pack(fill=tk.X, pady=(4, 0), ipady=4)

        # Vyber suboru na podpis
        tk.Label(
            parent,
            text="Select File to Sign:",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=LABEL_FONT,
        ).pack(anchor=tk.W, pady=(10, 2))

        self.select_file_btn = ttk.Button(
            parent,
            text="CHOOSE FILE...",
            style="Custom.TButton",
            command=self.on_select_file,
        )
        self.select_file_btn.pack(fill=tk.X, pady=(0, 6), ipady=4)

        # Informacie o subore
        tk.Label(
            parent,
            text="File Information:",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=LABEL_FONT,
        ).pack(anchor=tk.W, pady=(0, 2))

        self.file_info_text = tk.Text(
            parent,
            height=8,
            bg=FIELD_BG,
            fg=LIGHT_TXT,
            font=("Consolas", 9),
            bd=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
            padx=4,
            pady=4,
            wrap=tk.WORD,
            state=tk.DISABLED,
        )
        self.file_info_text.pack(fill=tk.BOTH, expand=False, pady=(0, 10))

        # Podpisovanie
        self.sign_btn = ttk.Button(
            parent,
            text="SIGN FILE",
            style="Custom.TButton",
            command=self.on_sign_file,
            state=tk.DISABLED,
        )
        self.sign_btn.pack(fill=tk.X, pady=(0, 6), ipady=6)

        # Status
        tk.Label(
            parent,
            text="Status:",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=LABEL_FONT,
        ).pack(anchor=tk.W, pady=(10, 2))

        self.status_text = tk.Text(
            parent,
            height=6,
            bg=FIELD_BG,
            fg=LIGHT_TXT,
            font=("Consolas", 9),
            bd=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
            padx=4,
            pady=4,
            wrap=tk.WORD,
            state=tk.DISABLED,
        )
        self.status_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Export klucov
        export_frame = tk.Frame(parent, bg=DARK_BG)
        export_frame.pack(fill=tk.X, pady=(10, 0))

        self.export_keys_btn = ttk.Button(
            export_frame,
            text="EXPORT KEYS (.priv + .pub)",
            style="Custom.TButton",
            command=self.on_export_keys,
            state=tk.DISABLED,
        )
        self.export_keys_btn.pack(fill=tk.X, ipady=4)

    def _build_right_panel(self, parent):
        """Pravy panel pre overovanie podpisov."""
        tk.Label(
            parent,
            text="VERIFY SIGNATURE",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=("Consolas", 14, "bold"),
        ).pack(anchor=tk.W, pady=(0, 10))

        # Nacitanie verejneho kluca
        tk.Label(
            parent,
            text="Load Public Key:",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=LABEL_FONT,
        ).pack(anchor=tk.W, pady=(0, 2))

        self.load_pubkey_btn = ttk.Button(
            parent,
            text="LOAD .pub FILE...",
            style="Custom.TButton",
            command=self.on_load_public_key,
        )
        self.load_pubkey_btn.pack(fill=tk.X, pady=(0, 6), ipady=4)

        # Status verejneho kluca
        self.pubkey_status_label = tk.Label(
            parent,
            text="No public key loaded",
            bg=DARK_BG,
            fg="#999999",
            font=("Consolas", 9),
            anchor="w",
        )
        self.pubkey_status_label.pack(anchor=tk.W, pady=(0, 10))

        # Vyber .zip suboru na overenie
        tk.Label(
            parent,
            text="Select Signed Package:",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=LABEL_FONT,
        ).pack(anchor=tk.W, pady=(10, 2))

        self.select_zip_btn = ttk.Button(
            parent,
            text="CHOOSE .zip FILE...",
            style="Custom.TButton",
            command=self.on_select_zip,
        )
        self.select_zip_btn.pack(fill=tk.X, pady=(0, 6), ipady=4)

        # Informacie o .zip subore
        tk.Label(
            parent,
            text="Package Information:",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=LABEL_FONT,
        ).pack(anchor=tk.W, pady=(0, 2))

        self.zip_info_text = tk.Text(
            parent,
            height=8,
            bg=FIELD_BG,
            fg=LIGHT_TXT,
            font=("Consolas", 9),
            bd=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
            padx=4,
            pady=4,
            wrap=tk.WORD,
            state=tk.DISABLED,
        )
        self.zip_info_text.pack(fill=tk.BOTH, expand=False, pady=(0, 10))

        # Overenie
        self.verify_btn = ttk.Button(
            parent,
            text="VERIFY SIGNATURE",
            style="Custom.TButton",
            command=self.on_verify_signature,
            state=tk.DISABLED,
        )
        self.verify_btn.pack(fill=tk.X, pady=(0, 6), ipady=6)

        # Vysledok overenia
        tk.Label(
            parent,
            text="Verification Result:",
            bg=DARK_BG,
            fg=LIGHT_TXT,
            font=LABEL_FONT,
        ).pack(anchor=tk.W, pady=(10, 2))

        self.verify_result_text = tk.Text(
            parent,
            height=10,
            bg=FIELD_BG,
            fg=LIGHT_TXT,
            font=("Consolas", 9),
            bd=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground=ACCENT,
            highlightcolor=ACCENT,
            padx=4,
            pady=4,
            wrap=tk.WORD,
            state=tk.DISABLED,
        )
        self.verify_result_text.pack(fill=tk.BOTH, expand=True, pady=(0, 0))

    def on_generate_keys(self):
        """Generovanie RSA klucov."""
        bits = int(self.key_bits_var.get())

        self.append_status("Generating RSA keys...")
        self.generate_keys_btn.config(state=tk.DISABLED)

        def worker():
            try:
                pub, priv = generate_keys(bits)
                self.public_key = pub
                self.private_key = priv

                self.root.after(
                    0, lambda: self.append_status(f"Keys generated successfully!")
                )
                self.root.after(
                    0, lambda: self.append_status(f"Public key (n, e): {pub}")
                )
                self.root.after(
                    0, lambda: self.append_status(f"Private key (n, d): {priv}")
                )
                self.root.after(0, lambda: self.export_keys_btn.config(state=tk.NORMAL))

                # Ak uz je vybrany subor, povol podpisovanie
                if self.selected_file:
                    self.root.after(0, lambda: self.sign_btn.config(state=tk.NORMAL))

            except Exception as ex:
                self.root.after(0, lambda: messagebox.showerror("Error", str(ex)))
            finally:
                self.root.after(
                    0, lambda: self.generate_keys_btn.config(state=tk.NORMAL)
                )

        threading.Thread(target=worker, daemon=True).start()

    def on_select_file(self):
        """Vyber suboru na podpis."""
        file_path = filedialog.askopenfilename(
            title="Select file to sign", filetypes=[("All files", "*.*")]
        )

        if not file_path:
            return

        self.selected_file = file_path

        # Zobraz informacie o subore
        info = get_file_info(file_path)
        self.set_text_widget(
            self.file_info_text,
            f"Name: {info['name']}\n"
            f"Path: {info['path']}\n"
            f"Type: {info['extension']}\n"
            f"Size: {info['size']} bytes ({info['size']/1024:.2f} KB)\n"
            f"Modified: {info['modified']}",
        )

        self.append_status(f"File selected: {info['name']}")

        # Ak su vygenerovane kluce, povol podpisovanie
        if self.private_key:
            self.sign_btn.config(state=tk.NORMAL)

    def on_sign_file(self):
        """Podpisanie vybraneho suboru."""
        if not self.selected_file or not self.private_key:
            messagebox.showwarning("Warning", "Select file and generate keys first!")
            return

        # Vyber zip_path PRED spustenim worker vlakna
        base_name = os.path.basename(self.selected_file)
        zip_path = filedialog.asksaveasfilename(
            title="Save signed package",
            defaultextension=".zip",
            initialfile=f"{base_name}.zip",
            filetypes=[("ZIP files", "*.zip")],
        )

        if not zip_path:
            return

        self.append_status("Signing file...")
        self.sign_btn.config(state=tk.DISABLED)

        def worker():
            try:
                # Podpis suboru
                signature = sign_file(self.selected_file, self.private_key)
                self.signature_str = signature

                # Uloz .sign subor
                sign_filename = f"{base_name}.sign"
                temp_sign_path = os.path.join(
                    os.path.dirname(self.selected_file), sign_filename
                )
                save_signature(signature, temp_sign_path)

                # Vytvor .zip s dokumentom + podpisom
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                    zipf.write(self.selected_file, base_name)
                    zipf.write(temp_sign_path, sign_filename)

                # Vymaz docasny .sign subor
                os.remove(temp_sign_path)

                self.root.after(
                    0, lambda: self.append_status(f"Signed package saved: {zip_path}")
                )
                self.root.after(
                    0,
                    lambda: messagebox.showinfo("Success", "File signed successfully!"),
                )

            except Exception as ex:
                self.root.after(0, lambda: messagebox.showerror("Error", str(ex)))
            finally:
                self.root.after(0, lambda: self.sign_btn.config(state=tk.NORMAL))

        threading.Thread(target=worker, daemon=True).start()

    def on_export_keys(self):
        """Export privatneho a verejneho kluca do suborov."""
        if not self.public_key or not self.private_key:
            messagebox.showwarning("Warning", "Generate keys first!")
            return

        # Vyber priecinku
        folder = filedialog.askdirectory(title="Select folder to save keys")
        if not folder:
            return

        try:
            # Export
            priv_path = os.path.join(folder, "private_key.priv")
            pub_path = os.path.join(folder, "public_key.pub")

            export_private_key(self.private_key, priv_path)
            export_public_key(self.public_key, pub_path)

            self.append_status(f"Keys exported to: {folder}")
            messagebox.showinfo("Success", f"Keys saved:\n{priv_path}\n{pub_path}")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def on_load_public_key(self):
        """Nacitanie verejneho kluca z .pub suboru."""
        pub_path = filedialog.askopenfilename(
            title="Select public key",
            filetypes=[("Public key", "*.pub"), ("All files", "*.*")],
        )

        if not pub_path:
            return

        try:
            self.public_key = import_public_key(pub_path)
            self.pubkey_status_label.config(
                text=f"✓ Public key loaded: {os.path.basename(pub_path)}", fg=ACCENT
            )
            self.append_verify_result(f"Public key loaded: {self.public_key}")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to load public key:\n{ex}")

    def on_select_zip(self):
        """Vyber .zip suboru na overenie."""
        zip_path = filedialog.askopenfilename(
            title="Select signed package",
            filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")],
        )

        if not zip_path:
            return

        # Zobraz informacie o .zip
        info = get_file_info(zip_path)
        self.set_text_widget(
            self.zip_info_text,
            f"Name: {info['name']}\n"
            f"Path: {info['path']}\n"
            f"Size: {info['size']} bytes ({info['size']/1024:.2f} KB)\n"
            f"Modified: {info['modified']}\n\n"
            f"Contents:\n",
        )

        # Zobraz obsah .zip
        try:
            with zipfile.ZipFile(zip_path, "r") as zipf:
                files = zipf.namelist()
                content_str = "\n".join([f"  - {f}" for f in files])
                self.append_text_widget(self.zip_info_text, content_str)
        except Exception as ex:
            self.append_text_widget(self.zip_info_text, f"Error reading ZIP: {ex}")

        # Uloz cestu pre overenie
        self.selected_zip = zip_path

        # Ak je nacitany verejny kluc, povol overenie
        if self.public_key:
            self.verify_btn.config(state=tk.NORMAL)

    def on_verify_signature(self):
        """Overenie podpisu."""
        if not self.public_key:
            messagebox.showwarning("Warning", "Load public key first!")
            return

        if not hasattr(self, "selected_zip"):
            messagebox.showwarning("Warning", "Select signed package first!")
            return

        self.append_verify_result("Verifying signature...")
        self.verify_btn.config(state=tk.DISABLED)

        def worker():
            temp_dir = None
            try:
                # Rozbal .zip do docasneho priecinka
                temp_dir = "temp_verify"
                os.makedirs(temp_dir, exist_ok=True)

                with zipfile.ZipFile(self.selected_zip, "r") as zipf:
                    zipf.extractall(temp_dir)
                    files = zipf.namelist()

                # Najdi .sign subor a dokument
                sign_file_name = None
                doc_file_name = None

                for f in files:
                    if f.endswith(".sign"):
                        sign_file_name = f
                    else:
                        doc_file_name = f

                if not sign_file_name or not doc_file_name:
                    raise ValueError("Invalid package: missing .sign or document file")

                sign_path = os.path.join(temp_dir, sign_file_name)
                doc_path = os.path.join(temp_dir, doc_file_name)

                # Nacitaj podpis
                signature_str = load_signature(sign_path)

                # Over podpis
                is_valid = verify_signature(doc_path, signature_str, self.public_key)

                # Zobraz vysledok
                if is_valid:
                    result_msg = (
                        "✓ SIGNATURE VALID\n\n"
                        f"Document: {doc_file_name}\n"
                        f"Signature: {signature_str[:50]}...\n"
                        f"Status: AUTHENTIC\n\n"
                        "The document has not been modified and was signed with the corresponding private key."
                    )
                    self.root.after(0, lambda: self.append_verify_result(result_msg))
                    self.root.after(
                        0,
                        lambda: messagebox.showinfo(
                            "Verification Success", "✓ Signature is VALID!"
                        ),
                    )
                else:
                    result_msg = (
                        "✗ SIGNATURE INVALID\n\n"
                        f"Document: {doc_file_name}\n"
                        f"Status: COMPROMISED\n\n"
                        "WARNING: The document may have been modified or the signature is incorrect!"
                    )
                    self.root.after(0, lambda: self.append_verify_result(result_msg))
                    self.root.after(
                        0,
                        lambda: messagebox.showwarning(
                            "Verification Failed", "✗ Signature is INVALID!"
                        ),
                    )

            except Exception as ex:
                self.root.after(0, lambda: self.append_verify_result(f"Error: {ex}"))
                self.root.after(0, lambda: messagebox.showerror("Error", str(ex)))
            finally:
                # Vycisti docasne subory
                if temp_dir and os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                self.root.after(0, lambda: self.verify_btn.config(state=tk.NORMAL))

        threading.Thread(target=worker, daemon=True).start()

    def append_status(self, text: str):
        """Prida riadok do status pola."""
        self.append_text_widget(self.status_text, text + "\n")

    def append_verify_result(self, text: str):
        """Prida text do verification result pola."""
        self.set_text_widget(self.verify_result_text, text)

    def set_text_widget(self, widget, text: str):
        """Nastavi text do disabled Text widgetu."""
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.insert(1.0, text)
        widget.config(state=tk.DISABLED)

    def append_text_widget(self, widget, text: str):
        """Prida text do disabled Text widgetu."""
        widget.config(state=tk.NORMAL)
        widget.insert(tk.END, text)
        widget.see(tk.END)
        widget.config(state=tk.DISABLED)


def main():
    root = tk.Tk()
    app = DigitalSignatureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
