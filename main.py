"""
main.py
Spúšťací súbor pre Digital Signature Application (DSA)
"""

import tkinter as tk
from gui import DigitalSignatureGUI


def main():
    root = tk.Tk()
    app = DigitalSignatureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()