import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk
import pandas as pd

class IPValidatorAutomata:
    def __init__(self):
        self.valid_ips = []
        self.invalid_ips = []

    def validate_ip(self, ip):
        # Validación para dirección IP normal, CIDR o hexadecimal
        if self.is_valid_normal_ip(ip) or self.is_valid_cidr(ip) or self.is_valid_hex_ip(ip):
            return True
        return False

    def is_valid_normal_ip(self, ip):
        # Expresión regular para una dirección IP normal
        pattern = r'^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
        return re.match(pattern, ip) is not None

    def is_valid_cidr(self, ip):
        # Expresión regular para una dirección IP en formato CIDR (solo acepta 8, 16, 24 como máscaras de subred)
        pattern = r'^([0-9]{1,3}\.){3}[0-9]{1,3}/(8|16|24)$'
        return re.match(pattern, ip) is not None

    def is_valid_hex_ip(self, ip):
        # Expresión regular para validar IP en notación hexadecimal
        pattern = r"^0[xX][0-9a-fA-F]{1,8}$"
        return re.match(pattern, ip) is not None

    def extract_ips(self, text):
        self.valid_ips = []  # Reiniciar la lista de IPs válidas
        self.invalid_ips = []  # Reiniciar la lista de IPs inválidas
        lines = text.splitlines()
        for row, line in enumerate(lines):
            for col, word in enumerate(line.split()):
                if self.validate_ip(word):
                    self.valid_ips.append((row + 1, col + 1, word))
                else:
                    self.invalid_ips.append((row + 1, col + 1, word))

class IPValidatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Validator")
        self.automaton = IPValidatorAutomata()
        self.create_widgets()

    def create_widgets(self):
        title_label = ttk.Label(self.root, text="IP Validator", font=("Arial", 16))
        title_label.pack(pady=10)

        self.select_button = ttk.Button(self.root, text="Selecciona el archivo a leer", command=self.select_file)
        self.select_button.pack(pady=10)

        self.report_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=60, height=20)
        self.report_text.pack(pady=10)

        self.save_button = ttk.Button(self.root, text="Guardar reporte", command=self.save_report, state=tk.DISABLED)
        self.save_button.pack(pady=10)

    def select_file(self):
        
        file_path = filedialog.askopenfilename(title="Selecciona el archivo a leer", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            self.analyze_file(file_path)

    def analyze_file(self, file_path):
        with open(file_path, 'r') as file:
            text = file.read()
        
        
        self.automaton.extract_ips(text)
        
        if self.automaton.valid_ips or self.automaton.invalid_ips:
            report = self.generate_report()
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, report)
            self.save_button.config(state=tk.NORMAL)
        else:
            messagebox.showinfo("IPs no validas", "No se encontraron IPs en el archivo.")

    def generate_report(self):
        
        report_lines = ["IPs válidas:\nFila,Columna,IP\n"]
        for row, col, ip in self.automaton.valid_ips:
            report_lines.append(f"{row},{col},{ip}\n")
        
        report_lines.append("\nIPs no válidas:\nFila,Columna,IP\n")
        for row, col, ip in self.automaton.invalid_ips:
            report_lines.append(f"{row},{col},{ip}\n")
        
        return ''.join(report_lines)

    def save_report(self):
        
        if self.automaton.valid_ips or self.automaton.invalid_ips:
            save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
            if save_path:
                report = self.generate_report()
                with open(save_path, 'w') as file:
                    file.write(report)
                messagebox.showinfo("Realizado", "El reporte se guardo correctamente.")

if __name__ == "__main__":
    root = tk.Tk()
    app = IPValidatorApp(root)
    root.mainloop()
