import tkinter as tk
from tkinter import ttk
import random
import string

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Генератор паролей")

        self.lower_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.length_var = tk.IntVar(value=12)
        self.password_var = tk.StringVar()

        self._create_widgets()

    def _create_widgets(self):
        # Рамка для параметров
        params_frame = ttk.LabelFrame(self.root, text="Параметры")
        params_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Чекбоксы
        lower_check = ttk.Checkbutton(params_frame, text="Включить алфавит нижнего регистра [a-z]", variable=self.lower_var)
        lower_check.grid(row=0, column=0, sticky="w", padx=5, pady=5)

        digits_check = ttk.Checkbutton(params_frame, text="Включить цифры [0-9]", variable=self.digits_var)
        digits_check.grid(row=1, column=0, sticky="w", padx=5, pady=5)

        symbols_check = ttk.Checkbutton(params_frame, text="Включить спецсимволы [! @ # $ %]", variable=self.symbols_var)
        symbols_check.grid(row=2, column=0, sticky="w", padx=5, pady=5)

        # Длина пароля
        length_label = ttk.Label(params_frame, text="Длина пароля:")
        length_label.grid(row=3, column=0, sticky="w", padx=5, pady=5)
        length_spinbox = tk.Spinbox(params_frame, from_=6, to=100, textvariable=self.length_var, width=5)
        length_spinbox.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        # Кнопка генерации
        generate_button = ttk.Button(self.root, text="Сгенерировать пароль", command=self._generate_password)
        generate_button.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        # Вывод пароля
        output_frame = ttk.LabelFrame(self.root, text="Сгенерированный пароль")
        output_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        self.password_label = ttk.Label(output_frame, textvariable=self.password_var, font=("Arial", 14))
        self.password_label.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        # Кнопка копирования
        copy_button = ttk.Button(output_frame, text="Скопировать", command=self._copy_password)
        copy_button.grid(row=0, column=1, padx=5, pady=5, sticky="e")

        # Настройка изменения размера
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)
        params_frame.columnconfigure(0, weight=1)
        output_frame.columnconfigure(0, weight=1)

    def _generate_password(self):
        characters = ''
        if self.lower_var.get():
            characters += string.ascii_lowercase
        if self.digits_var.get():
            characters += string.digits
        if self.symbols_var.get():
            characters += "!@#$%"

        length = self.length_var.get()

        if not characters:
            self.password_var.set("Выберите хотя бы один параметр!")
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_var.set(password)

    def _copy_password(self):
        if self.password_var.get():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.password_var.get())
            self.root.update()  # Необходимо для корректной работы в некоторых системах
            # Можно добавить визуальное подтверждение копирования (необязательно)
            # Например, временно изменить текст кнопки
            original_text = self.copy_button.cget("text")
            self.copy_button.config(text="Скопировано!")
            self.root.after(1500, lambda: self.copy_button.config(text=original_text))

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()