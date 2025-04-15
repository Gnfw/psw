# app.py
from flask import Flask, render_template, request, jsonify
import sys
import math
import json
import secrets
import string
import requests
from enum import IntFlag

app = Flask(__name__)

# ... (Весь ваш исходный код функций и классов до функции main()) ... 

import os
import sys
import math
import json
import secrets
import string
import requests
import hashlib
from enum import IntFlag
from typing import Tuple

def get_cryptographically_random_bytes(num_bytes: int) -> bytes:
    """Генерация криптобезопасных случайных байтов"""
    return secrets.token_bytes(num_bytes)

def bytes_to_uniform_chars(random_bytes: bytes, charset: str) -> str:
    """Преобразование байтов в символы с равномерным распределением"""
    if not charset:
        raise ValueError("CharSet is empty")
    if not random_bytes:
        return ""

    char_set_size = len(charset)
    result = []
    
    # Преобразование с использованием модульной арифметики
    for i in range(0, len(random_bytes), 4):
        chunk = random_bytes[i:i+4]
        value = int.from_bytes(chunk, byteorder='big', signed=False)
        
        while value > 0:
            result.append(charset[value % char_set_size])
            value = value // char_set_size
            if len(result) >= (len(random_bytes) * 8 // math.ceil(math.log2(char_set_size))):
                break

    return ''.join(result)

def generate_strong_password(length: int, charset: str) -> str:
    """Генерация криптобезопасного пароля"""
    if length <= 0:
        raise ValueError("Password length must be positive")
    if not charset:
        raise ValueError("Empty charset")

    # Увеличенный размер буфера для лучшего распределения
    required_bytes = math.ceil(length * 2)
    random_bytes = get_cryptographically_random_bytes(required_bytes)
    password = bytes_to_uniform_chars(random_bytes, charset)
    
    return password[:length]  # Обрезаем до нужной длины

# Остальные функции остаются без изменений, кроме удаления зависимостей от Crypto
# (add_separators, check_password_strength, get_password_strength_info, 
# PasswordOptions, is_password_pwned, generate_password_with_options, 
# check_user_password, main)

class PasswordOptions(IntFlag):
    OPT_LOWERCASE = 1 << 0
    OPT_UPPERCASE = 1 << 1
    OPT_DIGITS = 1 << 2
    OPT_SPECIAL = 1 << 3
    OPT_NO_DIGITS = 1 << 4
    OPT_SEPARATORS = 1 << 5
    OPT_FULLASCII = 1 << 6
    OPT_AVOID_SIMILAR = 1 << 7
    OPT_NO_REPEAT = 1 << 8
    OPT_RANDOM_CASE = 1 << 9
    OPT_CUSTOM_CHARSET = 1 << 10
    OPT_LANGUAGE_SPECIFIC = 1 << 11
    OPT_OUTPUT_FORMAT = 1 << 12

def is_password_pwned(password: str) -> bool:
    """Проверка пароля через Have I Been Pwned API"""
    try:
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.split(':')[0] == suffix:
                    return True
        return False
    except Exception as e:
        print(f"Ошибка при проверке пароля: {e}")
        return False

def initialize_crypto_libraries():
    """Инициализация криптобиблиотек (пустая, так как используем стандартные)"""
    pass

# Остальные функции (add_separators, check_password_strength и т.д.) 
# остаются без изменений из вашего исходного кода

def main():
    initialize_crypto_libraries()
    
    password_length = 24
    separator = "-"
    group_size = 4
    
    try:
        # Пример использования
        print("Пример генерации пароля:")
        options = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_DIGITS
        password = generate_password_with_options(password_length, options)
        print(f"Сгенерированный пароль: {password}")
        
        # Проверка пароля
        check_user_password(password)
        
    except Exception as ex:
        print(f"Ошибка генерации пароля: {ex}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())









@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_password_api():
    try:
        data = request.get_json()
        options = 0
        for opt in data.get('options', []):
            options |= getattr(PasswordOptions, opt)
        
        password = generate_password_with_options(
            length=data['length'],
            options=PasswordOptions(options),
            separator=data.get('separator', '-'),
            group_size=data.get('group_size', 4),
            custom_charset=data.get('custom_charset', ''),
            language_charset=data.get('language_charset', ''),
            output_format='json' if data.get('json_format') else 'plain'
        )
        
        if data.get('json_format'):
            return jsonify(json.loads(password))
        return jsonify({"password": password})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/check', methods=['POST'])
def check_password_api():
    try:
        data = request.get_json()
        password = data['password']
        
        strength_info = json.loads(get_password_strength_info(password))
        pwned = is_password_pwned(password)
        
        return jsonify({
            "strength": strength_info['strength'],
            "entropy": strength_info['entropy'],
            "time_to_crack": strength_info['timeToCrack'],
            "compromised": pwned
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    initialize_crypto_libraries()
    app.run(debug=True)
