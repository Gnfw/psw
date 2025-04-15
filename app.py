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

import os
import sys
import math
import json
import random
import secrets
import string
import requests
from enum import Enum, IntFlag
from typing import List, Tuple, Optional, Union

# Библиотеки для криптографии
try:
   try:
    import pycryptodome
    from Crypto.Random import get_random_bytes
except ImportError:
    print("Ошибка: Не удалось импортировать pycryptodome. Установите его с помощью pip install pycryptodome")
    sys.exit(1)

# Инициализация библиотек
def initialize_crypto_libraries():
    try:
        # В Python обычно не требуется явная инициализация
        pass
    except Exception as e:
        raise RuntimeError(f"Ошибка инициализации криптобиблиотек: {e}")

# Функция для получения криптографически случайных байтов
def get_cryptographically_random_bytes(num_bytes: int) -> bytes:
    return secrets.token_bytes(num_bytes)

# Функция для преобразования байтов в символы с равномерным распределением
def bytes_to_uniform_chars(random_bytes: bytes, charset: str) -> str:
    if not charset:
        raise ValueError("CharSet is empty")
    if not random_bytes:
        return ""

    char_set_size = len(charset)
    result = []

    for i in range(0, len(random_bytes), 8):
        chunk = random_bytes[i:i+8]
        value = int.from_bytes(chunk, byteorder='big', signed=False)
        
        while value > 0 and len(result) < (len(random_bytes) * 8 // math.ceil(math.log2(char_set_size))):
            result.append(charset[value % char_set_size])
            value = value // char_set_size

    return ''.join(result)

# Функция для генерации криптографически случайного пароля
def generate_strong_password(length: int, charset: str) -> str:
    if length <= 0:
        raise ValueError("Password length must be positive")
    if not charset:
        raise ValueError("Empty charset")

    required_bytes = math.ceil(length * 8 / 8)
    random_bytes = get_cryptographically_random_bytes(required_bytes)
    password = bytes_to_uniform_chars(random_bytes, charset)
    
    if len(password) < length:
        return generate_strong_password(length, charset)
    
    return password[:length]

# Функция для добавления разделителей
def add_separators(password: str, separator: str, group_size: int) -> str:
    if group_size <= 0:
        raise ValueError("Group size must be positive.")
    if not password:
        return ""

    result = []
    for i, char in enumerate(password):
        result.append(char)
        if (i + 1) % group_size == 0 and (i + 1) != len(password):
            result.append(separator)
    return ''.join(result)

# Функция для проверки надежности пароля (усиленная проверка)
def check_password_strength(password: str) -> Tuple[int, float, float]:
    if len(password) < 8:
        return 1, 0.0, 0.0
    
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    special_chars = "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-="
    has_special = any(c in special_chars for c in password)
    has_ascii = all(33 <= ord(c) <= 126 for c in password)

    char_set_size = 0
    if has_lower:
        char_set_size += 26
    if has_upper:
        char_set_size += 26
    if has_digit:
        char_set_size += 10
    if has_special:
        char_set_size += len(special_chars)
    if has_ascii:
        char_set_size = 94

    if char_set_size == 0:
        char_set_size = 1

    score = 0
    if has_lower:
        score += 1
    if has_upper:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1
    if has_ascii:
        score += 1

    if len(password) >= 24:
        score += 1
    if len(password) >= 32:
        score += 1
    if len(password) >= 48:
        score += 1

    # Проверка на повторения
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return 1, 0.0, 0.0

    entropy = len(password) * math.log2(char_set_size)
    attempts_per_second = 10_000_000_000.0  # 10 миллиардов попыток в секунду
    time_to_crack = (2 ** entropy) / attempts_per_second

    if score >= 8:
        strength = 5  # Ультра надежный
    elif score >= 7:
        strength = 4  # Очень надежный
    elif score >= 5:
        strength = 3  # Надежный
    elif score >= 3:
        strength = 2  # Средний
    else:
        strength = 1  # Слабый

    return strength, entropy, time_to_crack

# Функция для получения информации о надежности пароля в формате JSON
def get_password_strength_info(password: str) -> str:
    strength, entropy, time_to_crack = check_password_strength(password)
    
    strength_descriptions = {
        1: "Слабый",
        2: "Средний",
        3: "Надежный",
        4: "Очень надежный",
        5: "Ультра надежный"
    }
    
    strength_description = strength_descriptions.get(strength, "Неизвестный")
    
    return json.dumps({
        "strength": strength_description,
        "entropy": round(entropy, 2),
        "timeToCrack": time_to_crack
    }, ensure_ascii=False)

# Битовые флаги для опций генерации
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

# Функция для проверки пароля на утечки с использованием Have I Been Pwned API
def is_password_pwned(password: str) -> bool:
    try:
        import hashlib
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

# Функция для генерации пароля с заданными опциями
def generate_password_with_options(
    length: int,
    options: PasswordOptions,
    separator: str = "-",
    group_size: int = 4,
    custom_charset: str = "",
    language_charset: str = "",
    output_format: str = "plain"
) -> str:
    charset = ""
    
    if options & PasswordOptions.OPT_CUSTOM_CHARSET and custom_charset:
        charset = custom_charset
    elif options & PasswordOptions.OPT_LANGUAGE_SPECIFIC and language_charset:
        charset = language_charset
    elif options & PasswordOptions.OPT_FULLASCII:
        charset = string.printable[:94]  # ASCII 33-126
    else:
        if options & PasswordOptions.OPT_LOWERCASE:
            charset += string.ascii_lowercase
        if options & PasswordOptions.OPT_UPPERCASE:
            charset += string.ascii_uppercase
        if options & PasswordOptions.OPT_DIGITS:
            charset += string.digits
        if options & PasswordOptions.OPT_SPECIAL:
            charset += "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-="
        
        if options & PasswordOptions.OPT_NO_DIGITS and not (options & PasswordOptions.OPT_DIGITS):
            charset = ''.join(c for c in charset if not c.isdigit())
        
        if options & PasswordOptions.OPT_AVOID_SIMILAR:
            charset = ''.join(c for c in charset if c not in 'lI10Oo')

    if not charset:
        raise ValueError("Не удалось создать набор символов для пароля")

    password = ""
    while True:
        password = generate_strong_password(length, charset)
        strength, _, _ = check_password_strength(password)
        if not is_password_pwned(password) and strength != 1:
            break

    if options & PasswordOptions.OPT_RANDOM_CASE:
        password = ''.join(
            c.upper() if secrets.randbelow(2) else c.lower()
            for c in password
        )
    
    if options & PasswordOptions.OPT_SEPARATORS:
        password = add_separators(password, separator, group_size)
    
    if options & PasswordOptions.OPT_NO_REPEAT:
        password = ''.join(dict.fromkeys(password))[:length]
    
    if options & PasswordOptions.OPT_OUTPUT_FORMAT and output_format == "json":
        return json.dumps({"password": password}, ensure_ascii=False)
    
    return password

# Функция для проверки пользовательского пароля
def check_user_password(password: str):
    strength, entropy, time_to_crack = check_password_strength(password)
    
    strength_descriptions = {
        1: "Слабый",
        2: "Средний",
        3: "Надежный",
        4: "Очень надежный",
        5: "Ультра надежный"
    }
    
    strength_description = strength_descriptions.get(strength, "Неизвестный")
    
    print("Информация о надежности пароля:")
    print(f"Надежность: {strength_description}")
    print(f"Энтропия: {entropy:.2f}")
    print(f"Время подбора: {time_to_crack} секунд")
    
    if is_password_pwned(password):
        print("Внимание! Этот пароль был скомпрометирован.")
    else:
        print("Пароль не был скомпрометирован.")

def main():
    initialize_crypto_libraries()
    
    password_length = 24
    separator = "-"
    group_size = 4
    
    try:
        # 1. Пароль по умолчанию (все символы, с разделителями)
        print("1. Пароль по умолчанию (все символы, с разделителями):")
        options1 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_DIGITS | PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_SEPARATORS
        password1 = generate_password_with_options(password_length, options1, separator, group_size)
        print(f"Сгенерированный пароль: {password1}")
        print(f"Длина пароля: {len(password1)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password1)}")
        print("-----------------------------------")
        
        # 2. Пароль только из строчных букв, без разделителей
        print("2. Пароль только из строчных букв, без разделителей:")
        options2 = PasswordOptions.OPT_LOWERCASE
        password2 = generate_password_with_options(password_length, options2)
        print(f"Сгенерированный пароль: {password2}")
        print(f"Длина пароля: {len(password2)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password2)}")
        print("-----------------------------------")
        
        # 3. Пароль из строчных букв и цифр, с разделителями
        print("3. Пароль из строчных букв и цифр, с разделителями:")
        options3 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_DIGITS | PasswordOptions.OPT_SEPARATORS
        password3 = generate_password_with_options(password_length, options3, separator, group_size)
        print(f"Сгенерированный пароль: {password3}")
        print(f"Длина пароля: {len(password3)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password3)}")
        print("-----------------------------------")
        
        # 4. Пароль без цифр и с разделителями, только из спецсимволов
        print("4. Пароль без цифр и с разделителями, только из спецсимволов:")
        options4 = PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_NO_DIGITS | PasswordOptions.OPT_SEPARATORS
        password4 = generate_password_with_options(password_length, options4, separator, group_size)
        print(f"Сгенерированный пароль: {password4}")
        print(f"Длина пароля: {len(password4)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password4)}")
        print("-----------------------------------")
        
        # 5. Пароль только из прописных букв и цифр
        print("5. Пароль только из прописных букв и цифр:")
        options5 = PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_DIGITS
        password5 = generate_password_with_options(password_length, options5)
        print(f"Сгенерированный пароль: {password5}")
        print(f"Длина пароля: {len(password5)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password5)}")
        print("-----------------------------------")
        
        # 6. Пароль из полного ASCII набора, с разделителями
        print("6. Пароль из полного ASCII набора, с разделителями:")
        options6 = PasswordOptions.OPT_FULLASCII | PasswordOptions.OPT_SEPARATORS
        password6 = generate_password_with_options(password_length, options6, separator, group_size)
        print(f"Сгенерированный пароль: {password6}")
        print(f"Длина пароля: {len(password6)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password6)}")
        print("-----------------------------------")
        
        # 7. Пароль без похожих символов
        print("7. Пароль без похожих символов:")
        options7 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_DIGITS | PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_AVOID_SIMILAR
        password7 = generate_password_with_options(password_length, options7)
        print(f"Сгенерированный пароль: {password7}")
        print(f"Длина пароля: {len(password7)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password7)}")
        print("-----------------------------------")
        
        # 8. Пароль без повторяющихся символов
        print("8. Пароль без повторяющихся символов:")
        options8 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_DIGITS | PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_NO_REPEAT
        password8 = generate_password_with_options(password_length, options8)
        print(f"Сгенерированный пароль: {password8}")
        print(f"Длина пароля: {len(password8)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password8)}")
        print("-----------------------------------")
        
        # 9. Пароль со случайным регистром
        print("9. Пароль со случайным регистром:")
        options9 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_DIGITS | PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_RANDOM_CASE
        password9 = generate_password_with_options(password_length, options9)
        print(f"Сгенерированный пароль: {password9}")
        print(f"Длина пароля: {len(password9)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password9)}")
        print("-----------------------------------")
        
        # 10. Пароль с пользовательским набором символов
        print("10. Пароль с пользовательским набором символов (пример 'abc123!@#'):")
        options10 = PasswordOptions.OPT_CUSTOM_CHARSET
        custom_charset = "abc123!@#"
        password10 = generate_password_with_options(password_length, options10, separator, group_size, custom_charset)
        print(f"Сгенерированный пароль: {password10}")
        print(f"Длина пароля: {len(password10)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password10)}")
        print("-----------------------------------")
        
        # 11. Пароль с поддержкой различных языков (пример 'русский')
        print("11. Пароль с поддержкой различных языков (пример 'русский'):")
        options11 = PasswordOptions.OPT_LANGUAGE_SPECIFIC
        language_charset = "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
        password11 = generate_password_with_options(password_length, options11, separator, group_size, "", language_charset)
        print(f"Сгенерированный пароль: {password11}")
        print(f"Длина пароля: {len(password11)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password11)}")
        print("-----------------------------------")
        
        # 12. Пароль с поддержкой различных форматов вывода (пример JSON)
        print("12. Пароль с поддержкой различных форматов вывода (пример JSON):")
        options12 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_DIGITS | PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_OUTPUT_FORMAT
        output_format = "json"
        password12 = generate_password_with_options(password_length, options12, separator, group_size, "", "", output_format)
        print(f"Сгенерированный пароль: {password12}")
        print(f"Длина пароля: {len(password12)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password12)}")
        print("-----------------------------------")
        
        # 13. Пароль с использованием только специальных символов и цифр
        print("13. Пароль с использованием только специальных символов и цифр:")
        options13 = PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_DIGITS
        password13 = generate_password_with_options(password_length, options13)
        print(f"Сгенерированный пароль: {password13}")
        print(f"Длина пароля: {len(password13)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password13)}")
        print("-----------------------------------")
        
        # 14. Пароль с использованием только строчных букв и специальных символов
        print("14. Пароль с использованием только строчных букв и специальных символов:")
        options14 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_SPECIAL
        password14 = generate_password_with_options(password_length, options14)
        print(f"Сгенерированный пароль: {password14}")
        print(f"Длина пароля: {len(password14)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password14)}")
        print("-----------------------------------")
        
        # 15. Пароль с использованием только прописных букв и специальных символов
        print("15. Пароль с использованием только прописных букв и специальных символов:")
        options15 = PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_SPECIAL
        password15 = generate_password_with_options(password_length, options15)
        print(f"Сгенерированный пароль: {password15}")
        print(f"Длина пароля: {len(password15)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password15)}")
        print("-----------------------------------")
        
        # 16. Пароль с использованием только строчных букв, прописных букв и цифр
        print("16. Пароль с использованием только строчных букв, прописных букв и цифр:")
        options16 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_DIGITS
        password16 = generate_password_with_options(password_length, options16)
        print(f"Сгенерированный пароль: {password16}")
        print(f"Длина пароля: {len(password16)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password16)}")
        print("-----------------------------------")
        
        # 17. Пароль с использованием только строчных букв, прописных букв и специальных символов
        print("17. Пароль с использованием только строчных букв, прописных букв и специальных символов:")
        options17 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_SPECIAL
        password17 = generate_password_with_options(password_length, options17)
        print(f"Сгенерированный пароль: {password17}")
        print(f"Длина пароля: {len(password17)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password17)}")
        print("-----------------------------------")
        
        # 18. Пароль с использованием только цифр и специальных символов, с разделителями
        print("18. Пароль с использованием только цифр и специальных символов, с разделителями:")
        options18 = PasswordOptions.OPT_DIGITS | PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_SEPARATORS
        password18 = generate_password_with_options(password_length, options18, separator, group_size)
        print(f"Сгенерированный пароль: {password18}")
        print(f"Длина пароля: {len(password18)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password18)}")
        print("-----------------------------------")
        
        # 19. Пароль с использованием только строчных букв и специальных символов, с разделителями
        print("19. Пароль с использованием только строчных букв и специальных символов, с разделителями:")
        options19 = PasswordOptions.OPT_LOWERCASE | PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_SEPARATORS
        password19 = generate_password_with_options(password_length, options19, separator, group_size)
        print(f"Сгенерированный пароль: {password19}")
        print(f"Длина пароля: {len(password19)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password19)}")
        print("-----------------------------------")
        
        # 20. Пароль с использованием только прописных букв и специальных символов, с разделителями
        print("20. Пароль с использованием только прописных букв и специальных символов, с разделителями:")
        options20 = PasswordOptions.OPT_UPPERCASE | PasswordOptions.OPT_SPECIAL | PasswordOptions.OPT_SEPARATORS
        password20 = generate_password_with_options(password_length, options20, separator, group_size)
        print(f"Сгенерированный пароль: {password20}")
        print(f"Длина пароля: {len(password20)} символов.")
        print(f"Информация о надежности: {get_password_strength_info(password20)}")
        print("-----------------------------------")
        
        # Пример проверки пользовательского пароля
        print("Пример проверки пользовательского пароля:")
        user_password = input("Введите пароль для проверки: ")
        check_user_password(user_password)
        print("-----------------------------------")
        
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
