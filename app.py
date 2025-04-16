from flask import Flask, render_template, request, jsonify
import math
import secrets
import string
import requests
import hashlib
from enum import IntFlag
from typing import Tuple

app = Flask(__name__)

# Класс опций пароля
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

# Основные функции
def get_cryptographically_random_bytes(num_bytes: int) -> bytes:
    return secrets.token_bytes(num_bytes)

def bytes_to_uniform_chars(random_bytes: bytes, charset: str) -> str:
    if not charset:
        raise ValueError("CharSet is empty")
    
    char_set_size = len(charset)
    result = []
    
    for i in range(0, len(random_bytes), 4):
        chunk = random_bytes[i:i+4]
        value = int.from_bytes(chunk, byteorder='big')
        
        while value > 0:
            result.append(charset[value % char_set_size])
            value = value // char_set_size
    
    return ''.join(result)

def generate_strong_password(length: int, charset: str) -> str:
    required_bytes = math.ceil(length * 2)
    random_bytes = get_cryptographically_random_bytes(required_bytes)
    password = bytes_to_uniform_chars(random_bytes, charset)
    return password[:length]

def add_separators(password: str, separator: str, group_size: int) -> str:
    if group_size <= 0:
        return password
    
    result = []
    for i, char in enumerate(password):
        if i > 0 and i % group_size == 0:
            result.append(separator)
        result.append(char)
    return ''.join(result)

def check_password_strength(password: str) -> Tuple[int, float, float]:
    if len(password) < 8:
        return 1, 0.0, 0.0
    
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    special_chars = "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-="
    has_special = any(c in special_chars for c in password)
    
    char_set_size = 0
    if has_lower: char_set_size += 26
    if has_upper: char_set_size += 26
    if has_digit: char_set_size += 10
    if has_special: char_set_size += len(special_chars)
    
    if char_set_size == 0: char_set_size = 1
    
    entropy = len(password) * math.log2(char_set_size)
    time_to_crack = (2 ** entropy) / 1e10  # 10 млрд попыток/сек
    
    score = sum([has_lower, has_upper, has_digit, has_special])
    score += min(3, len(password) // 8)
    
    for i in range(len(password)-2):
        if password[i] == password[i+1] == password[i+2]:
            return 1, entropy, time_to_crack
    
    strength = 1
    if score >= 8: strength = 5
    elif score >= 7: strength = 4
    elif score >= 5: strength = 3
    elif score >= 3: strength = 2
    
    return strength, entropy, time_to_crack

def is_password_pwned(password: str) -> bool:
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        return any(line.startswith(suffix) for line in response.text.splitlines())
    except Exception:
        return False

def generate_password_with_options(
    length: int,
    options: PasswordOptions,
    separator: str = "-",
    group_size: int = 4,
    custom_charset: str = "",
    language_charset: str = ""
) -> str:
    charset = ""
    
    if options & PasswordOptions.OPT_CUSTOM_CHARSET:
        charset = custom_charset
    elif options & PasswordOptions.OPT_LANGUAGE_SPECIFIC:
        charset = language_charset
    elif options & PasswordOptions.OPT_FULLASCII:
        charset = string.printable[:94]
    else:
        if options & PasswordOptions.OPT_LOWERCASE:
            charset += string.ascii_lowercase
        if options & PasswordOptions.OPT_UPPERCASE:
            charset += string.ascii_uppercase
        if options & PasswordOptions.OPT_DIGITS:
            charset += string.digits
        if options & PasswordOptions.OPT_SPECIAL:
            charset += "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-="
        
        if options & PasswordOptions.OPT_NO_DIGITS:
            charset = ''.join(c for c in charset if not c.isdigit())
        
        if options & PasswordOptions.OPT_AVOID_SIMILAR:
            charset = ''.join(c for c in charset if c not in 'lI10Oo')
    
    if not charset:
        raise ValueError("Не удалось создать набор символов")
    
    password = generate_strong_password(length, charset)
    
    if options & PasswordOptions.OPT_RANDOM_CASE:
        password = ''.join(secrets.choice([c.upper(), c.lower()]) for c in password)
    
    if options & PasswordOptions.OPT_SEPARATORS:
        password = add_separators(password, separator, group_size)
    
    if options & PasswordOptions.OPT_NO_REPEAT:
        password = ''.join(dict.fromkeys(password))
    
    return password[:length]

# Маршруты Flask
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_password():
    try:
        data = request.get_json()
        
        # Валидация данных
        if not data or 'length' not in data:
            return jsonify({"error": "Не указана длина пароля"}), 400
        
        length = int(data['length'])
        if length < 8 or length > 100:
            return jsonify({"error": "Некорректная длина пароля (8-100)"}), 400
        
        # Парсинг опций
        options = 0
        for opt in data.get('options', []):
            if hasattr(PasswordOptions, opt):
                options |= getattr(PasswordOptions, opt)
        
        # Генерация пароля
        password = generate_password_with_options(
            length=length,
            options=PasswordOptions(options),
            separator=data.get('separator', '-'),
            group_size=data.get('group_size', 4),
            custom_charset=data.get('custom_charset', ''),
            language_charset=data.get('language_charset', '')
        )
        
        return jsonify({
            "password": password,
            "strength": check_password_strength(password)[0]
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
