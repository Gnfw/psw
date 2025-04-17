from flask import Flask, render_template, request, jsonify
import math
import secrets
import string
import requests
import hashlib
import re
from enum import IntFlag
from typing import Tuple, List
from collections import Counter

app = Flask(__name__)

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

def get_cryptographically_random_bytes(num_bytes: int) -> bytes:
    return secrets.token_bytes(num_bytes)

def bytes_to_uniform_chars(random_bytes: bytes, charset: str) -> str:
    if not charset:
        raise ValueError("CharSet is empty")
    
    charset_size = len(charset)
    max_index = charset_size - 1
    result = []
    
    for byte in random_bytes:
        for shift in [0, 2, 4, 6]:
            bits = (byte >> shift) & 0x03
            if max_index > 0:
                index = secrets.randbelow(charset_size)
                result.append(charset[index])
    
    return ''.join(result)

def generate_strong_password(length: int, charset: str) -> str:
    charset_size = len(charset)
    bits_per_char = math.log2(charset_size) if charset_size > 0 else 0
    required_bits = length * bits_per_char
    required_bytes = max(math.ceil(required_bits / 8), 1)
    
    random_bytes = get_cryptographically_random_bytes(required_bytes * 2)
    password = bytes_to_uniform_chars(random_bytes, charset)
    return password[:length]

def add_separators(password: str, separator: str, group_size: int) -> str:
    if group_size <= 0 or len(password) <= group_size:
        return password
    return separator.join([password[i:i+group_size] for i in range(0, len(password), group_size)])

def has_sequential_chars(password: str, min_seq: int = 3) -> bool:
    sequences = [
        '0123456789',
        'abcdefghijklmnopqrstuvwxyz',
        'qwertyuiopasdfghjklzxcvbnm'
    ]
    
    lower_pass = password.lower()
    return any(seq[i:i+min_seq] in lower_pass or seq[i:i+min_seq][::-1] in lower_pass
               for seq in sequences for i in range(len(seq) - min_seq + 1))

def check_unique_chars(password: str, min_unique: int = 4) -> bool:
    return len(set(password)) >= min_unique

def has_repeated_patterns(password: str, min_pattern_length: int = 2) -> bool:
    return any(password[i:i+min_pattern_length] in password[i+min_pattern_length:]
              for i in range(len(password) - min_pattern_length * 2 + 1))

def has_uniform_distribution(password: str, threshold: float = 0.25) -> bool:
    counts = Counter(password)
    max_freq = max(counts.values()) / len(password) if password else 0
    return max_freq > threshold

def check_password_strength(password: str) -> Tuple[int, float, float, List[str]]:
    warnings = []
    length = len(password)
    
    if length < 8:
        return 1, 0.0, 0.0, ["Пароль слишком короткий (минимум 8 символов)"]
    
    unique_chars = len(set(password))
    entropy_per_char = math.log2(unique_chars) if unique_chars > 0 else 0
    entropy = length * entropy_per_char
    time_to_crack = (2 ** entropy) / (1e12 * 1e6)  # 1 трлн попыток/сек * 1 млн ядер

    # Критерии оценки
    strength_rules = [
        (5, 120, "Ультра надежный"),
        (4, 80, "Очень надежный"),
        (3, 60, "Надежный"),
        (2, 40, "Средний"),
        (1, 0, "Слабый")
    ]
    
    strength = next((level for level, threshold, _ in strength_rules if entropy >= threshold), 1)
    
    # Проверка проблем
    if has_sequential_chars(password):
        warnings.append("Обнаружены последовательные символы")
    if has_repeated_patterns(password):
        warnings.append("Обнаружены повторяющиеся паттерны")
    if has_uniform_distribution(password):
        warnings.append("Неравномерное распределение символов")
    if any(password[i] == password[i+1] == password[i+2] for i in range(len(password)-2)):
        warnings.append("Обнаружены три повторяющихся символа подряд")

    return strength, entropy, time_to_crack, warnings

def is_password_pwned(password: str) -> bool:
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        return any(line.split(':')[0] == suffix for line in response.text.splitlines())
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
        if len(set(charset)) < 4:
            raise ValueError("Набор символов должен содержать минимум 4 уникальных символа")
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
            similar = {'l', 'I', '1', '0', 'O', 'o'}
            filtered = [c for c in charset if c not in similar]
            if len(filtered) < 20:
                raise ValueError("Недостаточно символов после фильтрации похожих")
            charset = ''.join(filtered)
    
    if not charset:
        raise ValueError("Не удалось создать набор символов")
    
    # Генерация с учетом разделителей
    original_length = length
    if options & PasswordOptions.OPT_SEPARATORS:
        num_separators = (original_length - 1) // group_size
        original_length = max(original_length - num_separators, 1)
    
    if options & PasswordOptions.OPT_NO_REPEAT:
        charset = ''.join(set(charset))
        if len(charset) < original_length:
            raise ValueError("Недостаточно уникальных символов")
        password = ''.join(secrets.choice(charset) for _ in range(original_length))
    else:
        password = generate_strong_password(original_length, charset)
    
    if options & PasswordOptions.OPT_RANDOM_CASE:
        password = ''.join(secrets.choice([c.upper(), c.lower()]) if c.isalpha() else c for c in password)
    
    if options & PasswordOptions.OPT_SEPARATORS:
        password = add_separators(password, separator, group_size)
    
    return password[:length]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_password():
    try:
        data = request.get_json()
        if not data or 'length' not in data:
            return jsonify({"error": "Не указана длина пароля"}), 400
        
        length = int(data.get('length', 12))
        if length < 8 or length > 100:
            return jsonify({"error": "Некорректная длина пароля (8-100)"}), 400
        
        options = PasswordOptions(0)
        for opt in data.get('options', []):
            if hasattr(PasswordOptions, opt):
                options |= getattr(PasswordOptions, opt)
        
        password = generate_password_with_options(
            length=length,
            options=options,
            separator=data.get('separator', '-'),
            group_size=data.get('group_size', 4),
            custom_charset=data.get('custom_charset', ''),
            language_charset=data.get('language_charset', '')
        )
        
        strength, *_ = check_password_strength(password)
        return jsonify({"password": password, "strength": strength})
    
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"Generation error: {str(e)}")
        return jsonify({"error": "Внутренняя ошибка сервера"}), 500

@app.route('/check', methods=['POST'])
def check_password():
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({"error": "Не указан пароль"}), 400
        
        password = data['password']
        strength, entropy, time_to_crack, warnings = check_password_strength(password)
        pwned = is_password_pwned(password)
        
        strength_labels = {
            1: "Слабый",
            2: "Средний",
            3: "Надежный",
            4: "Очень надежный",
            5: "Ультра надежный"
        }
        
        return jsonify({
            "strength": strength_labels.get(strength, "Неизвестный"),
            "entropy": round(entropy, 2),
            "time_to_crack": round(time_to_crack, 2),
            "compromised": pwned,
            "warnings": warnings,
            "recommendation": "Срочно измените пароль!" if pwned else 
                            "Используйте более сложный пароль" if strength < 3 else 
                            "Пароль соответствует стандартам безопасности"
        })
        
    except Exception as e:
        app.logger.error(f"Check error: {str(e)}")
        return jsonify({"error": "Внутренняя ошибка сервера"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
