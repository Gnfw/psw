from flask import Flask, render_template, request, jsonify
import math
import secrets
import string
import requests
import hashlib
import re
from enum import IntFlag
from typing import Tuple, List, Dict
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
    
    char_set_size = len(charset)
    result = []
    max_index = char_set_size - 1
    
    # Используем rejection sampling для равномерного распределения
    for byte in random_bytes:
        # Генерируем индекс с использованием всех битов
        for shift in [0, 2, 4, 6]:  # Используем 2 бита за итерацию (4 значения на байт)
            bits = (byte >> shift) & 0x03
            # Генерируем случайное число с помощью secrets.randbelow для устранения смещения
            if max_index > 0:
                index = secrets.randbelow(char_set_size)
                result.append(charset[index])
    
    return ''.join(result)

def generate_strong_password(length: int, charset: str) -> str:
    # Вычисляем необходимые байты с запасом
    char_set_size = len(charset)
    bits_per_char = math.log2(char_set_size) if char_set_size > 0 else 0
    required_bits = length * bits_per_char
    required_bytes = max(math.ceil(required_bits / 8), 1)
    
    random_bytes = get_cryptographically_random_bytes(required_bytes * 2)  # Запас
    password = bytes_to_uniform_chars(random_bytes, charset)
    return password[:length]

def add_separators(password: str, separator: str, group_size: int) -> str:
    if group_size <= 0 or len(password) <= group_size:
        return password
    
    chunks = [password[i:i+group_size] for i in range(0, len(password), group_size)]
    return separator.join(chunks)

def has_sequential_chars(password: str, min_seq: int = 3) -> bool:
    sequences = [
        '0123456789',
        'abcdefghijklmnopqrstuvwxyz',
        'qwertyuiopasdfghjklzxcvbnm'
    ]
    
    password_lower = password.lower()
    for seq in sequences:
        for i in range(len(seq) - min_seq + 1):
            if seq[i:i+min_seq] in password_lower:
                return True
            if seq[i:i+min_seq][::-1] in password_lower:
                return True
    return False

def check_unique_chars(password: str, min_unique: int = 4) -> bool:
    return len(set(password)) >= min_unique if len(password) >= min_unique else False

def has_repeated_patterns(password: str, min_pattern_length: int = 2) -> bool:
    for i in range(len(password) - min_pattern_length * 2 + 1):
        pattern = password[i:i+min_pattern_length]
        if pattern in password[i+min_pattern_length:]:
            return True
    return False

def has_dates(password: str) -> bool:
    patterns = [
        r'\d{1,2}[./-]\d{1,2}[./-]\d{2,4}',
        r'\d{4}',
        r'(19|20)\d{2}'
    ]
    return any(re.search(p, password) for p in patterns)

def has_uniform_distribution(password: str, threshold: float = 0.25) -> bool:
    counts = Counter(password)
    max_freq = max(counts.values()) / len(password) if password else 0
    return max_freq > threshold

def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    
    charset = set(password)
    char_set_size = 0
    
    has_lower = any(c.islower() for c in charset)
    has_upper = any(c.isupper() for c in charset)
    has_digit = any(c.isdigit() for c in charset)
    special_chars = "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-="
    has_special = any(c in special_chars for c in charset)
    
    if has_lower: char_set_size += 26
    if has_upper: char_set_size += 26
    if has_digit: char_set_size += 10
    if has_special: char_set_size += len(special_chars)
    
    # Учитываем реальный размер используемого набора символов
    real_charset_size = len(charset) or 1
    return len(password) * math.log2(real_charset_size) if real_charset_size > 0 else 0

def check_password_strength(password: str) -> Tuple[int, float, float, List[str]]:
    warnings = []
    
    if len(password) < 8:
        return 1, 0.0, 0.0, ["Пароль слишком короткий (минимум 8 символов)"]
    
    # Основные проверки
    entropy = calculate_entropy(password)
    time_to_crack = (2 ** entropy) / (1e12)  # Предполагаем 1 триллион попыток в секунду
    
    score = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    special_chars = "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-="
    has_special = any(c in special_chars for c in password)
    
    score += has_lower + has_upper + has_digit + has_special
    score += min(3, len(password) // 6)
    
    # Штрафы
    penalty = 0
    if has_sequential_chars(password):
        penalty += 1
        warnings.append("Обнаружены последовательные символы")
    
    if not check_unique_chars(password):
        penalty += 1
        warnings.append("Слишком много повторяющихся символов")
    
    if has_repeated_patterns(password):
        penalty += 1
        warnings.append("Обнаружены повторяющиеся паттерны")
    
    if has_dates(password):
        penalty += 1
        warnings.append("Обнаружены даты или годы")
    
    if has_uniform_distribution(password):
        penalty += 1
        warnings.append("Неравномерное распределение символов")
    
    # Проверка на повторяющиеся символы
    for i in range(len(password)-2):
        if password[i] == password[i+1] == password[i+2]:
            penalty += 2
            warnings.append("Обнаружены три повторяющихся символа подряд")
    
    score = max(1, score - penalty)
    
    # Определение уровня сложности
    strength_levels = [
        (1, 30),   # Слабый
        (2, 50),   # Средний
        (3, 70),   # Надежный
        (4, 90),   # Очень надежный
        (5, float('inf'))  # Ультра
    ]
    
    strength = 1
    for level, threshold in strength_levels:
        if entropy >= threshold:
            strength = level
        else:
            break
    
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
            charset = ''.join(c for c in charset if c not in 'lI10Oo')
    
    if not charset:
        raise ValueError("Не удалось создать набор символов")
    
    # Генерация с учетом ограничений
    original_length = length
    if options & PasswordOptions.OPT_SEPARATORS:
        num_separators = (original_length - 1) // group_size
        original_length = max(original_length - num_separators, 1)
    
    if options & PasswordOptions.OPT_NO_REPEAT:
        charset = ''.join(set(charset))
        if len(charset) < original_length:
            raise ValueError("Недостаточно уникальных символов для генерации пароля")
        password = ''.join(secrets.choice(charset) for _ in range(original_length))
    else:
        password = generate_strong_password(original_length, charset)
    
    # Применение дополнительных опций
    if options & PasswordOptions.OPT_RANDOM_CASE:
        password = ''.join(
            secrets.choice([c.upper(), c.lower()]) if c.isalpha() else c
            for c in password
        )
    
    if options & PasswordOptions.OPT_SEPARATORS:
        password = add_separators(password, separator, group_size)
    
    if options & PasswordOptions.OPT_NO_REPEAT and len(password) > original_length:
        password = password[:original_length]
    
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
        
        length = int(data['length'])
        if length < 8 or length > 100:
            return jsonify({"error": "Некорректная длина пароля (8-100)"}), 400
        
        options = 0
        for opt in data.get('options', []):
            if hasattr(PasswordOptions, opt):
                options |= getattr(PasswordOptions, opt)
        
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
    
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Error generating password: {str(e)}")
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
        app.logger.error(f"Error checking password: {str(e)}")
        return jsonify({"error": "Внутренняя ошибка сервера"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
