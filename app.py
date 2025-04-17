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
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    OPT_NO_REPEAT_CHARS = 1 << 13
    OPT_UNICODE = 1 << 14

DICTIONARY_URLS = {
    'english': 'https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt',
    'russian': 'https://raw.githubusercontent.com/Harrix/rus-wordlist/main/wordlist.txt'
}

DICTIONARY = set()

def load_online_dictionary(url: str) -> set:
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return set(word.strip().lower() for word in response.text.splitlines() if word.strip())
    except Exception as e:
        logger.error(f"Dictionary load error: {e}")
        return set()

try:
    DICTIONARY.update(load_online_dictionary(DICTIONARY_URLS['english']))
    DICTIONARY.update(load_online_dictionary(DICTIONARY_URLS['russian']))
    logger.info(f"Loaded {len(DICTIONARY)} dictionary words")
except Exception as e:
    logger.error(f"Failed to load dictionaries: {e}")

def get_cryptographically_random_bytes(num_bytes: int) -> bytes:
    return secrets.token_bytes(num_bytes)

def bytes_to_uniform_chars(random_bytes: bytes, charset: str) -> str:
    if not charset:
        raise ValueError("Empty charset")
    
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
    return bytes_to_uniform_chars(random_bytes, charset)[:length]

def add_separators(password: str, separator: str, group_size: int) -> str:
    if group_size <= 0:
        return password
    return separator.join([password[i:i+group_size] for i in range(0, len(password), group_size)])

def has_sequential_chars(password: str, min_seq: int = 3) -> bool:
    sequences = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiopasdfghjklzxcvbnm']
    password_lower = password.lower()
    return any(seq[i:i+min_seq] in password_lower or seq[i:i+min_seq][::-1] in password_lower
               for seq in sequences for i in range(len(seq) - min_seq + 1))

def is_dictionary_word(password: str) -> bool:
    if not DICTIONARY:
        return False
    words = re.findall(r'[a-zA-Zа-яА-Я]+', password.lower())
    return any(word in DICTIONARY for word in words)

def check_password_strength(password: str) -> Tuple[int, float, float, List[str]]:
    warnings = []
    
    if len(password) < 8:
        warnings.append("Пароль слишком короткий (минимум 8 символов)")
    
    if is_dictionary_word(password):
        warnings.append("Пароль содержит словарное слово")

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    special_chars = "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-="
    has_special = any(c in special_chars for c in password)
    
    char_set_size = sum([
        26 if has_lower else 0,
        26 if has_upper else 0,
        10 if has_digit else 0,
        len(special_chars) if has_special else 0
    ]) or 1
    
    entropy = len(password) * math.log2(char_set_size)
    time_to_crack = (2 ** entropy) / 1e10
    
    score = sum([has_lower, has_upper, has_digit, has_special]) + min(3, len(password) // 8)
    
    checks = [
        (has_sequential_chars(password), "Обнаружены последовательные символы"),
        (len(set(password)) < 4, "Слишком много повторяющихся символов"),
        (has_repeated_patterns(password), "Обнаружены повторяющиеся паттерны"),
        (has_dates(password), "Обнаружены даты или годы"),
        (has_uniform_distribution(password), "Неравномерное распределение символов"),
        (any(password[i] == password[i+1] == password[i+2] for i in range(len(password)-2)), 
         "Обнаружены три повторяющихся символа подряд")
    ]
    
    for condition, warning in checks:
        if condition:
            warnings.append(warning)
            score -= 1
    
    strength = min(max(math.ceil(score / 2), 1), 5)
    return strength, entropy, time_to_crack, warnings

def has_repeated_patterns(password: str, min_pattern_length: int = 2) -> bool:
    return any(password[i:i+min_pattern_length] in password[i+min_pattern_length:] 
              for i in range(len(password) - min_pattern_length * 2 + 1))

def has_dates(password: str) -> bool:
    return any(re.search(p, password) for p in [
        r'\d{1,2}[./-]\d{1,2}[./-]\d{2,4}', r'\d{4}', r'(19|20)\d{2}'
    ])

def has_uniform_distribution(password: str, threshold: float = 0.5) -> bool:
    counts = Counter(password)
    return max(counts.values()) / len(password) > threshold

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
    elif options & PasswordOptions.OPT_UNICODE:
        charset = ''.join(chr(c) for c in 
            list(range(0x0021, 0x007E)) + 
            list(range(0x00A1, 0x00FF)) + 
            list(range(0x0100, 0x017F)) + 
            list(range(0x2000, 0x206F)))
    elif options & PasswordOptions.OPT_FULLASCII:
        charset = string.printable[:94]
    else:
        charset += string.ascii_lowercase if options & PasswordOptions.OPT_LOWERCASE else ""
        charset += string.ascii_uppercase if options & PasswordOptions.OPT_UPPERCASE else ""
        charset += string.digits if options & PasswordOptions.OPT_DIGITS else ""
        charset += "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-=" if options & PasswordOptions.OPT_SPECIAL else ""
        
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
    
    if options & (PasswordOptions.OPT_NO_REPEAT | PasswordOptions.OPT_NO_REPEAT_CHARS):
        password = ''.join(dict.fromkeys(password))
    
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
        
        pwned = is_password_pwned(password)
        strength, entropy, time_to_crack, warnings = check_password_strength(password)
        
        return jsonify({
            "password": password,
            "strength": strength,
            "compromised": pwned,
            "warnings": warnings,
            "entropy": entropy,
            "time_to_crack": time_to_crack
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

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
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
