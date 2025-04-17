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
    OPT_AVOID_SIMILAR = 1 << 7
    OPT_NO_REPEAT = 1 << 8

def generate_strong_password(length: int, charset: str, no_repeat: bool) -> str:
    charset_list = list(charset)
    if no_repeat:
        if len(set(charset_list)) < length:
            raise ValueError("Недостаточно уникальных символов")
        secrets.SystemRandom().shuffle(charset_list)
        return ''.join(charset_list[:length])
    return ''.join(secrets.choice(charset_list) for _ in range(length))

def check_password_strength(password: str) -> Tuple[int, float, float, List[str]]:
    warnings = []
    length = len(password)
    
    if length < 8:
        return 1, 0.0, 0.0, ["Пароль слишком короткий"]
    
    unique_chars = len(set(password))
    entropy = length * math.log2(unique_chars) if unique_chars > 0 else 0
    time_to_crack = (2 ** entropy) / 1e9  # 1 миллиард попыток/сек
    
    strength_levels = [
        (5, 120, "Ультра надежный"),
        (4, 80, "Очень надежный"),
        (3, 60, "Надежный"),
        (2, 40, "Средний"),
        (1, 0, "Слабый")
    ]
    
    strength = next((level for level, th, _ in strength_levels if entropy >= th), 1)
    
    # Проверка проблем
    if re.search(r'(.)\1{2}', password):
        warnings.append("Повторяющиеся символы")
    if unique_chars < 4:
        warnings.append("Мало уникальных символов")
    
    return strength, round(entropy, 2), time_to_crack, warnings

def is_password_pwned(password: str) -> bool:
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        return any(line.split(':')[0] == suffix for line in response.text.splitlines())
    except Exception:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def handle_generate():
    try:
        data = request.get_json()
        length = int(data.get('length', 12))
        options = PasswordOptions(0)
        no_repeat = PasswordOptions.OPT_NO_REPEAT in options
        
        # Формирование charset
        charset = []
        if PasswordOptions.OPT_LOWERCASE in options:
            charset.extend(string.ascii_lowercase)
        if PasswordOptions.OPT_UPPERCASE in options:
            charset.extend(string.ascii_uppercase)
        if PasswordOptions.OPT_DIGITS in options and not PasswordOptions.OPT_NO_DIGITS in options:
            charset.extend(string.digits)
        if PasswordOptions.OPT_SPECIAL in options:
            charset.extend('!@#$%^&*()_+-=')
            
        if PasswordOptions.OPT_AVOID_SIMILAR in options:
            charset = [c for c in charset if c not in 'lI10Oo']
        
        charset = list(set(charset))  # Уникальные символы
        
        if not charset:
            raise ValueError("Недостаточно символов для генерации")
        
        # Генерация пароля
        password = generate_strong_password(length, charset, no_repeat)
        
        # Проверка на повторения при активированной опции
        if no_repeat and len(set(password)) != len(password):
            raise ValueError("Ошибка генерации без повторов")
        
        strength, *_ = check_password_strength(password)
        
        return jsonify({
            "password": password,
            "strength": strength,
            "entropy": check_password_strength(password)[1]
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/check', methods=['POST'])
def handle_check():
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        strength, entropy, time, warnings = check_password_strength(password)
        pwned = is_password_pwned(password)
        
        strength_labels = {
            1: "Слабый",
            2: "Средний", 
            3: "Надежный",
            4: "Очень надежный",
            5: "Ультра надежный"
        }
        
        return jsonify({
            "strength": strength_labels.get(strength, "Неизвестно"),
            "entropy": entropy,
            "time_to_crack": time,
            "compromised": pwned,
            "warnings": warnings,
            "recommendation": "Смените пароль немедленно!" if pwned else 
                            "Используйте более сложный пароль" if strength < 3 else 
                            "Пароль надежен"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
