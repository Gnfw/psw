from flask import Flask, render_template, request, jsonify
import math
import secrets
import string
import requests
import hashlib
import re
from enum import IntFlag
from typing import List, Dict, Set
from collections import Counter
import logging
from functools import lru_cache

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
    OPT_AVOID_SIMILAR = 1 << 6
    OPT_NO_REPEAT = 1 << 7
    OPT_RANDOM_CASE = 1 << 8
    OPT_CUSTOM_CHARSET = 1 << 9
    OPT_MNEMONIC = 1 << 10
    OPT_NO_REPEAT_CHARS = 1 << 11

DICTIONARY_URLS = {
    'english': 'https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt',
    'russian': 'https://raw.githubusercontent.com/Harrix/Russian-Nouns/main/dist/russian_nouns.txt'
}

BACKUP_WORDS = ['apple', 'sun', 'moon', 'password', 'security', 'tree', 'flower', 'rocket', 'coffee', 'python',
                'star', 'ocean', 'forest', 'mountain', 'light', 'shadow', 'fire', 'water', 'earth', 'air'] * 5

@lru_cache(maxsize=1)
def load_dictionaries() -> Set[str]:
    all_words = set(BACKUP_WORDS)
    try:
        for lang, url in DICTIONARY_URLS.items():
            response = requests.get(url, timeout=15)
            words = {
                word.strip().lower()
                for word in response.text.splitlines()
                if 5 <= len(word.strip()) <= 8 and word.isalpha()
            }
            all_words.update(words)
    except Exception as e:
        logger.error(f"Dictionary error: {e}")
    return all_words

DICTIONARY = load_dictionaries()

def generate_mnemonic_phrase(
    length: int,
    options: PasswordOptions,
    separator: str = "-"
) -> str:
    rng = secrets.SystemRandom()
    words = [w for w in DICTIONARY if 5 <= len(w) <= 8]
    if not words:
        words = BACKUP_WORDS
    
    # Расчет количества слов
    min_words = max(4, math.ceil(length / 8))
    num_words = min(min_words + 2, 8)
    
    selected = rng.sample(words, num_words)
    
    # Преобразование регистра
    case_modes = []
    if options & PasswordOptions.OPT_RANDOM_CASE:
        case_modes = [str.lower, str.title, str.upper]
    
    phrase = []
    for word in selected:
        if case_modes:
            word = rng.choice(case_modes)(word)
        phrase.append(word)
        
        # Обязательное добавление цифр/спецсимволов
        if options & PasswordOptions.OPT_DIGITS and rng.random() < 0.6:
            phrase.append(str(rng.randint(0, 9)))
        if options & PasswordOptions.OPT_SPECIAL and rng.random() < 0.4:
            phrase.append(rng.choice("!@#$%&*"))
    
    # Гарантированное наличие цифр/символов
    if options & PasswordOptions.OPT_DIGITS and not any(c.isdigit() for c in phrase):
        phrase.insert(rng.randint(1, len(phrase)), str(rng.randint(0, 9)))
    if options & PasswordOptions.OPT_SPECIAL and not any(c in "!@#$%&*" for c in phrase):
        phrase.insert(rng.randint(1, len(phrase)), rng.choice("!@#$%&*"))
    
    return separator.join(phrase)[:length]

def has_uniform_distribution(password: str, threshold: float = 0.25) -> bool:
    counts = Counter(password)
    max_freq = max(counts.values(), default=0)
    return (max_freq / len(password)) > threshold

def check_common_patterns(password: str) -> bool:
    patterns = ['qwerty', '12345', 'password', 'asdfgh', '123456', '111111', 'abc123']
    return any(p in password.lower() for p in patterns)

def check_password_strength(password: str, forbidden_context: List[str] = None) -> Dict:
    warnings = []
    forbidden_context = forbidden_context or []
    
    if forbidden_context:
        context_pattern = re.compile(r'\b(' + '|'.join(map(re.escape, forbidden_context)) + r')\b', re.I)
        if context_pattern.search(password):
            warnings.append("Пароль содержит контекстно-зависимые данные")

    if len(password) < 12:
        warnings.append("Пароль слишком короткий (минимум 12 символов)")
    elif len(password) > 100:
        warnings.append("Пароль слишком длинный (максимум 100 символов)")

    clean_password = re.sub(r'[\d\W_]+', ' ', password.lower())
    if any(word in clean_password.split() for word in DICTIONARY if len(word) >= 4):
        warnings.append("Обнаружено словарное слово")

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-=" for c in password)

    char_set_size = sum([
        26 if has_lower else 0,
        26 if has_upper else 0,
        10 if has_digit else 0,
        32 if has_special else 0
    ]) or 1

    standard_entropy = len(password) * math.log2(char_set_size)
    freq = Counter(password)
    probs = [count/len(password) for count in freq.values()]
    shannon_entropy = -sum(p * math.log2(p) for p in probs) * len(password) if len(password) > 0 else 0
    effective_entropy = 0.7 * standard_entropy + 0.3 * shannon_entropy
    time_to_crack = (2 ** effective_entropy) / 1e10

    score = sum([has_lower, has_upper, has_digit, has_special]) + min(3, len(password) // 12)
    
    checks = [
        (len(set(password)) < 4, "Слишком много повторяющихся символов"),
        (any(password[i] == password[i+1] == password[i+2] for i in range(len(password)-2)),
        "Три повторяющихся символа подряд"),
        (bool(re.search(r'(.)\1{2}', password)), "Повторяющиеся паттерны"),
        (bool(re.search(r'\d{4,}', password)), "Последовательности цифр"),
        (bool(re.search(r'(19|20)\d{2}', password)), "Обнаружен год"),
        (check_common_patterns(password), "Обнаружен опасный паттерн"),
        (has_uniform_distribution(password), "Неравномерное распределение символов")
    ]

    for condition, warning in checks:
        if condition:
            warnings.append(warning)
            score -= 1

    strength = min(max(math.ceil(score / 2), 1), 5)

    return {
        'strength': strength,
        'entropy': {
            'standard': standard_entropy,
            'shannon': shannon_entropy,
            'combined': effective_entropy
        },
        'time_to_crack': time_to_crack,
        'warnings': warnings
    }

def generate_password_with_options(
    length: int,
    options: PasswordOptions,
    separator: str = "-",
    custom_charset: str = ""
) -> str:
    if options & PasswordOptions.OPT_MNEMONIC:
        return generate_mnemonic_phrase(
            length=length,
            separator=separator,
            add_number=bool(options & PasswordOptions.OPT_DIGITS),
            add_special=bool(options & PasswordOptions.OPT_SPECIAL)
        )
    
    charset = ""
    if options & PasswordOptions.OPT_CUSTOM_CHARSET:
        charset = custom_charset
        if len(set(charset)) < 4:
            raise ValueError("Набор символов должен содержать минимум 4 уникальных символа")
    else:
        if options & PasswordOptions.OPT_LOWERCASE:
            charset += string.ascii_lowercase
        if options & PasswordOptions.OPT_UPPERCASE:
            charset += string.ascii_uppercase
        if options & PasswordOptions.OPT_DIGITS and not (options & PasswordOptions.OPT_NO_DIGITS):
            charset += string.digits
        if options & PasswordOptions.OPT_SPECIAL:
            charset += "!@#$%^&*()_+"
        
        if options & PasswordOptions.OPT_AVOID_SIMILAR:
            charset = ''.join(c for c in charset if c not in 'lI10Oo')
    
    if not charset:
        raise ValueError("Не удалось создать набор символов")
    
    password = ''.join(secrets.choice(charset) for _ in range(length))
    
    if options & PasswordOptions.OPT_SEPARATORS:
        password = '-'.join([password[i:i+4] for i in range(0, len(password), 4)])
    
    if options & PasswordOptions.OPT_NO_REPEAT_CHARS:
        password = ''.join(dict.fromkeys(password))
    
    return password[:length]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def handle_generate():
    try:
        data = request.get_json()
        length = int(data.get('length', 16))
        options = sum(getattr(PasswordOptions, opt) for opt in data.get('options', []))
        
        if (options & PasswordOptions.OPT_DIGITS) and (options & PasswordOptions.OPT_NO_DIGITS):
            raise ValueError("Конфликт опций: цифры и исключение цифр")
        
        password = generate_password_with_options(
            length=length,
            options=PasswordOptions(options),
            separator=data.get('separator', '-'),
            custom_charset=data.get('custom_charset', '')
        )
        
        result = check_password_strength(password, data.get('forbidden_context', []))
        pwned = is_password_pwned(password)
        
        return jsonify({
            'password': password,
            'strength': result['strength'],
            'entropy': {k: round(v, 2) for k, v in result['entropy'].items()},
            'time_to_crack': round(result['time_to_crack'], 2),
            'warnings': result['warnings'],
            'compromised': pwned
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/check', methods=['POST'])
def handle_check():
    try:
        data = request.get_json()
        password = data.get('password', '')
        result = check_password_strength(password, data.get('forbidden_context', []))
        result['compromised'] = is_password_pwned(password)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

def is_password_pwned(password: str) -> bool:
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        return any(line.split(':')[0] == suffix for line in response.text.splitlines())
    except Exception:
        return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
