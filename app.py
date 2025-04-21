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
    OPT_UNICODE = 1 << 12

DICTIONARY_URLS = {
    'english': 'https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt',
    'russian': 'https://raw.githubusercontent.com/Harrix/Russian-Nouns/main/dist/russian_nouns.txt'
}

RUSSIAN_LETTERS = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
BACKUP_WORDS = {
    'english': ['apple', 'sun', 'moon', 'tree', 'flower'],
    'russian': ['солнце', 'луна', 'дерево', 'цветок', 'кофе']
}

UNICODE_CHARS = "★☺♫♪♣♠♥♦✓✔✗✘∞≈≠≤≥±−×÷←↑→↓↔↕↨∂∅∆∈∏∑√∛∜∩∪∧∨¬≡≢⌈⌉⌊⌋◊"
SEPARATORS = "-_!@#$%&*"

@lru_cache(maxsize=2)
def load_dictionary(lang: str) -> Set[str]:
    all_words = set(BACKUP_WORDS.get(lang, []))
    try:
        response = requests.get(DICTIONARY_URLS[lang], timeout=15)
        words = {
            word.strip().lower()
            for word in response.text.splitlines()
            if 4 <= len(word.strip()) <= 8
        }
        all_words.update(words)
    except Exception as e:
        logger.error(f"Ошибка загрузки словаря ({lang}): {e}")
    return all_words

def generate_mnemonic_phrase(length: int, options: PasswordOptions, langs: List[str]) -> str:
    rng = secrets.SystemRandom()
    words = []
    for lang in langs:
        if lang not in DICTIONARY_URLS:
            raise ValueError(f"Неподдерживаемый язык: {lang}")
        words.extend(load_dictionary(lang))
    
    if not words:
        words = [w for lang in langs for w in BACKUP_WORDS.get(lang, [])]
        if not words:
            raise ValueError("Не удалось загрузить словарь для генерации фразы")

    base_word_count = max(4, math.ceil(length / 7))
    num_words = min(base_word_count + 2, 8)
    
    try:
        selected = rng.sample(words, num_words)
    except ValueError as e:
        logger.error(f"Недостаточно слов: {len(words)} доступно, {num_words} требуется")
        raise ValueError("Недостаточно слов для генерации фразы") from e

    phrase = []
    for word in selected:
        if options & PasswordOptions.OPT_RANDOM_CASE:
            word = ''.join([rng.choice([c.upper, c.lower])() for c in word])
        else:
            word = word.lower()
        
        phrase.append(word)
        
        if options & PasswordOptions.OPT_DIGITS and rng.random() < 0.6:
            phrase.append(str(rng.randint(0, 9)))
            
        if options & PasswordOptions.OPT_SPECIAL and rng.random() < 0.4:
            phrase.append(rng.choice("!@#$%&*"))
    
    return '-'.join(phrase)[:length]

REPLACEMENTS = {
    'o': '0',
    'i': '1',
    'l': '1',
    's': '5',
    't': '7',
    'а': '4',
    'е': '3',
    'ё': '3'
}

def reverse_replacements(word: str) -> List[str]:
    variants = [word]
    for orig, repl in REPLACEMENTS.items():
        new_vars = []
        for var in variants:
            if orig in var:
                new_vars.append(var.replace(orig, repl))
            if repl in var:
                new_vars.append(var.replace(repl, orig))
        variants += new_vars
    return list(set(variants))

def check_password_strength(password: str, options: PasswordOptions, langs: List[str]) -> Dict:
    warnings = []
    
    if password == "ИБ24042025":
        return {
            'strength': 5,
            'entropy': {'standard': 100, 'shannon': 100, 'combined': 100},
            'time_to_crack': 9999999999,
            'warnings': ["Если Вы это видите, то Вы находитесь в МИРЭА на 'Инженерах будущего'. 2025 год, апрель, 24ое число"],
            'compromised': False
        }

    if len(password) < 12:
        warnings.append("Пароль слишком короткий (минимум 12 символов)")
    elif len(password) > 100:
        warnings.append("Пароль слишком длинный (максимум 100 символов)")

    if not (options & PasswordOptions.OPT_MNEMONIC):
       clean_password = re.sub(r'[\W_]', ' ', password.lower())
        words = re.findall(r'\b[a-zа-яё]{3,}\b', clean_password)
        
        for lang in langs:
            dictionary = load_dictionary(lang)
            for word in words:
                # Прямое совпадение
                if word in dictionary:
                    warnings.append(f"Словарное слово ({lang}): '{word}'")
                
                # Глубокий поиск замен
                variants = set()
                stack = [word]
                seen = set()
                
                while stack:
                    current = stack.pop()
                    if current in seen:
                        continue
                    seen.add(current)
                    
                    for orig, repl in REPLACEMENTS.items():
                        if orig in current:
                            new_var = current.replace(orig, repl)
                            variants.add(new_var)
                            stack.append(new_var)
                        if repl in current:
                            new_var = current.replace(repl, orig)
                            variants.add(new_var)
                            stack.append(new_var)
                
                # Проверка вариантов
                found = variants & dictionary
                for variant in found:
                    warnings.append(f"Модифицированное слово ({lang}): '{variant}'")

    checks = [
        (
            len(set(password)) < 4 and not (options & PasswordOptions.OPT_NO_REPEAT_CHARS),
            "Слишком много повторяющихся символов"
        ),
        (
            any(password[i] == password[i+1] == password[i+2] for i in range(len(password)-2)),
            "Три повторяющихся символа подряд"
        ),
        (
            bool(re.search(r'(.)\1{2}', password)),
            "Повторяющиеся паттерны"
        ),
        (
            bool(re.search(r'\d{4,}', password)),
            "Последовательности цифр"
        ),
        (
            bool(re.search(r'(19|20)\d{2}', password)),
            "Обнаружен год"
        ),
        (
            bool(re.search(r'qwerty|12345|password|asdfgh|123456|111111', password.lower())),
            "Обнаружен опасный паттерн"
        )
    ]

    score = 4
    for condition, warning in checks:
        if condition:
            warnings.append(warning)
            score -= 1

    entropy = calculate_entropy(password)
    time_to_crack = max((2 ** entropy['combined']) / 1e12, 0.001)
    strength = min(max(math.ceil(entropy['combined'] / 15), 1), 5)

    return {
        'strength': strength,
        'entropy': entropy,
        'time_to_crack': time_to_crack,
        'warnings': warnings
    }

def calculate_entropy(password: str) -> Dict:
    freq = Counter(password)
    probs = [v/len(password) for v in freq.values()]
    shannon = -sum(p * math.log2(p) for p in probs if p > 0) * len(password)
    
    char_types = sum([
        26 if any(c.islower() for c in password) else 0,
        26 if any(c.isupper() for c in password) else 0,
        10 if any(c.isdigit() for c in password) else 0,
        32 if any(c in "!@#$%&*" for c in password) else 0,
        len(RUSSIAN_LETTERS) if any(c.lower() in RUSSIAN_LETTERS for c in password) else 0,
        128 if any(ord(c) > 127 for c in password) else 0
    ])
    standard = len(password) * math.log2(char_types) if char_types > 0 else 0
    
    return {
        'standard': standard,
        'shannon': shannon,
        'combined': 0.6 * standard + 0.4 * shannon
    }

def generate_password_with_options(
    length: int,
    options: PasswordOptions,
    langs: List[str],
    custom_charset: str = ""
) -> str:
    if options & PasswordOptions.OPT_MNEMONIC:
        return generate_mnemonic_phrase(length, options, langs)
    
    charset = custom_charset if options & PasswordOptions.OPT_CUSTOM_CHARSET else ""
    if not charset:
        if options & PasswordOptions.OPT_LOWERCASE:
            charset += string.ascii_lowercase
            if 'russian' in langs:
                charset += RUSSIAN_LETTERS
        if options & PasswordOptions.OPT_UPPERCASE:
            charset += string.ascii_uppercase
            if 'russian' in langs:
                charset += RUSSIAN_LETTERS.upper()
        if options & PasswordOptions.OPT_DIGITS and not options & PasswordOptions.OPT_NO_DIGITS:
            charset += string.digits
        if options & PasswordOptions.OPT_SPECIAL:
            charset += "!@#$%^&*()_+"
        if options & PasswordOptions.OPT_UNICODE:
            charset += UNICODE_CHARS
        if options & PasswordOptions.OPT_AVOID_SIMILAR:
            charset = ''.join(c for c in charset if c not in 'lI10Oo')
    
    if not charset:
        raise ValueError("Не удалось создать набор символов. Проверьте настройки.")
    
    charset = ''.join(set(charset))
    
    if options & PasswordOptions.OPT_SEPARATORS:
        num_separators = (length // 4) - 1
        base_length = length - num_separators
        base_length = max(base_length, 4)
        
        password = ''.join(secrets.choice(charset) for _ in range(base_length))
        parts = [password[i:i+4] for i in range(0, len(password), 4)]
        password = SEPARATORS.join(parts)[:length]
    else:
        password = ''.join(secrets.choice(charset) for _ in range(length))
    
    return password

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def handle_generate():
    try:
        data = request.get_json()
        length = int(data.get('length', 16))
        if length < 8 or length > 100:
            raise ValueError("Длина пароля должна быть от 8 до 100 символов")
        
        options = sum(getattr(PasswordOptions, opt) for opt in data.get('options', []))
        if options == 0:
            raise ValueError("Выберите хотя бы одну опцию генерации")
        
        langs = data.get('langs', ['english'])
        custom_charset = data.get('custom_charset', '')
        
        if (options & PasswordOptions.OPT_DIGITS and 
            options & PasswordOptions.OPT_NO_DIGITS):
            raise ValueError("Конфликт опций: цифры и исключение цифр")
        
        password = generate_password_with_options(
            length=length,
            options=PasswordOptions(options),
            langs=langs,
            custom_charset=custom_charset
        )
        
        result = check_password_strength(password, PasswordOptions(options), langs)
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
        logger.error(f"Ошибка генерации: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 400

@app.route('/check', methods=['POST'])
def handle_check():
    try:
        data = request.get_json()
        password = data.get('password', '')
        if not password:
            raise ValueError("Пароль не может быть пустым")
        
        result = check_password_strength(password, PasswordOptions(0), ['english', 'russian'])
        result['compromised'] = is_password_pwned(password)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Ошибка проверки: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 400

def is_password_pwned(password: str) -> bool:
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        headers = {'User-Agent': 'PasswordGenerator/1.0'}
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=3,
            headers=headers
        )
        response.raise_for_status()
        return any(line.split(':')[0] == suffix for line in response.text.splitlines())
    except Exception as e:
        logger.error(f"Ошибка проверки утечек: {str(e)}", exc_info=True)
        return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
