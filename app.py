from flask import Flask, render_template, request, jsonify
import math
import secrets
import string
import requests
import hashlib
import re
from enum import IntFlag
from typing import Tuple, List, Dict, Set
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
    OPT_AVOID_SIMILAR = 1 << 6
    OPT_NO_REPEAT = 1 << 7
    OPT_RANDOM_CASE = 1 << 8
    OPT_CUSTOM_CHARSET = 1 << 9
    OPT_MNEMONIC = 1 << 10

DICTIONARY_URLS = {
    'english': 'https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt',
    'russian': 'https://raw.githubusercontent.com/Harrix/Russian-Nouns/main/dist/russian_nouns.txt'
}

DICTIONARY: Set[str] = set()

def load_online_dictionary(url: str) -> Set[str]:
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        words = [
            word.strip().lower()
            for word in response.text.splitlines()
            if word.strip()
            and 4 <= len(word.strip()) <= 8
            and word.isalpha()
        ]
        return set(words)
    except Exception as e:
        logger.error(f"Ошибка загрузки словаря: {e}")
        return set()

try:
    eng_words = load_online_dictionary(DICTIONARY_URLS['english'])
    rus_words = load_online_dictionary(DICTIONARY_URLS['russian'])
    DICTIONARY.update(eng_words)
    DICTIONARY.update(rus_words)
    logger.info(f"Загружено слов: EN {len(eng_words)}, RU {len(rus_words)}")
except Exception as e:
    logger.error(f"Ошибка загрузки словарей: {e}")
    DICTIONARY.update({'apple', 'sun', 'moon', 'password', 'security'})

def generate_mnemonic_phrase(
    length: int,
    separator: str = "-",
    add_number: bool = True,
    add_special: bool = False
) -> str:
    words = [w for w in DICTIONARY if 5 <= len(w) <= 8]
    if not words:
        raise ValueError("Словарь не содержит подходящих слов")
    
    rng = secrets.SystemRandom()
    num_words = max(3, min(6, length // 4))
    selected = rng.sample(words, num_words)
    
    phrase = []
    for i, word in enumerate(selected):
        if rng.random() < 0.3:
            word = word.title() if rng.random() < 0.5 else word.upper()
        
        phrase.append(word)
        
        if add_number and rng.random() < 0.4:
            phrase.append(str(rng.randint(0, 9)))
            
        if add_special and rng.random() < 0.2:
            phrase.append(rng.choice("!@#$%&*"))
    
    return separator.join(phrase)[:length]

def calculate_entropy(password: str) -> Tuple[float, float]:
    char_set = set(password)
    char_size = len(char_set) if char_set else 1
    standard = len(password) * math.log2(char_size)
    
    freq = Counter(password)
    probs = [c/len(password) for c in freq.values()]
    shannon = -sum(p * math.log2(p) for p in probs) * len(password)
    
    return standard, shannon

def check_password_strength(password: str, forbidden_context: List[str] = None) -> Dict:
    warnings = []
    forbidden_context = forbidden_context or []
    
    if forbidden_context:
        context_pattern = re.compile('|'.join(map(re.escape, forbidden_context)), re.I)
        if context_pattern.search(password):
            warnings.append("Пароль содержит контекстно-зависимые данные")

    if len(password) < 8:
        warnings.append("Пароль слишком короткий (минимум 8 символов)")
    
    if any(word in password.lower() for word in DICTIONARY):
        warnings.append("Обнаружено словарное слово")

    standard_entropy, shannon_entropy = calculate_entropy(password)
    effective_entropy = max(standard_entropy, shannon_entropy)
    time_to_crack = (2 ** effective_entropy) / 1e10  # 10 млрд попыток/сек

    score = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in "!@#$%^&*()_+" for c in password)
    ]) + min(3, len(password) // 8)

    checks = [
        (len(set(password)) < 4, "Слишком много повторяющихся символов"),
        (any(password[i] == password[i+1] == password[i+2] for i in range(len(password)-2)),
         "Три повторяющихся символа подряд")
    ]
    
    for condition, warning in checks:
        if condition:
            warnings.append(warning)
            score -= 1
    
    strength = min(max(math.ceil(score / 2), 1), 5)
    return {
        'strength': strength,
        'entropy': {'standard': standard_entropy, 'shannon': shannon_entropy},
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
            add_number=options & PasswordOptions.OPT_DIGITS,
            add_special=options & PasswordOptions.OPT_SPECIAL
        )
    
    charset = ""
    if options & PasswordOptions.OPT_CUSTOM_CHARSET:
        charset = custom_charset
    else:
        if options & PasswordOptions.OPT_LOWERCASE:
            charset += string.ascii_lowercase
        if options & PasswordOptions.OPT_UPPERCASE:
            charset += string.ascii_uppercase
        if options & PasswordOptions.OPT_DIGITS:
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
    
    return password[:length]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def handle_generate():
    try:
        data = request.get_json()
        length = int(data.get('length', 12))
        options = sum(getattr(PasswordOptions, opt) for opt in data.get('options', []))
        
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
