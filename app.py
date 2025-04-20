# ... (остальной код без изменений)

def generate_mnemonic_phrase(length: int, options: PasswordOptions, langs: List[str]) -> str:
    # CHANGED: Сообщения ошибок на русском
    rng = secrets.SystemRandom()
    words = []
    for lang in langs:
        if lang not in DICTIONARY_URLS:
            raise ValueError(f"Неподдерживаемый язык: {lang}")
        words.extend(load_dictionary(lang))
    
    if not words:
        words = [w for lang in langs for w in BACKUP_WORDS.get(lang, [])]
        if not words:
            raise ValueError("Не удалось загрузить словарь для мнемонической фразы")

    try:
        selected = rng.sample(words, num_words)
    except ValueError as e:
        logger.error(f"Недостаточно слов в словаре: {len(words)} доступно, {num_words} требуется")
        raise ValueError("Недостаточно слов для генерации фразы") from e

def check_password_strength(password: str, options: PasswordOptions, langs: List[str]) -> Dict:
    warnings = []
    
    if len(password) < 12:
        warnings.append("Пароль слишком короткий (минимум 12 символов)")
    elif len(password) > 100:
        warnings.append("Пароль слишком длинный (максимум 100 символов)")

    # CHANGED: Сообщения проверок на русском
    for lang in langs:
        dictionary = load_dictionary(lang)
        for word in words:
            if word in dictionary:
                warnings.append(f"Обнаружено слово из {lang} словаря")
            
            variants = reverse_replacements(word)
            if any(variant in dictionary for variant in variants):
                warnings.append(f"Обнаружено слово из {lang} словаря с заменой символов")

    if not (options & PasswordOptions.OPT_NO_REPEAT_CHARS):
        if len(set(password)) < 4:
            warnings.append("Слишком много повторяющихся символов")

    checks = [
        (any(password[i] == password[i+1] == password[i+2] for i in range(len(password)-2)),
         "Три одинаковых символа подряд"),
        (bool(re.search(r'(.)\1{2}', password)), "Повторяющиеся паттерны"),
        (bool(re.search(r'\d{4,}', password)), "Слишком длинная последовательность цифр"),
        (bool(re.search(r'(19|20)\d{2}', password)), "Обнаружен год в пароле"),
        (bool(re.search(r'qwerty|12345|password|asdfgh|123456|111111', password.lower())),
         "Обнаружен опасный паттерн")
    ]

@app.route('/generate', methods=['POST'])
def handle_generate():
    except Exception as e:
        # CHANGED: Логирование на русском
        logger.error(f"Ошибка генерации пароля: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 400

@app.route('/check', methods=['POST'])
def handle_check():
    except Exception as e:
        logger.error(f"Ошибка проверки пароля: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 400

def is_password_pwned(password: str) -> bool:
    except Exception as e:
        # CHANGED: Логирование на русском
        logger.error(f"Ошибка проверки утечек: {str(e)}", exc_info=True)
        return False

# ... (остальной код)

def generate_password_with_options(...):
    if not charset:
        raise ValueError("Не удалось создать набор символов. Проверьте настройки.")
