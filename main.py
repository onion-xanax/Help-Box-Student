from flask import Flask, send_from_directory, request, jsonify, render_template_string
import os
import asyncio
import logging
import html
import re
from threading import Thread
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardButton
from aiogram.utils.keyboard import InlineKeyboardBuilder

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

BOT_TOKEN = "8287358653:AAFbx9Hyt-KMhk9JNnaPjFj6b7DmXI-0Nxw"
ADMIN_ID = [87560475, 122746101]

bot = None
dp = None
bot_thread = None
active_sessions = {}
bot_loop = None
user_sessions = {}

def sanitize_input(text):
    if not text:
        return ""
    text = str(text)
    text = html.escape(text)
    text = re.sub(r'[<>\"\']', '', text)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'vbscript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+=', '', text, flags=re.IGNORECASE)
    text = re.sub(r'data:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'expression\s*\(', '', text, flags=re.IGNORECASE)
    text = re.sub(r'url\s*\(', '', text, flags=re.IGNORECASE)
    text = re.sub(r'@import', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\\x[0-9a-fA-F]{2}', '', text)
    text = re.sub(r'\\u[0-9a-fA-F]{4}', '', text)
    text = re.sub(r'[`$|&;{}()\[\]]', '', text)
    return text.strip()

def validate_session_id(session_id):
    return bool(re.match(r'^[a-f0-9]{32}$', session_id))

def validate_filename(filename):
    return bool(re.match(r'^[a-zA-Z0-9_.-]+$', filename))

def is_mobile_device(user_agent):
    mobile_indicators = ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'blackberry',
                         'windows phone', 'webos', 'opera mini', 'iemobile']
    user_agent = user_agent.lower()
    return any(indicator in user_agent for indicator in mobile_indicators)

def init_bot():
    global bot, dp, bot_loop
    if bot is None:
        bot = Bot(token=BOT_TOKEN)
        dp = Dispatcher()
        bot_loop = asyncio.new_event_loop()

        @dp.message(Command("start"))
        async def start_command(message: types.Message):
            if str(message.from_user.id) in [str(admin) for admin in ADMIN_ID]:
                await message.answer("👋 Привет, администратор! Я готов к работе.")
            else:
                await message.answer("❌ Доступ запрещен.")

        @dp.callback_query(F.data.startswith("start_dialog:"))
        async def start_dialog_handler(callback: types.CallbackQuery):
            try:
                session_id = callback.data.split(":")[1]

                if not validate_session_id(session_id):
                    await callback.answer("Неверный ID сессии")
                    return

                if session_id in user_sessions:
                    active_sessions[session_id] = {
                        'admin_message_id': callback.message.message_id,
                        'started': True
                    }

                    user_info = user_sessions[session_id]
                    await callback.message.edit_text(
                        f"💬 Диалог начат!\n\n"
                        f"📋 Сессия: {session_id}\n"
                        f"🌐 User Agent: {user_info['user_agent']}\n"
                        f"📍 IP-адрес: {user_info['user_ip']}\n\n"
                        f"💬 Последнее сообщение студента:\n{user_info['last_message']}\n\n"
                        f"💡 Пишите сообщения в этот чат - они будут отправляться студенту.",
                        reply_markup=None
                    )
                    await callback.answer("Диалог начат!")
                else:
                    await callback.answer("Сессия не найдена")

            except Exception as e:
                await callback.answer("Ошибка начала диалога")
                logging.error(f"Start dialog error: {e}")

        @dp.callback_query(F.data.startswith("ignore:"))
        async def ignore_handler(callback: types.CallbackQuery):
            try:
                session_id = callback.data.split(":")[1]

                if not validate_session_id(session_id):
                    await callback.answer("Неверный ID сессии")
                    return

                if session_id in user_sessions:
                    user_sessions[session_id]['ignored'] = True
                    user_sessions[session_id]['admin_response'] = "Хорошо, мы приняли ваше обращение!"

                await callback.message.edit_text(
                    f"❌ Обращение проигнорировано.\n\n{callback.message.text}",
                    reply_markup=None
                )
                await callback.answer("Обращение проигнорировано")
            except Exception as e:
                await callback.answer("Ошибка")
                logging.error(f"Ignore error: {e}")

        @dp.callback_query(F.data.startswith("end_dialog:"))
        async def end_dialog_handler(callback: types.CallbackQuery):
            try:
                session_id = callback.data.split(":")[1]

                if not validate_session_id(session_id):
                    await callback.answer("Неверный ID сессии")
                    return

                if session_id in active_sessions:
                    del active_sessions[session_id]

                if session_id in user_sessions:
                    user_sessions[session_id]['dialog_ended'] = True
                    user_sessions[session_id]['admin_response'] = "Диалог завершен администратором. Спасибо за обращение!"

                await callback.message.edit_text(
                    f"🔒 Диалог завершен\n\n{callback.message.text}",
                    reply_markup=None
                )
                await callback.answer("Диалог завершен")

            except Exception as e:
                await callback.answer("Ошибка завершения диалога")
                logging.error(f"End dialog error: {e}")

        @dp.message(F.chat.id.in_([int(admin) for admin in ADMIN_ID]))
        async def admin_message_handler(message: types.Message):
            try:
                active_session_id = None
                for session_id, session_data in active_sessions.items():
                    if session_data.get('started'):
                        active_session_id = session_id
                        break

                if active_session_id and active_session_id in user_sessions:
                    sanitized_message = sanitize_input(message.text)

                    if len(sanitized_message) > 2000:
                        await message.answer("❌ Сообщение слишком длинное (макс. 2000 символов)")
                        return

                    if 'admin_messages' not in user_sessions[active_session_id]:
                        user_sessions[active_session_id]['admin_messages'] = []
                    user_sessions[active_session_id]['admin_messages'].append(sanitized_message)
                    user_sessions[active_session_id]['last_admin_response'] = sanitized_message

                    keyboard = InlineKeyboardBuilder()
                    keyboard.add(InlineKeyboardButton(text="🔒 Завершить диалог", callback_data=f"end_dialog:{active_session_id}"))

                    await message.answer(
                        f"✅ Ответ отправлен студенту:\nIT hub~$ {sanitized_message}",
                        reply_markup=keyboard.as_markup()
                    )
                    return

                await message.answer("💡 Нет активных диалогов. Чтобы начать диалог, нажмите 'Начать диалог' на обращении студента.")

            except Exception as e:
                await message.answer("❌ Ошибка обработки сообщения")
                logging.error(f"Admin message error: {e}")

async def send_to_admin_async(message_text: str, user_agent: str, user_ip: str, session_id: str):
    try:
        if bot is None:
            logging.error("Bot not initialized")
            return False

        sanitized_message = sanitize_input(message_text)

        text = f"🆘 Новое сообщение от студента!\n\n"
        text += f"📋 Сессия: {session_id}\n"
        text += f"🌐 User Agent: {user_agent}\n"
        text += f"📍 IP-адрес: {user_ip}\n\n"
        text += f"💬 Сообщение:\n{sanitized_message}"

        if session_id in active_sessions:
            keyboard = InlineKeyboardBuilder()
            keyboard.add(InlineKeyboardButton(text="🔒 Завершить диалог", callback_data=f"end_dialog:{session_id}"))

            await bot.send_message(
                chat_id=ADMIN_ID[0],
                text=text,
                reply_markup=keyboard.as_markup()
            )
        else:
            keyboard = InlineKeyboardBuilder()
            keyboard.add(InlineKeyboardButton(text="💬 Начать диалог", callback_data=f"start_dialog:{session_id}"))
            keyboard.add(InlineKeyboardButton(text="❌ Проигнорировать", callback_data=f"ignore:{session_id}"))
            keyboard.adjust(2)

            await bot.send_message(
                chat_id=ADMIN_ID[0],
                text=text,
                reply_markup=keyboard.as_markup()
            )

        logging.info("Message sent to admin successfully")
        return True
    except Exception as e:
        logging.error(f"Send to admin error: {e}")
        return False

def send_to_admin_sync(message_text: str, user_agent: str, user_ip: str, session_id: str):
    try:
        if bot_loop is None:
            logging.error("Bot loop not initialized")
            return False

        future = asyncio.run_coroutine_threadsafe(
            send_to_admin_async(message_text, user_agent, user_ip, session_id),
            bot_loop
        )
        return future.result(timeout=10)
    except Exception as e:
        logging.error(f"Sync wrapper error: {e}")
        return False

async def run_bot():
    if bot is None:
        init_bot()
    try:
        await dp.start_polling(bot, handle_signals=False)
    except Exception as e:
        logging.error(f"Bot polling error: {e}")

def start_bot():
    asyncio.set_event_loop(bot_loop)
    bot_loop.run_until_complete(run_bot())

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = "geolocation=(), microphone=(), camera=()"
    return response

@app.route('/')
def index():
    user_agent = request.headers.get('User-Agent', '')
    if is_mobile_device(user_agent):
        return send_from_directory('.', 'mobile.html')
    return send_from_directory('.', 'web.html')

@app.route('/help')
def help_page():
    user_agent = request.headers.get('User-Agent', '')
    if is_mobile_device(user_agent):
        return send_from_directory('help', 'mobile.html')
    return send_from_directory('help', 'web.html')

@app.route('/complaint')
def complaint():
    user_agent = request.headers.get('User-Agent', '')
    if is_mobile_device(user_agent):
        return send_from_directory('complaint', 'mobile.html')
    return send_from_directory('complaint', 'web.html')

@app.route('/proposal')
def proposal():
    user_agent = request.headers.get('User-Agent', '')
    if is_mobile_device(user_agent):
        return send_from_directory('proposal', 'mobile.html')
    return send_from_directory('proposal', 'web.html')

@app.route('/help/<path:filename>')
def help_static(filename):
    if not validate_filename(filename):
        return "Invalid filename", 400
    return send_from_directory('help', filename)

@app.route('/complaint/<path:filename>')
def complaint_static(filename):
    if not validate_filename(filename):
        return "Invalid filename", 400
    return send_from_directory('complaint', filename)

@app.route('/proposal/<path:filename>')
def proposal_static(filename):
    if not validate_filename(filename):
        return "Invalid filename", 400
    return send_from_directory('proposal', filename)

@app.route('/<path:filename>')
def static_files(filename):
    if not validate_filename(filename):
        return "Invalid filename", 400
    return send_from_directory('.', filename)

@app.route('/send_help_message', methods=['POST'])
def send_help_message():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Invalid content type'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON'}), 400

        message = sanitize_input(data.get('message', ''))
        user_agent = sanitize_input(data.get('user_agent', ''))

        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in user_ip:
            user_ip = user_ip.split(',')[0].strip()
        user_ip = sanitize_input(user_ip)

        if not message:
            return jsonify({'success': False, 'error': 'Empty message'}), 400

        if len(message) > 1000:
            return jsonify({'success': False, 'error': 'Message too long (max 1000 characters)'}), 400

        session_id = request.cookies.get('session_id') or os.urandom(16).hex()

        if not validate_session_id(session_id):
            session_id = os.urandom(16).hex()

        if session_id not in user_sessions:
            user_sessions[session_id] = {
                'messages': [],
                'admin_messages': [],
                'user_agent': user_agent,
                'user_ip': user_ip,
                'ignored': False,
                'dialog_ended': False,
                'last_admin_response': None
            }

        user_sessions[session_id]['messages'].append(message)
        user_sessions[session_id]['last_message'] = message

        logging.info(f"Received message from {user_ip}: {message}")

        result = send_to_admin_sync(message, user_agent, user_ip, session_id)

        response = jsonify({'success': result, 'session_id': session_id})
        response.set_cookie('session_id', session_id, max_age=3600, httponly=True, secure=True, samesite='Strict')
        return response

    except Exception as e:
        logging.error(f"Send help message error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/check_response/<session_id>')
def check_response(session_id):
    if not validate_session_id(session_id):
        return jsonify({'error': 'Invalid session'}), 400

    if session_id in user_sessions:
        session = user_sessions[session_id]
        response_data = {
            'responded': False,
            'ignored': False,
            'dialog_ended': False,
            'admin_response': None
        }

        if session.get('last_admin_response'):
            response_data['responded'] = True
            response_data['admin_response'] = session['last_admin_response']
            session['last_admin_response'] = None

        if session.get('ignored'):
            response_data['ignored'] = True
            response_data['admin_response'] = session.get('admin_response')

        if session.get('dialog_ended'):
            response_data['dialog_ended'] = True
            response_data['admin_response'] = session.get('admin_response')

        return jsonify(response_data)

    return jsonify({'responded': False, 'ignored': False, 'dialog_ended': False})

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        init_bot()
        bot_thread = Thread(target=start_bot, daemon=True)
        bot_thread.start()
        logging.info("Bot started in separate thread")

    app.run(debug=False, port=5000, use_reloader=False, host='0.0.0.0')


