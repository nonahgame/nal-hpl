# working Ok only tele msg with inex 01
import os
from dotenv import load_dotenv
import pandas as pd
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import telegram
import asyncio
import logging
import requests
import base64
from datetime import datetime
import atexit
import traceback

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG,
    handlers=[
        logging.FileHandler('renda_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
try:
    load_dotenv()
    logger.debug("Loaded environment variables from .env file")
except ImportError:
    logger.warning("python-dotenv not installed. Relying on system environment variables.")

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key")

# Environment variables
BOT_TOKEN = os.getenv("BOT_TOKEN", "your-telegram-bot-token")
CHAT_ID = os.getenv("CHAT_ID", "your-telegram-chat-id")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "your-github-token")
GITHUB_REPO = os.getenv("GITHUB_REPO", "your-username/your-repo")
GITHUB_PATH = os.getenv("GITHUB_PATH", "data/gwoza-df-amb.db")
DB_PATH = "data/gwoza-df-amb.db"

# GitHub API setup
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# Admin passphrase
ADMIN_PASSPHRASE = os.getenv("ADMIN_PASSPHRASE", "admin1234")

# Initialize Telegram bot
try:
    application = telegram.Application.builder().token(BOT_TOKEN).build()
    logger.info("Telegram bot initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Telegram bot: {str(e)}")
    application = None

# GitHub file handling
def upload_to_github(file_path, file_name):
    try:
        if not GITHUB_TOKEN or GITHUB_TOKEN == "your-github-token":
            logger.error("GITHUB_TOKEN is not set or invalid.")
            return
        if not GITHUB_REPO or GITHUB_REPO == "your-username/your-repo":
            logger.error("GITHUB_REPO is not set or invalid.")
            return
        if not GITHUB_PATH:
            logger.error("GITHUB_PATH is not set.")
            return

        logger.debug(f"Uploading {file_name} to GitHub: {GITHUB_REPO}/{GITHUB_PATH}")

        with open(file_path, "rb") as f:
            content = base64.b64encode(f.read()).decode("utf-8")

        response = requests.get(GITHUB_API_URL, headers=HEADERS)
        sha = None
        if response.status_code == 200:
            sha = response.json().get("sha")
            logger.debug(f"Existing file SHA: {sha}")
        elif response.status_code != 404:
            logger.error(f"Failed to check existing file on GitHub: {response.status_code} - {response.text}")
            return

        payload = {
            "message": f"Update {file_name} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "content": content
        }
        if sha:
            payload["sha"] = sha

        response = requests.put(GITHUB_API_URL, headers=HEADERS, json=payload)
        if response.status_code in [200, 201]:
            logger.info(f"Successfully uploaded {file_name} to GitHub")
        else:
            logger.error(f"Failed to upload {file_name} to GitHub: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Error uploading {file_name} to GitHub: {e}", exc_info=True)

def download_from_github(file_name, destination_path):
    try:
        if not GITHUB_TOKEN or GITHUB_TOKEN == "your-github-token":
            logger.error("GITHUB_TOKEN is not set or invalid.")
            return False
        if not GITHUB_REPO or GITHUB_REPO == "your-username/your-repo":
            logger.error("GITHUB_REPO is not set or invalid.")
            return False
        if not GITHUB_PATH:
            logger.error("GITHUB_PATH is not set.")
            return False

        logger.debug(f"Downloading {file_name} from GitHub: {GITHUB_REPO}/{GITHUB_PATH}")

        response = requests.get(GITHUB_API_URL, headers=HEADERS)
        if response.status_code == 404:
            logger.info(f"No {file_name} found in GitHub repository. Starting with a new database.")
            return False
        elif response.status_code != 200:
            logger.error(f"Failed to fetch {file_name} from GitHub: {response.status_code} - {response.text}")
            return False

        content = base64.b64decode(response.json()["content"])
        with open(destination_path, "wb") as f:
            f.write(content)
        logger.info(f"Downloaded {file_name} from GitHub to {destination_path}")
        return True
    except Exception as e:
        logger.error(f"Error downloading {file_name} from GitHub: {e}", exc_info=True)
        return False

# Initialize database
def init_db():
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        if download_from_github("gwoza-df-amb.db", DB_PATH):
            logger.info("Database downloaded from GitHub")
        else:
            logger.info("No database found on GitHub, creating new one")

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            second_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            username TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS edit_permissions (
            user_id INTEGER PRIMARY KEY,
            can_edit INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS todo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sn TEXT,
            date TEXT,
            time TEXT,
            am_number TEXT,
            rank TEXT,
            first_second_name TEXT,
            unit TEXT,
            phone_no TEXT,
            age INTEGER,
            temp REAL,
            bp REAL,
            bp1 REAL,
            pauls INTEGER,
            rest TEXT,
            wt TEXT,
            complain TEXT,
            diagn TEXT,
            plan TEXT,
            rmks TEXT
        )''')

        try:
            c.execute("ALTER TABLE todo ADD COLUMN bp1 REAL")
            logger.info("Added bp1 column to todo table")
        except sqlite3.OperationalError:
            logger.info("bp1 column already exists")
        try:
            c.execute("ALTER TABLE todo ADD COLUMN wt TEXT")
            logger.info("Added wt column to todo table")
        except sqlite3.OperationalError:
            logger.info("wt column already exists")

        c.execute("SELECT * FROM users WHERE is_admin = 1")
        if not c.fetchone():
            default_admin_password = generate_password_hash("admin123")
            c.execute("INSERT INTO users (first_name, second_name, email, phone, password, username, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     ("Admin", "User", "admin@example.com", "0000000000", default_admin_password, "admin", 1))
            logger.info("Created default admin user")
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
        upload_to_github(DB_PATH, "gwoza-df-amb.db")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}", exc_info=True)
        raise

# Database connection
def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        logger.info("Database connection established")
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise

# Send Telegram notification
async def send_telegram_message(message):
    if application is None:
        logger.warning("Telegram bot not initialized, skipping notification")
        return
    try:
        await application.bot.send_message(chat_id=CHAT_ID, text=message)
        logger.info(f"Telegram message sent: {message}")
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {str(e)}")

def sync_send_telegram_message(message):
    loop = None
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_telegram_message(message))
    except Exception as e:
        logger.error(f"Error in sync_send_telegram_message: {str(e)}")
    finally:
        if loop is not None and not loop.is_closed():
            loop.close()

# Validate numeric fields
def validate_numeric(value, field_name):
    if value == '':
        return None
    try:
        return float(value) if field_name in ['temp', 'bp', 'bp1'] else int(value)
    except ValueError:
        raise ValueError(f"Invalid value for {field_name}: {value}")

# New endpoint to fetch record by ID for dynamic update
@app.route('/get_record/<int:id>', methods=['GET'])
def get_record(id):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM todo WHERE id = ?", (id,))
        record = c.fetchone()
        conn.close()
        if record:
            logger.info(f"Fetched record ID: {id}")
            return jsonify(dict(record))
        logger.warning(f"Record ID {id} not found")
        return jsonify({"error": "Record not found"}), 404
    except Exception as e:
        logger.error(f"Error fetching record ID {id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Internal server error"}), 500

# Index route with keyset pagination and search
@app.route('/', methods=['GET', 'POST'])
def index():
    try:
        if 'user_id' not in session:
            logger.info("User not logged in, redirecting to login")
            return redirect(url_for('login'))

        conn = get_db_connection()
        c = conn.cursor()

        c.execute("SELECT can_edit FROM edit_permissions WHERE user_id = ?", (session['user_id'],))
        edit_perm = c.fetchone()
        can_edit = edit_perm['can_edit'] if edit_perm else 0
        logger.info(f"User {session['username']} has edit permissions: {can_edit}")

        cursor = request.args.get('cursor', '0')
        direction = request.args.get('direction', 'next')
        per_page = 5
        search_query = request.form.get('search_query', '') if request.method == 'POST' else request.args.get('search_query', '')

        columns = 'id, sn, date, time, am_number, rank, first_second_name, unit, phone_no, age, temp, bp, bp1, pauls, rest, wt, complain, diagn, plan, rmks'
        base_query = f"SELECT {columns} FROM todo"
        where_clause = ""
        params = []

        if search_query:
            where_clause = " WHERE sn LIKE ? OR first_second_name LIKE ? OR am_number LIKE ? OR complain LIKE ?"
            params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])

        if cursor != '0':
            if where_clause:
                where_clause += " AND id > ?" if direction == 'next' else " AND id < ?"
            else:
                where_clause = " WHERE id > ?" if direction == 'next' else " WHERE id < ?"
            params.append(cursor)

        order_by = " ORDER BY id ASC" if direction == 'next' else " ORDER BY id DESC"
        query = f"{base_query}{where_clause}{order_by} LIMIT ?"
        params.append(per_page + 1)

        c.execute(query, params)
        rows = c.fetchall()

        has_next = len(rows) > per_page
        has_prev = cursor != '0'

        rows = rows[:per_page] if direction == 'next' else rows[:per_page][::-1]
        df = pd.DataFrame([dict(row) for row in rows])

        next_cursor = rows[-1]['id'] if rows and has_next else None
        prev_cursor = rows[0]['id'] if rows and has_prev else None

        if request.method == 'POST' and can_edit:
            action = request.form.get('action')
            logger.info(f"Processing action: {action}")
            try:
                if action == 'add':
                    fields = ['sn', 'date', 'time', 'am_number', 'rank', 'first_second_name', 'unit', 'phone_no', 'age', 'temp', 'bp', 'bp1', 'pauls', 'rest', 'wt', 'complain', 'diagn', 'plan', 'rmks']
                    values = []
                    for field in fields:
                        value = request.form.get(field, '')
                        if field in ['age', 'pauls']:
                            values.append(validate_numeric(value, field))
                        elif field in ['temp', 'bp', 'bp1']:
                            values.append(validate_numeric(value, field))
                        else:
                            values.append(value)
                    c.execute(f'''INSERT INTO todo ({', '.join(fields)})
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', values)
                    conn.commit()
                    upload_to_github(DB_PATH, "gwoza-df-amb.db")
                    sync_send_telegram_message(f"New entry added: {values[0] or 'No SN'} by user {session['username']}")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        conn.close()
                        return jsonify({'status': 'success', 'message': 'Entry added successfully'})
                    flash('Entry added successfully!', 'success')

                elif action == 'update':
                    id = request.form.get('id')
                    try:
                        id = int(id)
                        c.execute("SELECT * FROM todo WHERE id = ?", (id,))
                        if not c.fetchone():
                            logger.warning(f"Update failed: Record ID {id} not found")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'error', 'error': 'Record ID does not exist'}), 404
                            flash('Entry ID does not exist', 'danger')
                        else:
                            fields = ['sn', 'date', 'time', 'am_number', 'rank', 'first_second_name', 'unit', 'phone_no', 'age', 'temp', 'bp', 'bp1', 'pauls', 'rest', 'wt', 'complain', 'diagn', 'plan', 'rmks']
                            values = []
                            for field in fields:
                                value = request.form.get(field, '')
                                if field in ['age', 'pauls']:
                                    values.append(validate_numeric(value, field))
                                elif field in ['temp', 'bp', 'bp1']:
                                    values.append(validate_numeric(value, field))
                                else:
                                    values.append(value)
                            values.append(id)
                            c.execute(f'''UPDATE todo SET {', '.join(f'{f} = ?' for f in fields)}
                                         WHERE id = ?''', values)
                            conn.commit()
                            upload_to_github(DB_PATH, "gwoza-df-amb.db")
                            sync_send_telegram_message(f"Entry ID {id} updated by user {session['username']}")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'success', 'message': 'Entry updated successfully'})
                            flash('Entry updated successfully!', 'success')
                    except ValueError as e:
                        logger.error(f"Update error: Invalid ID {id}: {str(e)}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': f'Invalid ID: {str(e)}'}), 400
                        flash(f'Invalid ID: {str(e)}', 'danger')
                    except Exception as e:
                        logger.error(f"Update error for ID {id}: {str(e)}\n{traceback.format_exc()}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': f'Error updating record: {str(e)}'}), 500
                        flash(f'Error updating record: {str(e)}', 'danger')

                elif action == 'delete':
                    id = request.form.get('id')
                    try:
                        id = int(id)
                        c.execute("SELECT * FROM todo WHERE id = ?", (id,))
                        if not c.fetchone():
                            logger.warning(f"Delete failed: Record ID {id} not found")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'error', 'error': 'Record ID does not exist'}), 404
                            flash('Entry ID does not exist', 'danger')
                        else:
                            c.execute("DELETE FROM todo WHERE id = ?", (id,))
                            conn.commit()
                            upload_to_github(DB_PATH, "gwoza-df-amb.db")
                            sync_send_telegram_message(f"Entry ID {id} deleted by user {session['username']}")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'success', 'message': 'Entry deleted successfully'})
                            flash('Entry deleted successfully!', 'success')
                    except ValueError:
                        logger.warning(f"Delete failed: Invalid ID {id}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': 'Invalid ID'}), 400
                        flash('Invalid ID', 'danger')
                    except Exception as e:
                        logger.error(f"Delete error for ID {id}: {str(e)}\n{traceback.format_exc()}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': f'Error deleting record: {str(e)}'}), 500
                        flash(f'Error deleting record: {str(e)}', 'danger')

            except Exception as e:
                logger.error(f"Action error: {str(e)}\n{traceback.format_exc()}")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    conn.close()
                    return jsonify({'status': 'error', 'error': f'Error processing action: {str(e)}'}), 500
                flash(f'Error processing action: {str(e)}', 'danger')

        conn.close()
        return render_template('index.html', df=df, has_next=has_next, has_prev=has_prev,
                              next_cursor=next_cursor, prev_cursor=prev_cursor, search_query=search_query,
                              can_edit=can_edit)

    except Exception as e:
        logger.error(f"Error in index route: {str(e)}\n{traceback.format_exc()}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'error': f'Internal Server Error: {str(e)}'}), 500
        flash(f'Internal Server Error: {str(e)}', 'danger')
        return redirect(url_for('login'))

# Admin route
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    try:
        if 'user_id' not in session or not session.get('is_admin'):
            logger.info("Non-admin user attempted to access admin panel")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'status': 'error', 'error': 'Unauthorized access'}), 403
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))

        conn = get_db_connection()
        c = conn.cursor()

        c.execute("SELECT id, username, email FROM users")
        users = c.fetchall()
        c.execute("SELECT user_id FROM edit_permissions")
        edit_permissions = c.fetchall()

        columns = 'id, sn, date, time, am_number, rank, first_second_name, unit, phone_no, age, temp, bp, bp1, pauls, rest, wt, complain, diagn, plan, rmks'
        c.execute(f"SELECT {columns} FROM todo ORDER BY id DESC LIMIT 5")
        rows = c.fetchall()
        df = pd.DataFrame([dict(row) for row in rows]) if rows else pd.DataFrame()

        if request.method == 'POST':
            action = request.form.get('action')
            logger.info(f"Processing admin action: {action}")

            try:
                if action == 'add':
                    fields = ['sn', 'date', 'time', 'am_number', 'rank', 'first_second_name', 'unit', 'phone_no', 'age', 'temp', 'bp', 'bp1', 'pauls', 'rest', 'wt', 'complain', 'diagn', 'plan', 'rmks']
                    values = []
                    for field in fields:
                        value = request.form.get(field, '')
                        if field in ['age', 'pauls']:
                            values.append(validate_numeric(value, field))
                        elif field in ['temp', 'bp', 'bp1']:
                            values.append(validate_numeric(value, field))
                        else:
                            values.append(value)
                    c.execute(f'''INSERT INTO todo ({', '.join(fields)})
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', values)
                    conn.commit()
                    upload_to_github(DB_PATH, "gwoza-df-amb.db")
                    sync_send_telegram_message(f"New entry added: {values[0] or 'No SN'} by admin {session['username']}")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        conn.close()
                        return jsonify({'status': 'success', 'message': 'Entry added successfully'})
                    flash('Entry added successfully!', 'success')

                elif action == 'update':
                    id = request.form.get('id')
                    try:
                        id = int(id)
                        c.execute("SELECT * FROM todo WHERE id = ?", (id,))
                        if not c.fetchone():
                            logger.warning(f"Update failed: Record ID {id} not found")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'error', 'error': 'Record ID does not exist'}), 404
                            flash('Entry ID does not exist', 'danger')
                        else:
                            fields = ['sn', 'date', 'time', 'am_number', 'rank', 'first_second_name', 'unit', 'phone_no', 'age', 'temp', 'bp', 'bp1', 'pauls', 'rest', 'wt', 'complain', 'diagn', 'plan', 'rmks']
                            values = []
                            for field in fields:
                                value = request.form.get(field, '')
                                if field in ['age', 'pauls']:
                                    values.append(validate_numeric(value, field))
                                elif field in ['temp', 'bp', 'bp1']:
                                    values.append(validate_numeric(value, field))
                                else:
                                    values.append(value)
                            values.append(id)
                            c.execute(f'''UPDATE todo SET {', '.join(f'{f} = ?' for f in fields)}
                                         WHERE id = ?''', values)
                            conn.commit()
                            upload_to_github(DB_PATH, "gwoza-df-amb.db")
                            sync_send_telegram_message(f"Entry ID {id} updated by admin {session['username']}")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'success', 'message': 'Entry updated successfully'})
                            flash('Entry updated successfully!', 'success')
                    except ValueError as e:
                        logger.error(f"Update error: Invalid ID {id}: {str(e)}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': f'Invalid ID: {str(e)}'}), 400
                        flash(f'Invalid ID: {str(e)}', 'danger')
                    except Exception as e:
                        logger.error(f"Update error for ID {id}: {str(e)}\n{traceback.format_exc()}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': f'Error updating record: {str(e)}'}), 500
                        flash(f'Error updating record: {str(e)}', 'danger')

                elif action == 'delete':
                    id = request.form.get('id')
                    try:
                        id = int(id)
                        c.execute("SELECT * FROM todo WHERE id = ?", (id,))
                        if not c.fetchone():
                            logger.warning(f"Delete failed: Record ID {id} not found")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'error', 'error': 'Record ID does not exist'}), 404
                            flash('Entry ID does not exist', 'danger')
                        else:
                            c.execute("DELETE FROM todo WHERE id = ?", (id,))
                            conn.commit()
                            upload_to_github(DB_PATH, "gwoza-df-amb.db")
                            sync_send_telegram_message(f"Entry ID {id} deleted by admin {session['username']}")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'success', 'message': 'Entry deleted successfully'})
                            flash('Entry deleted successfully!', 'success')
                    except ValueError:
                        logger.warning(f"Delete failed: Invalid ID {id}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': 'Invalid ID'}), 400
                        flash('Invalid ID', 'danger')
                    except Exception as e:
                        logger.error(f"Delete error for ID {id}: {str(e)}\n{traceback.format_exc()}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': f'Error deleting record: {str(e)}'}), 500
                        flash(f'Error deleting record: {str(e)}', 'danger')

                elif action == 'manage_user':
                    user_id = request.form.get('user_id')
                    can_edit = 'can_edit' in request.form
                    try:
                        user_id = int(user_id)
                        c.execute("SELECT id FROM users WHERE id = ?", (user_id,))
                        if not c.fetchone():
                            logger.warning(f"Manage user failed: User ID {user_id} not found")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'error', 'error': 'User ID does not exist'}), 404
                            flash('User ID does not exist', 'danger')
                        else:
                            c.execute("SELECT * FROM edit_permissions WHERE user_id = ?", (user_id,))
                            if c.fetchone():
                                c.execute("UPDATE edit_permissions SET can_edit = ? WHERE user_id = ?", (1 if can_edit else 0, user_id))
                            else:
                                c.execute("INSERT INTO edit_permissions (user_id, can_edit) VALUES (?, ?)", (user_id, 1 if can_edit else 0))
                            conn.commit()
                            sync_send_telegram_message(f"User ID {user_id} edit permission set to {can_edit} by admin {session['username']}")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'success', 'message': 'User permissions updated successfully'})
                            flash('User permissions updated successfully!', 'success')
                    except ValueError:
                        logger.warning(f"Manage user failed: Invalid user ID {user_id}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': 'Invalid user ID'}), 400
                        flash('Invalid user ID', 'danger')
                    except Exception as e:
                        logger.error(f"Manage user error for user ID {user_id}: {str(e)}\n{traceback.format_exc()}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': f'Error updating user permissions: {str(e)}'}), 500
                        flash(f'Error updating user permissions: {str(e)}', 'danger')

                elif action == 'delete_user':
                    user_id = request.form.get('user_id')
                    try:
                        user_id = int(user_id)
                        c.execute("SELECT id FROM users WHERE id = ?", (user_id,))
                        if not c.fetchone():
                            logger.warning(f"Delete user failed: User ID {user_id} not found")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'error', 'error': 'User ID does not exist'}), 404
                            flash('User ID does not exist', 'danger')
                        else:
                            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
                            c.execute("DELETE FROM edit_permissions WHERE user_id = ?", (user_id,))
                            conn.commit()
                            sync_send_telegram_message(f"User ID {user_id} deleted by admin {session['username']}")
                            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                                conn.close()
                                return jsonify({'status': 'success', 'message': 'User deleted successfully'})
                            flash('User deleted successfully!', 'success')
                    except ValueError:
                        logger.warning(f"Delete user failed: Invalid user ID {user_id}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': 'Invalid user ID'}), 400
                        flash('Invalid user ID', 'danger')
                    except Exception as e:
                        logger.error(f"Delete user error for user ID {user_id}: {str(e)}\n{traceback.format_exc()}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': f'Error deleting user: {str(e)}'}), 500
                        flash(f'Error deleting user: {str(e)}', 'danger')

                elif action == 'change_passphrase':
                    new_passphrase = request.form.get('new_passphrase')
                    if not new_passphrase:
                        logger.warning("Change passphrase failed: No passphrase provided")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'error', 'error': 'No passphrase provided'}), 400
                        flash('No passphrase provided', 'danger')
                    else:
                        c.execute("UPDATE admin SET passphrase = ? WHERE id = 1", (new_passphrase,))
                        conn.commit()
                        sync_send_telegram_message(f"Admin passphrase changed by {session['username']}")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            conn.close()
                            return jsonify({'status': 'success', 'message': 'Passphrase changed successfully'})
                        flash('Passphrase changed successfully!', 'success')

            except Exception as e:
                logger.error(f"Admin action error: {str(e)}\n{traceback.format_exc()}")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    conn.close()
                    return jsonify({'status': 'error', 'error': f'Error processing action: {str(e)}'}), 500
                flash(f'Error processing action: {str(e)}', 'danger')

        conn.close()
        return render_template('admin.html', users=users, edit_permissions=edit_permissions, df=df)

    except Exception as e:
        logger.error(f"Error in admin route: {str(e)}\n{traceback.format_exc()}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'error', 'error': f'Internal Server Error: {str(e)}'}), 500
        flash(f'Internal Server Error: {str(e)}', 'danger')
        return redirect(url_for('index'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            logger.info(f"Login attempt for email: {email}")
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            conn.close()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                sync_send_telegram_message(f"User {user['username']} logged in")
                logger.info(f"User {user['username']} logged in successfully")
                return redirect(url_for('index'))
            flash('Invalid email or password', 'danger')
            logger.warning(f"Failed login attempt for email: {email}")
        return render_template('login.html')

    except Exception as e:
        logger.error(f"Error in login route: {str(e)}\n{traceback.format_exc()}")
        flash(f"Internal Server Error: {str(e)}", 'danger')
        return redirect(url_for('login'))

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            first_name = request.form['first_name']
            second_name = request.form['second_name']
            email = request.form['email']
            phone = request.form['phone']
            password = generate_password_hash(request.form['password'])
            username = request.form['username']
            logger.info(f"Register attempt for email: {email}, username: {username}")

            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO users (first_name, second_name, email, phone, password, username) VALUES (?, ?, ?, ?, ?, ?)",
                      (first_name, second_name, email, phone, password, username))
            conn.commit()
            upload_to_github(DB_PATH, "gwoza-df-amb.db")
            sync_send_telegram_message(f"New user registered: {username}")
            flash('Registration successful! Please log in.', 'success')
            logger.info(f"User {username} registered successfully")
            conn.close()
            return redirect(url_for('login'))
        return render_template('register.html')

    except sqlite3.OperationalError as e:
        logger.error(f"Database error in register route: {str(e)}\n{traceback.format_exc()}")
        if "no such table" in str(e):
            flash('Database error: Users table not found. Please contact the administrator.', 'danger')
        else:
            flash('Database error occurred. Please try again.', 'danger')
        return render_template('register.html')
    except Exception as e:
        logger.error(f"Error in register route: {str(e)}\n{traceback.format_exc()}")
        flash(f"Internal Server Error: {str(e)}", 'danger')
        return redirect(url_for('login'))

# Recover route
@app.route('/recover', methods=['GET', 'POST'])
def recover():
    try:
        if request.method == 'POST':
            email = request.form['email']
            logger.info(f"Password recovery attempt for email: {email}")
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            if user:
                new_password = request.form['new_password']
                c.execute("UPDATE users SET password = ? WHERE email = ?", (generate_password_hash(new_password), email))
                conn.commit()
                upload_to_github(DB_PATH, "gwoza-df-amb.db")
                sync_send_telegram_message(f"Password reset for user: {user['username']}")
                flash('Password reset successfully! Please log in.', 'success')
                logger.info(f"Password reset successful for user: {user['username']}")
                conn.close()
                return redirect(url_for('login'))
            flash('Email not found', 'danger')
            logger.warning(f"Password recovery failed: Email {email} not found")
            conn.close()
        return render_template('recover.html')

    except Exception as e:
        logger.error(f"Error in recover route: {str(e)}\n{traceback.format_exc()}")
        flash(f"Internal Server Error: {str(e)}", 'danger')
        return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    try:
        username = session.get('username')
        session.clear()
        sync_send_telegram_message(f"User {username} logged out")
        flash('Logged out successfully', 'success')
        logger.info(f"User {username} logged out")
        return redirect(url_for('login'))

    except Exception as e:
        logger.error(f"Error in logout route: {str(e)}\n{traceback.format_exc()}")
        flash(f"Internal Server Error: {str(e)}", 'danger')
        return redirect(url_for('login'))

# Search route
@app.route('/search', methods=['GET', 'POST'])
def search():
    try:
        if 'user_id' not in session:
            logger.info("User not logged in, redirecting to login from search")
            return redirect(url_for('login'))

        if request.method == 'POST':
            query = request.form['query']
            logger.info(f"Search query: {query}")
            conn = get_db_connection()
            c = conn.cursor()
            columns = 'id, sn, date, time, am_number, rank, first_second_name, unit, phone_no, age, temp, bp, bp1, pauls, rest, wt, complain, diagn, plan, rmks'
            c.execute(f"SELECT {columns} FROM todo WHERE sn LIKE ? OR first_second_name LIKE ? OR am_number LIKE ? OR complain LIKE ?",
                      (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
            rows = c.fetchall()
            df = pd.DataFrame([dict(row) for row in rows])
            conn.close()
            return render_template('search.html', df=df, search_query=query)
        return render_template('search.html', df=None)

    except Exception as e:
        logger.error(f"Error in search route: {str(e)}\n{traceback.format_exc()}")
        flash(f"Internal Server Error: {str(e)}", 'danger')
        return redirect(url_for('index'))

# Cleanup on shutdown
def cleanup():
    logger.info("Application shutting down, uploading database to GitHub")
    upload_to_github(DB_PATH, "gwoza-df-amb.db")

# Initialize database on app startup
init_db()

atexit.register(cleanup)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5000)))
