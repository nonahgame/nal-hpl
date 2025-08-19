import os
import sqlite3
import logging
import pandas as pd
import traceback
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from github import Github
from dotenv import load_dotenv
import telegram
from telegram.ext import Application
import asyncio

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')

# Configure logging
logging.basicConfig(filename='renda_bot.log', level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
logger.debug("Loaded environment variables from .env file")

DB_PATH = "gwoza-df-amb.db"
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_REPO = os.getenv('GITHUB_REPO', 'nonahgame/nal-hpl')
GITHUB_PATH = os.getenv('GITHUB_PATH', 'dat/gwoza-df-amb.db')
BOT_TOKEN = os.getenv('BOT_TOKEN')
CHAT_ID = os.getenv('CHAT_ID')
ADMIN_PASSPHRASE = os.getenv('ADMIN_PASSPHRASE')

# Initialize Telegram bot
telegram_bot = None
try:
    if BOT_TOKEN and CHAT_ID:
        telegram_bot = Application.builder().token(BOT_TOKEN).build()
        logger.info("Telegram bot initialized successfully")
    else:
        logger.warning("BOT_TOKEN or CHAT_ID not set, Telegram bot not initialized")
except Exception as e:
    logger.error(f"Failed to initialize Telegram bot: {str(e)}")
    telegram_bot = None

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def validate_numeric(value, field_name):
    try:
        return float(value) if value else None
    except ValueError:
        logger.error(f"Invalid {field_name}: {value}")
        raise ValueError(f"Invalid {field_name}: {value}")

def upload_to_github(file_path, repo_name, github_path):
    if not GITHUB_TOKEN:
        logger.warning("GITHUB_TOKEN not set, skipping GitHub upload")
        return
    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(repo_name)
        with open(file_path, 'rb') as file:
            content = file.read()
        try:
            contents = repo.get_contents(github_path)
            repo.update_file(github_path, f"Update {file_path}", content, contents.sha)
            logger.info(f"Updated {file_path} on GitHub")
        except:
            repo.create_file(github_path, f"Create {file_path}", content)
            logger.info(f"Created {file_path} on GitHub")
    except Exception as e:
        logger.error(f"Failed to upload to GitHub: {str(e)}")

async def send_telegram_message(message):
    if telegram_bot is None:
        logger.warning("Telegram bot not initialized, skipping notification")
        return
    try:
        await telegram_bot.bot.send_message(chat_id=CHAT_ID, text=message)
        logger.info(f"Sent Telegram message: {message}")
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {str(e)}")

def sync_send_telegram_message(message):
    if telegram_bot is None:
        logger.warning("Telegram bot not initialized, skipping sync notification")
        return
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is already running, create a new one for async execution
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            try:
                new_loop.run_until_complete(send_telegram_message(message))
            finally:
                new_loop.close()
        else:
            loop.run_until_complete(send_telegram_message(message))
    except Exception as e:
        logger.error(f"Failed to send sync Telegram message: {str(e)}")

# Routes (only admin route shown for brevity; other routes remain as previously provided)
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

# Other routes (index, login, register, etc.) remain as previously provided
# Example placeholder for index route
@app.route('/index', methods=['GET', 'POST'])
def index():
    # Implement as per previous responses
    pass

if __name__ == '__main__':
    app.run(debug=True)
