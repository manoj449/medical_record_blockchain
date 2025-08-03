from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import mysql.connector
import os
from blockchain import Blockchain
from config import Config
from datetime import datetime
import hashlib
import PyPDF2
from docx import Document
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.config.from_object(Config)
blockchain = Blockchain()

   # Encryption setup
cipher_suite = Fernet(Config.ENCRYPTION_KEY)

   # Database connection
def get_db_connection():
       return mysql.connector.connect(
           host=app.config['MYSQL_HOST'],
           user=app.config['MYSQL_USER'],
           password=app.config['MYSQL_PASSWORD'],
           database=app.config['MYSQL_DB']
       )

   # Home route
@app.route('/')
def home():
       if 'user_id' in session:
           return redirect(url_for('dashboard'))
       return redirect(url_for('login'))

   # Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
       if request.method == 'POST':
           username = request.form['username']
           password = request.form['password']
           conn = get_db_connection()
           cursor = conn.cursor()
           cursor.execute('SELECT id, password FROM users WHERE username = %s', (username,))
           user = cursor.fetchone()
           cursor.close()
           conn.close()
           if user and check_password_hash(user[1], password):
               session['user_id'] = user[0]
               flash('Login successful!', 'success')
               return redirect(url_for('dashboard'))
           flash('Invalid credentials', 'danger')
       return render_template('login.html')

   # Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
       if request.method == 'POST':
           username = request.form['username']
           password = request.form['password']
           hashed_password = generate_password_hash(password)
           conn = get_db_connection()
           cursor = conn.cursor()
           try:
               cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
               conn.commit()
               flash('Registration successful! Redirecting to login...', 'success')
               return redirect(url_for('register'))
           except mysql.connector.Error:
               flash('Username already exists', 'danger')
           finally:
               cursor.close()
               conn.close()
       return render_template('register.html')

   # Dashboard route
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
       if 'user_id' not in session:
           return redirect(url_for('login'))
       if request.method == 'POST':
           file = request.files['file']
           if file and allowed_file(file.filename):
               filename = secure_filename(file.filename)
               temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
               file.save(temp_path)
               # Encrypt file
               with open(temp_path, 'rb') as f:
                   file_data = f.read()
               encrypted_data = cipher_suite.encrypt(file_data)
               # Mock IPFS upload (replace with real IPFS client)
               ipfs_hash = mock_ipfs_upload(encrypted_data)
               os.remove(temp_path)  # Clean up temporary file
               file_hash = calculate_file_hash(temp_path, file.filename.rsplit('.', 1)[1].lower())  # Use original file for hash
               prev_hash = blockchain.get_previous_hash()
               # Compute block_hash (simplified for now, adjust based on blockchain logic)
               block_hash = hashlib.sha256(f"{session['user_id']}{ipfs_hash}{prev_hash}{datetime.utcnow()}".encode()).hexdigest()
               timestamp = datetime.utcnow()
               blockchain.add_block(session['user_id'], ipfs_hash, prev_hash, block_hash, timestamp)
               conn = get_db_connection()
               cursor = conn.cursor()
               cursor.execute(
                   'INSERT INTO records (user_id, file_name, file_type, ipfs_hash, block_hash, prev_hash, timestamp) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                   (session['user_id'], filename, file.filename.rsplit('.', 1)[1].lower(), ipfs_hash, block_hash, prev_hash, timestamp)
               )
               conn.commit()
               print(f"Inserted record: user_id={session['user_id']}, filename={filename}, ipfs_hash={ipfs_hash}")
               cursor.close()
               conn.close()
               flash('File uploaded and added to blockchain!', 'success')
           else:
               flash('Invalid file type', 'danger')
       return render_template('dashboard.html')

   # Records route
@app.route('/records')
def records():
       if 'user_id' not in session:
           return redirect(url_for('login'))
       conn = get_db_connection()
       cursor = conn.cursor()
       cursor.execute('SELECT file_name, file_type, ipfs_hash, block_hash, prev_hash, timestamp FROM records WHERE user_id = %s', (session['user_id'],))
       records = cursor.fetchall()
       cursor.close()
       conn.close()
       processed_records = []
       upload_folder = app.config['UPLOAD_FOLDER']
       print(f"Retrieved records for user_id={session['user_id']}: {records}")  # Debug print
       for record in records:
           if record[2]:  # Check if ipfs_hash exists
               relative_path = record[2]  # Use IPFS hash directly
               static_url = url_for('static', filename=relative_path)
               print(f"Processing record: {record}, Static URL: {static_url}")
               processed_records.append((record[0], record[1], relative_path, record[3], record[4], record[5]))
           else:
               print(f"Invalid IPFS hash for record: {record}")
       return render_template('records.html', records=processed_records, upload_folder=upload_folder)

   # Access Requests route
@app.route('/access_requests')
def access_requests():
       if 'user_id' not in session:
           return redirect(url_for('login'))
       conn = get_db_connection()
       cursor = conn.cursor()
       cursor.execute('SELECT id, doctor_id, patient_id, record_ipfs_hash, status, timestamp FROM access_requests WHERE patient_id = %s', (session['user_id'],))
       requests = cursor.fetchall()
       cursor.close()
       conn.close()
       print(f"Retrieved access requests for user_id={session['user_id']}: {requests}")  # Debug print
       return render_template('access_requests.html', requests=requests)

   # Approve access request
@app.route('/approve_request/<int:request_id>')
def approve_request(request_id):
       if 'user_id' not in session:
           return redirect(url_for('login'))
       conn = get_db_connection()
       cursor = conn.cursor()
       cursor.execute('UPDATE access_requests SET status = %s WHERE id = %s AND patient_id = %s', ('approved', request_id, session['user_id']))
       conn.commit()
       cursor.close()
       conn.close()
       flash('Access request approved!', 'success')
       return redirect(url_for('access_requests'))

   # Retrieve record (for authorized doctors)
@app.route('/retrieve/<ipfs_hash>')
def retrieve_record(ipfs_hash):
       if 'user_id' not in session:
           return "Unauthorized", 403
       conn = get_db_connection()
       cursor = conn.cursor()
       cursor.execute('SELECT r.file_name, r.file_type FROM records r JOIN access_requests ar ON r.ipfs_hash = ar.record_ipfs_hash WHERE ar.doctor_id = %s AND ar.record_ipfs_hash = %s AND ar.status = %s', (session['user_id'], ipfs_hash, 'approved'))
       record = cursor.fetchone()
       cursor.close()
       conn.close()
       if record:
           # Mock IPFS retrieval and decryption
           encrypted_data = mock_ipfs_retrieve(ipfs_hash)
           decrypted_data = cipher_suite.decrypt(encrypted_data)
           return decrypted_data  # Should serve as file download in production
       return "Access denied or record not found", 403

   # Mock IPFS functions (replace with real IPFS client)
def mock_ipfs_upload(data):
       # Simulate IPFS hash generation
       return base64.b64encode(data[:10]).decode('utf-8')  # Simple mock hash

def mock_ipfs_retrieve(ipfs_hash):
       # Simulate IPFS retrieval
       return cipher_suite.encrypt(b"Mock decrypted data for " + ipfs_hash.encode())  # Mock encrypted data

   # Logout route
@app.route('/logout')
def logout():
       session.pop('user_id', None)
       flash('Logged out successfully', 'success')
       return redirect(url_for('login'))

   # Helper functions
def allowed_file(filename):
       return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_file_hash(file_path, file_type):
       sha256_hash = hashlib.sha256()
       if os.path.exists(file_path):
           with open(file_path, 'rb') as f:
               for byte_block in iter(lambda: f.read(4096), b''):
                   sha256_hash.update(byte_block)
       return sha256_hash.hexdigest()

if __name__ == '__main__':
       app.run(debug=True)