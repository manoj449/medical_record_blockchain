import os

class Config:
         SECRET_KEY = 'your-secret-key-here'
         MYSQL_HOST = 'localhost'
         MYSQL_USER = 'root'
         MYSQL_PASSWORD = 'root'
         MYSQL_DB = 'medical_records'
         UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
         ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'dcm'}
         ENCRYPTION_KEY = b'e4a5V51OeaTOCuMgI95Qn8fhr3wp2Vci_YMe2picHh8='  # Replace with the key from step 3