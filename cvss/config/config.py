import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    # Flask Configuration
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')  # Added for security
    
    # AI Configuration
    AI_PROVIDER = os.getenv('AI_PROVIDER', 'ollama')
    OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
    OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama2')
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
    
    # File Upload Configuration
    ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv'}
    
    # Logging Configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    @staticmethod
    def init_app(app):
        # Ensure upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
