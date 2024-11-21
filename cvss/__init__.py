import os
from flask import Flask
from cvss.api.routes import api
from cvss.config.config import Config

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Base upload directory
    base_upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    
    # Ensure the input and output folders exist
    input_folder = os.path.join(base_upload_dir, 'input')
    output_folder = os.path.join(base_upload_dir, 'output')
    os.makedirs(input_folder, exist_ok=True)
    os.makedirs(output_folder, exist_ok=True)
    
    # Configure upload folders
    app.config['UPLOAD_FOLDER'] = input_folder
    app.config['OUTPUT_FOLDER'] = output_folder
    
    # Register blueprints
    app.register_blueprint(api)
    
    return app
