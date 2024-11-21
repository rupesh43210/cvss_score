from flask import Blueprint, request, render_template, jsonify, send_from_directory, current_app
from werkzeug.utils import safe_join, secure_filename
from cvss.services.ai_service import AIService
from cvss.services.cvss_service import CVSSService
from cvss.services.file_service import FileService
from cvss.config.config import Config
from cvss.utils.logger import setup_logger
import os
import mimetypes

logger = setup_logger(__name__)
api = Blueprint('api', __name__)

# Initialize services
ai_service = AIService()
cvss_service = CVSSService()
file_service = FileService()

@api.route('/')
def index():
    """Render the main page."""
    return render_template('index.html', config=Config)

@api.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and process it."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        filename = file_service.save_uploaded_file(file)
        if not filename:
            return jsonify({'error': 'Failed to save file'}), 500
        
        return jsonify({
            'message': 'File uploaded successfully',
            'filename': filename
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/analyze', methods=['POST'])
def analyze_file():
    """Analyze the uploaded file."""
    try:
        data = request.get_json()
        if not data or 'filename' not in data:
            return jsonify({'error': 'No filename provided'}), 400
        
        input_filename = data['filename']
        input_path = safe_join(file_service.upload_folder, input_filename)
        
        if not input_path or not os.path.exists(input_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Read threats from file
        threats = file_service.read_threats(input_path)
        if not threats:
            return jsonify({'error': 'No threats found in file'}), 400

        # Analyze threats
        results = []
        for threat in threats:
            # Get AI analysis
            metrics = ai_service.analyze_threat(threat['description'])
            if not metrics:
                logger.warning(f"Failed to analyze threat: {threat['description'][:100]}...")
                continue

            # Calculate CVSS score
            cvss_score, severity = cvss_service.calculate_score(metrics)
            if cvss_score is None:
                logger.warning(f"Failed to calculate CVSS score for threat: {threat['description'][:100]}...")
                continue

            results.append({
                'description': threat['description'],
                'metrics': metrics,
                'cvss_score': cvss_score,
                'severity': severity
            })

        if not results:
            return jsonify({'error': 'No valid results generated'}), 400

        output_filename = file_service.create_excel_output(results, input_filename)
        
        if not output_filename:
            return jsonify({'error': 'Failed to create output file'}), 500
        
        return jsonify({
            'message': 'Analysis completed successfully',
            'input_file': input_filename,
            'output_file': output_filename,
            'results': results
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/download/<path:filename>')
def download_file(filename):
    """Download a file from either input or output directory."""
    try:
        # First try the output folder
        if filename.startswith('analysis_'):
            return send_from_directory(
                file_service.output_folder,
                filename,
                as_attachment=True
            )
        
        # Then try the input folder
        return send_from_directory(
            file_service.upload_folder,
            filename,
            as_attachment=True
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 404

@api.route('/models', methods=['GET'])
def get_models():
    """Get available AI models."""
    try:
        if Config.AI_PROVIDER == 'ollama':
            models = ai_service.get_available_ollama_models()
            return jsonify({'models': models})
        return jsonify({'models': ['gpt-3.5-turbo']})
    except Exception as e:
        logger.error(f"Error getting models: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to get models'}), 500

@api.route('/model', methods=['POST'])
def set_model():
    """Set the current AI model."""
    try:
        model = request.json.get('model')
        if not model:
            return jsonify({'error': 'No model specified'}), 400
            
        if Config.AI_PROVIDER == 'ollama':
            Config.OLLAMA_MODEL = model
            return jsonify({'message': f'Model set to {model}'})
        return jsonify({'error': 'Model selection not supported for current AI provider'}), 400
    except Exception as e:
        logger.error(f"Error setting model: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to set model'}), 500
