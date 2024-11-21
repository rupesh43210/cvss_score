# CVSS Threat Analysis Application

A comprehensive web application for analyzing security vulnerabilities and generating CVSS (Common Vulnerability Scoring System) scores using AI-powered threat metrics.

## Features

- Upload Excel (.xlsx, .xls) or CSV files containing threat descriptions
- AI-powered threat analysis using Ollama or OpenAI
- CVSS score calculation and severity assessment
- Interactive web interface with real-time feedback
- Excel report generation with detailed analysis
- Support for multiple AI models
- Comprehensive logging and error handling

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cvss.git
cd cvss
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with the following configuration:
```env
AI_PROVIDER=ollama  # or openai
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama2
OPENAI_API_KEY=your_openai_key  # Only if using OpenAI
SECRET_KEY=your_secret_key
LOG_LEVEL=INFO
```

## Usage

1. Start the application:
```bash
python run.py
```

2. Open your browser and navigate to `http://localhost:5000`

3. Select an AI model from the dropdown menu

4. Upload an Excel or CSV file containing threat descriptions

5. View the analysis results and download the Excel report

## File Format

Your input file should contain a column with threat descriptions. The application will automatically detect the appropriate column using the following keywords:
- description
- threat
- vulnerability
- details

## Development

### Project Structure
```
cvss/
├── cvss/              # Main package
│   ├── api/          # API routes
│   ├── config/       # Configuration
│   ├── services/     # Business logic
│   ├── static/       # Static files
│   ├── templates/    # HTML templates
│   └── utils/        # Utilities
├── tests/            # Test files
├── uploads/          # Uploaded files
└── logs/             # Application logs
```

### Running Tests
```bash
pytest
```

### Code Quality
```bash
# Format code
black .
isort .

# Check code quality
flake8
mypy .
```

## Security Considerations

- Input validation for all file uploads
- File size limits (16MB max)
- Secure file handling and path validation
- Environment variable configuration
- Error handling without exposing sensitive information

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
