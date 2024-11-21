import pytest
import os
from cvss.services.file_service import FileService
from werkzeug.datastructures import FileStorage
from io import BytesIO

@pytest.fixture
def file_service():
    return FileService()

@pytest.fixture
def sample_excel_content():
    return b'PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00!test'  # Minimal Excel file signature

@pytest.fixture
def sample_csv_content():
    return b'Description,Severity\nTest threat 1,High\nTest threat 2,Medium'

def test_allowed_file(file_service):
    """Test file type validation."""
    assert file_service._allowed_file('test.xlsx') is True
    assert file_service._allowed_file('test.xls') is True
    assert file_service._allowed_file('test.csv') is True
    assert file_service._allowed_file('test.txt') is False
    assert file_service._allowed_file('test') is False

def test_find_description_column(file_service):
    """Test description column detection."""
    # Exact match
    headers = ['ID', 'Description', 'Severity']
    assert file_service._find_description_column(headers) == 1

    # Partial match
    headers = ['ID', 'Threat Details', 'Severity']
    assert file_service._find_description_column(headers) == 1

    # Single column
    headers = ['Description']
    assert file_service._find_description_column(headers) == 0

    # No match
    headers = ['ID', 'Status', 'Severity']
    assert file_service._find_description_column(headers) is None

def test_save_uploaded_file(file_service, sample_excel_content):
    """Test file upload handling."""
    # Create a test file
    test_file = FileStorage(
        stream=BytesIO(sample_excel_content),
        filename='test.xlsx',
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

    # Save the file
    filepath = file_service.save_uploaded_file(test_file)
    
    # Verify file was saved
    assert filepath is not None
    assert os.path.exists(filepath)
    assert filepath.endswith('test.xlsx')
    
    # Clean up
    os.remove(filepath)

def test_save_uploaded_file_invalid(file_service):
    """Test invalid file upload handling."""
    # Create an invalid file
    test_file = FileStorage(
        stream=BytesIO(b'test'),
        filename='test.txt',
        content_type='text/plain'
    )

    # Try to save the file
    filepath = file_service.save_uploaded_file(test_file)
    
    # Verify file was not saved
    assert filepath is None

def test_create_excel_output(file_service):
    """Test Excel output creation."""
    results = [{
        'description': 'Test threat',
        'metrics': {
            'AV': 'N',
            'AC': 'L',
            'PR': 'N',
            'UI': 'N',
            'S': 'U',
            'C': 'H',
            'I': 'H',
            'A': 'H',
            'explanation': 'Test explanation',
            'confidence': 85
        },
        'cvss_score': 9.8,
        'severity': 'CRITICAL'
    }]

    output_path = os.path.join(file_service.upload_folder, 'test_output.xlsx')
    result_path = file_service.create_excel_output(results, output_path)
    
    # Verify file was created
    assert result_path is not None
    assert os.path.exists(result_path)
    
    # Clean up
    os.remove(result_path)
