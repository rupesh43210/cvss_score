import json
import requests
from typing import Dict, Optional, List, Tuple
from openai import OpenAI
from cvss.config.config import Config
from cvss.utils.logger import setup_logger
import concurrent.futures
import multiprocessing
from functools import partial
import re

logger = setup_logger(__name__)

class AIService:
    def __init__(self):
        self.openai_client = OpenAI(api_key=Config.OPENAI_API_KEY) if Config.OPENAI_API_KEY else None
        # Use 75% of available CPU cores for parallel processing
        self.max_workers = max(1, int(multiprocessing.cpu_count() * 0.75))
        logger.info(f"Initialized AIService with {self.max_workers} workers")
    
    def analyze_threats(self, descriptions: List[str]) -> List[Optional[Dict]]:
        """
        Analyze multiple security threats in parallel using the configured AI provider.
        
        Args:
            descriptions (List[str]): List of threat descriptions to analyze
            
        Returns:
            List[Optional[Dict]]: List of analysis results
        """
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                results = list(executor.map(self.analyze_threat, descriptions))
            return results
        except Exception as e:
            logger.error(f"Error in parallel threat analysis: {str(e)}", exc_info=True)
            return [None] * len(descriptions)

    def analyze_threat(self, description: str) -> Optional[Dict]:
        """
        Analyze a security threat using the configured AI provider.
        
        Args:
            description (str): The threat description to analyze
            
        Returns:
            Optional[Dict]: Analysis results or None if analysis fails
        """
        try:
            if Config.AI_PROVIDER == 'ollama':
                return self._analyze_with_ollama(description)
            elif Config.AI_PROVIDER == 'openai':
                return self._analyze_with_openai(description)
            else:
                logger.error(f"Unknown AI provider: {Config.AI_PROVIDER}")
                return None
        except Exception as e:
            logger.error(f"Error analyzing threat: {str(e)}", exc_info=True)
            return None

    def _analyze_with_ollama(self, description: str) -> Optional[Dict]:
        """Analyze threat using Ollama model."""
        logger.info(f"Analyzing threat with Ollama ({Config.OLLAMA_MODEL})")
        
        prompt = self._create_analysis_prompt(description)
        
        try:
            response = requests.post(
                f"{Config.OLLAMA_HOST}/api/generate",
                json={
                    "model": Config.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 1000,  # Increased for more detailed responses
                        "top_k": 50,
                        "top_p": 0.95,
                        "repeat_penalty": 1.1
                    }
                },
                timeout=45  # Increased timeout for more thorough analysis
            )
            
            if response.status_code != 200:
                logger.error(f"Ollama API error: {response.text}")
                return None

            content = response.json()['response']
            return self._parse_ai_response(content)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama API request failed: {str(e)}", exc_info=True)
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Ollama response: {str(e)}", exc_info=True)
            return None

    def _analyze_with_openai(self, description: str) -> Optional[Dict]:
        """Analyze threat using OpenAI."""
        if not self.openai_client:
            logger.error("OpenAI client not initialized - missing API key")
            return None
            
        logger.info("Analyzing threat with OpenAI")
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {
                        "role": "system", 
                        "content": (
                            "You are a senior security expert specializing in CVSS v3.1 scoring. "
                            "Your task is to analyze security threats and provide accurate, unique CVSS metrics for each threat. "
                            "Consider all aspects of the threat carefully, including technical details, attack patterns, and potential impact. "
                            "Be precise and thorough in your analysis, ensuring each score reflects the specific characteristics of the threat."
                        )
                    },
                    {"role": "user", "content": self._create_analysis_prompt(description)}
                ],
                temperature=0.3,
                max_tokens=1000,  # Increased for more detailed responses
                presence_penalty=0.1,  # Slightly penalize repetitive responses
                frequency_penalty=0.1  # Encourage more diverse language
            )
            
            content = response.choices[0].message.content
            return self._parse_ai_response(content)
            
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}", exc_info=True)
            return None

    def _create_analysis_prompt(self, description: str) -> str:
        """Create the analysis prompt for AI models."""
        return (
            "Analyze the following security threat and provide CVSS v3.1 metrics in a strict JSON format. "
            "Consider all aspects carefully and provide unique, accurate scores specific to this threat:\n\n"
            f"Threat Description: {description}\n\n"
            "Consider these aspects in your analysis:\n"
            "1. How is the vulnerability accessed? (Network, Adjacent, Local, Physical)\n"
            "2. What technical skills or resources are needed to exploit it?\n"
            "3. What privileges are required for the attack?\n"
            "4. Is user interaction needed?\n"
            "5. Does the attack impact extend beyond the vulnerable component?\n"
            "6. What are the confidentiality, integrity, and availability impacts?\n\n"
            "Return a JSON object with these exact fields:\n"
            "{\n"
            '    "AV": "N",     // Attack Vector: Network (N), Adjacent (A), Local (L), Physical (P)\n'
            '    "AC": "L",     // Attack Complexity: Low (L) or High (H)\n'
            '    "PR": "N",     // Privileges Required: None (N), Low (L), High (H)\n'
            '    "UI": "N",     // User Interaction: None (N) or Required (R)\n'
            '    "S": "U",      // Scope: Unchanged (U) or Changed (C)\n'
            '    "C": "N",      // Confidentiality Impact: None (N), Low (L), High (H)\n'
            '    "I": "N",      // Integrity Impact: None (N), Low (L), High (H)\n'
            '    "A": "N",      // Availability Impact: None (N), Low (L), High (H)\n'
            '    "explanation": "Brief explanation of the analysis",\n'
            '    "justification": "Detailed justification of each metric choice, explaining the specific characteristics of this threat that led to each score",\n'
            '    "confidence": 85  // Confidence level (0-100) based on available information\n'
            "}\n\n"
            "Important:\n"
            "- Analyze THIS SPECIFIC threat carefully - do not use generic scores\n"
            "- Provide detailed justification for each metric choice\n"
            "- Consider real-world impact and exploitability\n"
            "- If uncertain about any metric, explain your reasoning in the justification\n"
            "\nProvide ONLY the JSON object, no additional text."
        )

    def _parse_ai_response(self, content: str) -> Optional[Dict]:
        """Parse and validate AI response."""
        if not content:
            logger.error("Empty AI response")
            return None

        logger.debug(f"Raw AI response:\n{content}")
        
        try:
            # First try direct JSON parsing
            return json.loads(content)
        except json.JSONDecodeError:
            # If direct parsing fails, try to clean and fix the content
            try:
                # Remove any potential markdown code block markers
                content = content.replace('```json', '').replace('```', '')
                
                # Split into lines and clean each line
                lines = []
                in_string = False
                quote_char = None
                
                # First pass: basic cleanup
                for line in content.split('\n'):
                    # Remove comments
                    if '//' in line and not in_string:
                        line = line.split('//')[0]
                    
                    # Clean whitespace but preserve spaces in strings
                    if not in_string:
                        line = line.strip()
                    
                    # Skip empty lines
                    if not line:
                        continue
                    
                    # Track string boundaries
                    for i, char in enumerate(line):
                        if char in ['"', "'"] and (i == 0 or line[i-1] != '\\'):
                            if not in_string:
                                in_string = True
                                quote_char = char
                            elif char == quote_char:
                                in_string = False
                                quote_char = None
                    
                    lines.append(line)
                
                # Second pass: fix JSON structure
                fixed_lines = []
                for i, line in enumerate(lines):
                    # Remove trailing commas at the end of objects/arrays
                    if i < len(lines) - 1:
                        next_line = lines[i + 1].strip()
                        if line.rstrip().endswith(',') and next_line.startswith('}'):
                            line = line.rstrip(',')
                    
                    # Handle trailing commas in the last field
                    if i == len(lines) - 1 and line.rstrip().endswith(','):
                        line = line.rstrip(',')
                    
                    # Ensure proper field separation
                    if (line.lstrip().startswith('"') and 
                        not line.rstrip().endswith(',') and
                        i < len(lines) - 1 and
                        not lines[i + 1].lstrip().startswith('}')):
                        line += ','
                    
                    # Fix malformed field values
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().strip('"')
                        value = value.strip().strip(',')
                        
                        # Ensure proper string quotes
                        if not key.startswith('"'):
                            key = f'"{key}"'
                        
                        # Handle non-string values
                        try:
                            float(value)  # Check if number
                        except ValueError:
                            if value.lower() not in ['true', 'false', 'null'] and not value.startswith('"'):
                                value = f'"{value}"'
                        
                        line = f'{key}: {value}'
                        
                        # Add comma if not last line and next line isn't closing brace
                        if i < len(lines) - 1 and not lines[i + 1].strip().startswith('}'):
                            line += ','
                    
                    fixed_lines.append(line)
                
                # Join lines and ensure proper JSON structure
                content = '\n'.join(fixed_lines)
                if not content.strip().startswith('{'):
                    content = '{' + content
                if not content.strip().endswith('}'):
                    content = content + '}'
                
                # Remove any remaining invalid commas
                content = re.sub(r',\s*}', '}', content)
                content = re.sub(r',\s*]', ']', content)
                
                logger.debug(f"Cleaned JSON content:\n{content}")
                
                analysis = json.loads(content)
                
                # Validate required fields
                required_fields = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 
                                 'explanation', 'justification', 'confidence']
                missing_fields = [field for field in required_fields if field not in analysis]
                
                if missing_fields:
                    logger.error(f"Missing required fields in AI response: {missing_fields}")
                    return None
                
                # Validate field values
                cvss_metrics = {
                    'AV': ['N', 'A', 'L', 'P'],
                    'AC': ['L', 'H'],
                    'PR': ['N', 'L', 'H'],
                    'UI': ['N', 'R'],
                    'S': ['U', 'C'],
                    'C': ['N', 'L', 'H'],
                    'I': ['N', 'L', 'H'],
                    'A': ['N', 'L', 'H']
                }
                
                for metric, valid_values in cvss_metrics.items():
                    if analysis[metric] not in valid_values:
                        logger.error(f"Invalid value for {metric}: {analysis[metric]}")
                        return None
                
                # Validate explanation and justification length
                if len(analysis['explanation']) < 50:
                    logger.error("Explanation too short")
                    return None
                if len(analysis['justification']) < 100:
                    logger.error("Justification too short")
                    return None
                
                # Validate confidence score
                if not isinstance(analysis['confidence'], (int, float)) or \
                   not 0 <= analysis['confidence'] <= 100:
                    logger.error(f"Invalid confidence score: {analysis['confidence']}")
                    return None
                
                return analysis
                
            except Exception as e:
                logger.error(f"Failed to parse AI response: {str(e)}\nContent:\n{content}")
                return None

    def get_available_ollama_models(self) -> List[str]:
        """Get list of available Ollama models."""
        try:
            response = requests.get(f"{Config.OLLAMA_HOST}/api/tags")
            if response.status_code == 200:
                models = response.json().get('models', [])
                return [model['name'] for model in models]
            else:
                logger.error(f"Failed to get Ollama models: {response.text}")
                return ['llama2']  # Return default model if request fails
        except Exception as e:
            logger.error(f"Error getting Ollama models: {str(e)}", exc_info=True)
            return ['llama2']  # Return default model on error
