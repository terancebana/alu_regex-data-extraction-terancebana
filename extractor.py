import re
import json
import sys
from typing import Dict, List, Any


class DataExtractor:
    
    def __init__(self):
        self.patterns = {
            "emails": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "urls": r'https?://(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:/[^\s<>"\']*)?',
            "phone_numbers": r'(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}',
            "credit_cards": r'(?:\d{4}[-\s]?){3}\d{4}',
            "time_formats": r'(?:(?:1[0-2]|0?[1-9]):[0-5]\d\s*(?:AM|PM|am|pm))|(?:(?:2[0-3]|[01]?\d):[0-5]\d)',
            "html_tags": r'<[a-zA-Z][a-zA-Z0-9]*(?:\s+[a-zA-Z][-a-zA-Z0-9]*=(?:"[^"]*"|\'[^\']*\'))*\s*/?>',
            "hashtags": r'#[a-zA-Z][a-zA-Z0-9_]*',
            "currency": r'\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?'
        }
        
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript\s*:',
            r'on\w+\s*=\s*["\']',
            r'data\s*:\s*text/html',
            r'eval\s*\(',
            r'document\s*\.\s*(?:cookie|write|location)',
            r'window\s*\.\s*(?:location|open)',
            r'alert\s*\(',
            r'<\s*iframe',
            r'<\s*object',
            r'<\s*embed',
            r'expression\s*\(',
            r'vbscript\s*:',
            r";\s*(?:DROP|DELETE|INSERT|UPDATE)\s+",
            r'UNION\s+SELECT',
            r"(?:^|['\"])\s*OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r'\.\./\.\.',
            r'%00',
            r'%0d%0a'
        ]
    
    def is_safe_input(self, text: str) -> bool:
        for pattern in self.dangerous_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return False
        return True
    
    def sanitize_output(self, data: Dict[str, List[str]]) -> Dict[str, List[str]]:
        sanitized = {}
        for key, values in data.items():
            sanitized[key] = []
            for value in values:
                if key == "credit_cards":
                    clean = re.sub(r'[-\s]', '', value)
                    masked = clean[:4] + "****" + "****" + clean[-4:]
                    sanitized[key].append(masked)
                elif key == "emails":
                    parts = value.split('@')
                    if len(parts) == 2:
                        username = parts[0]
                        if len(username) > 2:
                            masked_user = username[0] + "*" * (len(username) - 2) + username[-1]
                        else:
                            masked_user = username[0] + "*"
                        sanitized[key].append(f"{masked_user}@{parts[1]}")
                    else:
                        sanitized[key].append(value)
                else:
                    sanitized[key].append(value)
        return sanitized
    
    def validate_email(self, email: str) -> bool:
        if len(email) > 254:
            return False
        parts = email.split('@')
        if len(parts) != 2:
            return False
        local, domain = parts
        if len(local) > 64 or len(local) == 0:
            return False
        if len(domain) == 0 or '..' in domain:
            return False
        return True
    
    def validate_credit_card(self, card: str) -> bool:
        clean = re.sub(r'[-\s]', '', card)
        if not clean.isdigit() or len(clean) != 16:
            return False
        digits = [int(d) for d in clean]
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        return sum(digits) % 10 == 0
    
    def validate_url(self, url: str) -> bool:
        if len(url) > 2048:
            return False
        dangerous_chars = ['<', '>', '"', "'", '{', '}', '|', '\\', '^', '`']
        for char in dangerous_chars:
            if char in url:
                return False
        return True
    
    def validate_phone(self, phone: str) -> bool:
        digits = re.sub(r'\D', '', phone)
        return len(digits) >= 10 and len(digits) <= 11
    
    def extract(self, text: str) -> Dict[str, Any]:
        result = {
            "status": "success",
            "security_check": "passed",
            "data": {},
            "rejected": []
        }
        
        if not self.is_safe_input(text):
            result["status"] = "rejected"
            result["security_check"] = "failed"
            result["message"] = "Input contains potentially malicious content"
            return result
        
        for data_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            valid_matches = []
            
            for match in matches:
                is_valid = True
                
                if data_type == "emails":
                    is_valid = self.validate_email(match)
                elif data_type == "credit_cards":
                    is_valid = self.validate_credit_card(match)
                elif data_type == "urls":
                    is_valid = self.validate_url(match)
                elif data_type == "phone_numbers":
                    is_valid = self.validate_phone(match)
                
                if is_valid:
                    if match not in valid_matches:
                        valid_matches.append(match)
                else:
                    result["rejected"].append({"type": data_type, "value": match, "reason": "validation_failed"})
            
            result["data"][data_type] = valid_matches
        
        result["data"] = self.sanitize_output(result["data"])
        
        return result
    
    def extract_from_file(self, filepath: str) -> Dict[str, Any]:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                text = f.read()
            return self.extract(text)
        except FileNotFoundError:
            return {"status": "error", "message": f"File not found: {filepath}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


def main():
    extractor = DataExtractor()
    
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        result = extractor.extract_from_file(filepath)
    else:
        filepath = "sample_input.txt"
        result = extractor.extract_from_file(filepath)
    
    print(json.dumps(result, indent=2))
    
    return result


if __name__ == "__main__":
    main()
