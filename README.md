# Regex Data Extraction Tool

A Python-based tool that extracts structured data from raw text using regular expressions while implementing security validation to reject malicious input.

## Data Types Extracted

1. Email addresses
2. URLs
3. Phone numbers
4. Credit card numbers
5. Time formats (12-hour and 24-hour)
6. HTML tags
7. Hashtags
8. Currency amounts

## Security Features

The tool implements multiple security measures:

- Detection and rejection of XSS attack patterns (script tags, event handlers, javascript: URLs)
- SQL injection pattern detection
- Path traversal attempt detection
- Encoded attack detection (null bytes, CRLF injection)
- Credit card masking in output (shows first 4 and last 4 digits only)
- Email masking in output (hides username characters)
- Luhn algorithm validation for credit cards

## Usage

```bash
python3 extractor.py sample_input.txt
```

Or specify any text file:

```bash
python3 extractor.py your_input_file.txt
```

## Output

The tool outputs JSON with the following structure:

```json
{
  "status": "success",
  "security_check": "passed",
  "data": {
    "emails": [...],
    "urls": [...],
    "phone_numbers": [...],
    "credit_cards": [...],
    "time_formats": [...],
    "html_tags": [...],
    "hashtags": [...],
    "currency": [...]
  },
  "rejected": [...]
}
```

For malicious input, the output will be:

```json
{
  "status": "rejected",
  "security_check": "failed",
  "message": "Input contains potentially malicious content"
}
```

## Files

- `extractor.py` - Main extraction program
- `sample_input.txt` - Realistic sample input data
- `malicious_input.txt` - Test file with attack vectors
- `sample_output.json` - Output from sample input
- `malicious_output.json` - Output from malicious input (rejected)

## Validation Rules

- Emails: Must have valid format, max 254 characters, local part max 64 characters
- Credit Cards: Must pass Luhn algorithm checksum, exactly 16 digits
- URLs: Max 2048 characters, no dangerous characters
- Phone Numbers: Must have 10-11 digits
