# Sample Files for Testing

This directory contains pre-existing files that you can use to test the RSA Hybrid FileCrypter.

## Available Files:

### Text Files
- **secret_message.txt** (~250 bytes) - A classified project message
- **meeting_notes.txt** (~500 bytes) - Confidential meeting notes with action items
- **credentials.txt** (~400 bytes) - Sensitive database credentials and API keys

### Binary Files
- **contract_draft.pdf** (~1.5 KB) - A confidential service agreement contract

## Usage Examples:

### Send a text file:
```bash
python client.py --alias Client1 send --partner Client2 --file ../files/secret_message.txt
```

### Send the PDF:
```bash
python client.py --alias Client1 send --partner Client2 --file ../files/contract_draft.pdf
```

### Send meeting notes:
```bash
python client.py --alias Client1 send --partner Client2 --file ../files/meeting_notes.txt
```

## Notes:
- The encryption system works with ANY file type (text, PDF, images, etc.)
- Files are encrypted using AES-256-GCM after being read in binary mode
- The AES key is protected using RSA-OAEP with the recipient's public key
- Maximum practical file size depends on available memory (entire file is read into memory)
