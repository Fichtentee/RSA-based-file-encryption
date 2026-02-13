# server/validation.py
"""Input validation and sanitization for security."""
import re


# Security limits
MAX_ALIAS_LENGTH = 50
MIN_ALIAS_LENGTH = 3
MAX_FILENAME_LENGTH = 255
MAX_FILE_SIZE_MB = 16
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024  # 16 MB
MAX_MESSAGE_PAYLOAD_SIZE = 20 * 1024 * 1024  # 20 MB (Base64-encoded file)


class ValidationError(ValueError):
    """Custom exception for validation errors."""
    pass


def validate_alias(alias: str) -> str:
    """
    Validiert Client-Alias gegen bekannte Angriffsvektoren.
    
    Security Checks:
    - Länge: 3-50 Zeichen
    - Zeichen: Nur alphanumerisch, Unterstrich, Bindestrich
    - Kein Path Traversal
    
    Raises:
        ValidationError: Bei ungültigem Alias
    """
    if not alias:
        raise ValidationError("Alias is required")
    
    if not (MIN_ALIAS_LENGTH <= len(alias) <= MAX_ALIAS_LENGTH):
        raise ValidationError(
            f"Alias must be between {MIN_ALIAS_LENGTH} and {MAX_ALIAS_LENGTH} characters"
        )
    
    # Nur erlaubte Zeichen: alphanumerisch, Unterstrich, Bindestrich
    if not re.match(r'^[a-zA-Z0-9_-]+$', alias):
        raise ValidationError(
            "Alias contains invalid characters. Only letters, numbers, underscore and hyphen allowed"
        )
    
    # Explizite Path Traversal Prevention
    if ".." in alias or "/" in alias or "\\" in alias:
        raise ValidationError("Alias contains path traversal characters")
    
    return alias


def validate_filename(filename: str) -> str:
    """
    Sanitiert Dateinamen gegen Path Traversal und andere Angriffe.
    
    Security Checks:
    - Entfernt Path-Komponenten (nur Basename)
    - Entfernt Path Traversal Sequenzen
    - Längen-Limitierung
    - Kein leerer Filename
    
    Raises:
        ValidationError: Bei ungültigem Dateinamen
    """
    import os
    
    if not filename:
        raise ValidationError("Filename is required")
    
    # Normalisiere Pfadtrennzeichen (Windows + Unix)
    filename = filename.replace("\\", "/")
    
    # Nur Basename verwenden (entfernt alle Path-Komponenten)
    filename = os.path.basename(filename)
    
    # Entferne gefährliche Zeichen
    filename = filename.replace("..", "")
    filename = filename.replace("/", "")
    filename = filename.replace("\\", "")
    filename = filename.replace("\0", "")
    
    if not filename or filename in (".", ".."):
        raise ValidationError("Invalid filename after sanitization")
    
    if len(filename) > MAX_FILENAME_LENGTH:
        raise ValidationError(f"Filename too long (max {MAX_FILENAME_LENGTH} characters)")
    
    return filename


def validate_uuid(uuid: str) -> str:
    """
    Validiert UUID-Format.
    
    Security Checks:
    - Standard UUID-Format (8-4-4-4-12)
    - Verhindert übermäßig lange Strings
    
    Raises:
        ValidationError: Bei ungültigem UUID
    """
    if not uuid:
        raise ValidationError("UUID is required")
    
    # UUID sollte nicht übermäßig lang sein
    if len(uuid) > 100:
        raise ValidationError("UUID too long")
    
    # Standard UUID Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    if not re.match(uuid_pattern, uuid.lower()):
        raise ValidationError("Invalid UUID format")
    
    return uuid


def validate_payload_size(payload: dict) -> None:
    """
    Validiert Größe des Nachricht-Payloads.
    
    Security Checks:
    - Verhindert Memory Exhaustion durch riesige Payloads
    
    Raises:
        ValidationError: Bei zu großem Payload
    """
    import json
    
    # Approximiere Größe durch JSON-Serialisierung
    try:
        payload_str = json.dumps(payload)
        size = len(payload_str)
        
        if size > MAX_MESSAGE_PAYLOAD_SIZE:
            raise ValidationError(
                f"Payload too large: {size} bytes (max {MAX_MESSAGE_PAYLOAD_SIZE})"
            )
    except (TypeError, ValueError) as e:
        raise ValidationError(f"Invalid payload structure: {e}")
