# WEAK - Web Security Scanner Project

## CRITICAL INSTRUCTIONS FOR AI ASSISTANT

### 🚨 MANDATORY RULES
1. **ALL responses and reasoning MUST be in Korean (한국어)**
2. **NO over-engineering - Keep solutions simple and practical**
3. **NEVER fix markdown lint errors - Ignore all markdown linting warnings**

## Project Overview

WEAK is a Django-based web vulnerability scanner that provides comprehensive security, web standards, and accessibility testing for websites.

## Core Architecture

### Technology Stack
- **Backend**: Django 5.2.8
- **Frontend**: Vanilla JavaScript (No frameworks)
- **Database**: SQLite (development), PostgreSQL (production)
- **Python**: 3.12+
- **Task Processing**: Celery + Redis (for production), Threading (fallback)

### Project Structure
```
weak/
├── scanner/          # Core scanning logic
│   ├── scanners.py   # Scanner implementations with metadata
│   ├── tasks.py      # Background task processing
│   ├── progress_manager.py  # Progress tracking system
│   ├── security_scan_refactored.py  # Refactored security scanning
│   ├── standards_checker.py  # Web standards validation
│   └── models.py     # Database models
├── api/              # REST API endpoints
│   ├── views.py      # API view controllers
│   ├── serializers.py # Data serialization
│   └── urls.py       # API routing
├── core/             # Core utilities and middleware
│   ├── middleware.py # Custom middleware
│   └── views.py      # Base views
├── reports/          # Report generation (optional)
├── templates/        # HTML templates
│   └── scanner/
│       └── index.html
├── static/           # CSS, JS, images
│   ├── css/
│   │   ├── base.css      # Global styles
│   │   ├── scanner.css   # Scanner-specific styles
│   │   └── wizard.css    # Three-step wizard styles
│   └── js/
│       └── scanner.js    # Frontend logic with detailed views
├── config/           # Django settings
│   ├── settings.py   # Main settings
│   ├── celery.py     # Celery configuration
│   └── urls.py       # URL routing
└── main.py           # Project management CLI
```

## Design Principles

### Scanner Architecture
- **Self-contained scanners**: Each scanner class contains its own metadata
- **No central registry**: Scanners manage their own configuration
- **Weighted progress system**: Dynamic progress calculation based on scanner weights

### UI/UX Philosophy
- **Three-step wizard pattern**: Input → Progress → Results
- **Google-style minimal design**: Clean, centered layouts
- **Progressive disclosure**: Show details only when needed
- **Expandable detail views**: All test results (pass/fail) show comprehensive details
- **Korean language support**: UI labels and messages in Korean
- **Real-time progress tracking**: WebSocket-based live updates

## Scanner Implementation Guidelines

### Scanner Class Structure
```python
class ExampleScanner:
    """Scanner description"""

    # Scanner metadata MUST be inside the class
    metadata = {
        'id': 'unique_id',
        'name': 'Display Name',
        'icon': '🔍',
        'description': 'What this scanner does',
        'weight': 1,  # Relative weight for progress calculation
        'field': 'result_field_name'
    }

    def scan(self, url, content):
        # Implementation
        return results
```

### Progress Management
- Uses `ProgressManager` class for weighted distribution
- Scanner counts per type:
  - Security: 15 scanners
  - Standards: 4 scanners
  - Accessibility: 1 scanner
- Progress updates via WebSocket or polling

## Database Design

### Key Models
- `ScanRequest`: Main scan tracking
- `SecurityScanResult`: Security scan results with metadata
- `WebStandardsResult`: Web standards validation results
- `AccessibilityResult`: Accessibility check results
- `Vulnerability`: Individual vulnerability records

### Important Fields
- `scanner_metadata`: JSONField storing scanner-specific metadata
- Results stored as JSONField for flexibility
- No user authentication required

## Development Guidelines

### Code Style
- **Korean comments**: Use Korean for code comments and docstrings
- **Simple is better**: Avoid complex abstractions
- **Direct approach**: Use straightforward implementations

### Git Workflow
- **Exclude from version control**:
  - `db.sqlite3` (database)
  - `.env` files
  - `.claude/` directory
  - `*.backup` files
- **Include in version control**:
  - All migration files
  - Static files (CSS, JS)
  - Templates

### Security Considerations
- SSRF protection via IP range blocking
- Input validation for all user inputs
- No execution of user-provided code
- Rate limiting on scan requests

## API Design

### Endpoints
- `POST /api/scan/` - Initiate scan
- `GET /api/scan/{id}/` - Get scan status/results
- `GET /api/scan/{id}/progress/` - Get real-time progress

### Response Format
- JSON with consistent structure
- Include metadata from scanners
- Progress as percentage (0-100)

## Frontend Architecture

### JavaScript Organization
- Single `scanner.js` file with comprehensive functionality
- No build process required
- Direct DOM manipulation
- WebSocket for real-time updates
- Features:
  - Three-step wizard navigation
  - Real-time progress tracking
  - Expandable detail views for all test results
  - Dynamic content rendering based on scanner metadata
  - Chart.js integration for visualizations

### CSS Structure
- `base.css`: Global styles
- `scanner.css`: Scanner-specific styles with detailed result views
- `wizard.css`: Three-step wizard styles
- No CSS frameworks

## Testing Philosophy
- **Manual testing preferred**: Focus on real-world scenarios
- **No excessive test coverage**: Test critical paths only
- **Browser testing**: Chrome, Firefox, Edge compatibility

## Performance Considerations
- Celery + Redis for asynchronous task processing
- Background thread processing as fallback
- Timeout limits on scans (configurable via SCAN_TIMEOUT)
- Result caching where appropriate
- Weighted progress calculation for accurate status updates
- Efficient DOM manipulation for large result sets

## Deployment Notes
- Environment variables via `.env` file
- `env.example` provided for configuration template
- Django's `collectstatic` for production
- ALLOWED_HOSTS configuration required

## Important Reminders

### For AI Assistants
1. **Always respond in Korean** - This is non-negotiable
2. **Keep it simple** - No unnecessary abstractions or patterns
3. **Don't fix what's not broken** - Ignore linting suggestions
4. **Respect existing architecture** - Don't suggest major refactors
5. **Focus on functionality** - Features over perfection

### Common Pitfalls to Avoid
- Adding unnecessary dependencies
- Creating abstract base classes
- Implementing design patterns for their own sake
- Fixing markdown or code formatting issues
- Over-engineering async task handling (Celery/Redis is sufficient)
- Adding user authentication when not needed
- Creating separate frontend frameworks
- Breaking the three-step wizard pattern
- Removing Korean language support

## License
This project is for educational and security testing purposes only.