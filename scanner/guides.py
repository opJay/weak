"""
스캐너별 가이드 정보
각 스캐너에 대한 설명, 권장사항, 참고 자료 등을 포함
"""

SCANNER_GUIDES = {
    # XSS (Cross-Site Scripting)
    'xss': {
        'description': 'Cross-Site Scripting(XSS)은 공격자가 웹 애플리케이션에 악성 스크립트를 삽입하여 다른 사용자의 브라우저에서 실행되도록 하는 취약점입니다.',
        'owasp': ['A03:2025'],
        'cwe': ['CWE-79', 'CWE-80'],
        'remediation': {
            'steps': [
                '모든 사용자 입력값을 HTML 인코딩하여 출력',
                'Content-Security-Policy(CSP) 헤더 설정',
                'X-XSS-Protection 헤더 활성화',
                '템플릿 엔진의 자동 이스케이프 기능 사용',
                '위험한 JavaScript 함수(eval, innerHTML) 사용 금지'
            ],
            'code_examples': {
                'vulnerable': '<div>{{userInput}}</div>',
                'secure': '<div>{{escape(userInput)}}</div>'
            },
            'framework_specific': {
                'django': 'Django 템플릿의 {{ variable|escape }} 필터 사용',
                'react': 'JSX는 기본적으로 자동 이스케이프됨',
                'vue': 'v-text 대신 v-html 사용 자제'
            }
        },
        'references': [
            'https://owasp.org/www-community/attacks/xss/',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/79.html'
        ]
    },

    # SQL Injection
    'sql_injection': {
        'description': 'SQL Injection은 공격자가 악의적인 SQL 쿼리를 삽입하여 데이터베이스를 조작하는 취약점입니다.',
        'owasp': ['A03:2025'],
        'cwe': ['CWE-89'],
        'remediation': {
            'steps': [
                '매개변수화된 쿼리(Prepared Statements) 사용',
                'ORM(Object-Relational Mapping) 프레임워크 활용',
                '입력값 검증 및 화이트리스트 적용',
                '최소 권한 원칙으로 DB 사용자 권한 제한',
                '저장 프로시저 사용 고려'
            ],
            'code_examples': {
                'vulnerable': "SELECT * FROM users WHERE id = '{user_id}'",
                'secure': 'SELECT * FROM users WHERE id = ?'
            },
            'framework_specific': {
                'django': 'Django ORM 사용 및 raw SQL 최소화',
                'node': 'Parameterized queries with pg-promise 또는 mysql2',
                'php': 'PDO prepared statements 사용'
            }
        },
        'references': [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/89.html'
        ]
    },

    # CSRF (Cross-Site Request Forgery)
    'csrf': {
        'description': 'CSRF는 인증된 사용자가 의도하지 않은 요청을 실행하도록 만드는 공격입니다.',
        'owasp': ['A01:2025'],
        'cwe': ['CWE-352'],
        'remediation': {
            'steps': [
                'CSRF 토큰을 모든 상태 변경 요청에 포함',
                'SameSite 쿠키 속성 설정',
                'Referer/Origin 헤더 검증',
                'Double Submit Cookie 패턴 구현',
                '사용자 재인증 요구 (중요 작업)'
            ],
            'code_examples': {
                'vulnerable': '<form action="/transfer" method="POST">',
                'secure': '<form action="/transfer" method="POST"><input type="hidden" name="csrf_token" value="{{ csrf_token }}">'
            },
            'framework_specific': {
                'django': '{% csrf_token %} 템플릿 태그 사용',
                'express': 'csurf 미들웨어 적용',
                'rails': 'protect_from_forgery with: :exception'
            }
        },
        'references': [
            'https://owasp.org/www-community/attacks/csrf',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/352.html'
        ]
    },

    # Security Headers
    'security_headers': {
        'description': '보안 헤더는 브라우저가 웹 애플리케이션을 보호하는 데 도움이 되는 HTTP 응답 헤더입니다.',
        'owasp': ['A05:2025'],
        'cwe': ['CWE-693'],
        'remediation': {
            'steps': [
                'Content-Security-Policy 헤더 설정',
                'X-Frame-Options 헤더로 클릭재킹 방지',
                'X-Content-Type-Options: nosniff 설정',
                'Strict-Transport-Security 헤더 설정 (HTTPS)',
                'Referrer-Policy 헤더 설정',
                'Permissions-Policy 헤더로 기능 제한'
            ],
            'code_examples': {
                'nginx': 'add_header X-Frame-Options "SAMEORIGIN";',
                'apache': 'Header always set X-Frame-Options "SAMEORIGIN"',
                'django': "SECURE_BROWSER_XSS_FILTER = True"
            },
            'framework_specific': {
                'express': 'helmet 미들웨어 사용',
                'django': 'django-security 패키지 활용',
                'asp.net': 'NWebsec 라이브러리 사용'
            }
        },
        'references': [
            'https://owasp.org/www-project-secure-headers/',
            'https://securityheaders.com/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers'
        ]
    },

    # SSL/TLS Configuration
    'ssl_tls': {
        'description': 'SSL/TLS는 클라이언트와 서버 간의 안전한 통신을 보장하는 암호화 프로토콜입니다.',
        'owasp': ['A02:2025'],
        'cwe': ['CWE-311'],
        'remediation': {
            'steps': [
                'TLS 1.2 이상 버전만 사용',
                '강력한 암호화 스위트 설정',
                'HSTS(HTTP Strict Transport Security) 활성화',
                '인증서 체인 올바르게 구성',
                'Perfect Forward Secrecy 지원',
                'CAA(Certificate Authority Authorization) 레코드 설정'
            ],
            'code_examples': {
                'nginx': 'ssl_protocols TLSv1.2 TLSv1.3;',
                'apache': 'SSLProtocol -all +TLSv1.2 +TLSv1.3'
            },
            'framework_specific': {
                'nginx': 'Mozilla SSL Configuration Generator 사용',
                'apache': 'mod_ssl 모듈 최신 버전 유지',
                'cloudflare': 'Full (Strict) SSL 모드 설정'
            }
        },
        'references': [
            'https://ssl-config.mozilla.org/',
            'https://www.ssllabs.com/ssltest/',
            'https://cwe.mitre.org/data/definitions/311.html'
        ]
    },

    # SSRF (Server-Side Request Forgery)
    'ssrf': {
        'description': 'SSRF는 서버가 공격자가 지정한 내부 리소스에 접근하도록 만드는 취약점입니다.',
        'owasp': ['A06:2025'],
        'cwe': ['CWE-918'],
        'remediation': {
            'steps': [
                'URL 입력값 화이트리스트 검증',
                '내부 IP 범위(127.0.0.1, 192.168.x.x) 차단',
                'DNS Rebinding 공격 방어',
                'HTTP 리다이렉트 따라가지 않기',
                '네트워크 수준에서 아웃바운드 트래픽 제한',
                'URL 파서 일관성 검증'
            ],
            'code_examples': {
                'vulnerable': 'fetch(user_provided_url)',
                'secure': 'if (isWhitelisted(url)) { fetch(url) }'
            },
            'framework_specific': {
                'python': 'requests 라이브러리의 allow_redirects=False',
                'node': 'ssrf-req-filter 패키지 사용',
                'java': 'Apache HttpClient의 커스텀 검증 구현'
            }
        },
        'references': [
            'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/918.html'
        ]
    },

    # XXE (XML External Entity)
    'xxe': {
        'description': 'XXE는 XML 파서가 외부 엔티티를 처리할 때 발생하는 취약점으로, 파일 읽기나 SSRF 공격이 가능합니다.',
        'owasp': ['A04:2025'],
        'cwe': ['CWE-611'],
        'remediation': {
            'steps': [
                'XML 외부 엔티티 처리 비활성화',
                'DTD(Document Type Definition) 처리 비활성화',
                'JSON 등 대체 형식 사용 고려',
                'XML 파서 최신 버전 유지',
                'XML 입력 크기 제한'
            ],
            'code_examples': {
                'java': 'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
                'python': 'defusedxml 라이브러리 사용',
                'php': 'libxml_disable_entity_loader(true);'
            },
            'framework_specific': {
                'java': 'OWASP Java Encoder 사용',
                'python': 'defusedxml 패키지 사용',
                '.net': 'XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit'
            }
        },
        'references': [
            'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
            'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/611.html'
        ]
    },

    # Command Injection
    'command_injection': {
        'description': '명령어 주입은 공격자가 시스템 명령을 실행할 수 있게 하는 치명적인 취약점입니다.',
        'owasp': ['A03:2025'],
        'cwe': ['CWE-77', 'CWE-78'],
        'remediation': {
            'steps': [
                '시스템 명령 실행 최소화',
                '매개변수화된 API 사용',
                '입력값 엄격한 검증 (화이트리스트)',
                '특수 문자 이스케이프',
                '최소 권한으로 프로세스 실행',
                '샌드박스 환경 활용'
            ],
            'code_examples': {
                'vulnerable': 'os.system(f"ping {ip_address}")',
                'secure': 'subprocess.run(["ping", ip_address], shell=False)'
            },
            'framework_specific': {
                'python': 'subprocess 모듈의 shell=False 사용',
                'node': 'child_process.spawn() 사용 (exec 대신)',
                'php': 'escapeshellarg() 및 escapeshellcmd() 사용'
            }
        },
        'references': [
            'https://owasp.org/www-community/attacks/Command_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/78.html'
        ]
    },

    # JWT Security
    'jwt_security': {
        'description': 'JWT(JSON Web Token)는 인증 정보를 안전하게 전달하는 토큰이지만, 잘못 구현하면 보안 취약점이 발생할 수 있습니다.',
        'owasp': ['A07:2025'],
        'cwe': ['CWE-347'],
        'remediation': {
            'steps': [
                '강력한 비밀 키 사용 (256비트 이상)',
                'alg:none 허용 금지',
                'RSA/HMAC 알고리즘 혼동 방지',
                '토큰 만료 시간 설정',
                '민감한 정보 페이로드에 포함 금지',
                'JWK(JSON Web Key) 헤더 검증'
            ],
            'code_examples': {
                'vulnerable': 'jwt.decode(token, verify=False)',
                'secure': 'jwt.decode(token, secret_key, algorithms=["HS256"])'
            },
            'framework_specific': {
                'python': 'PyJWT 라이브러리 최신 버전 사용',
                'node': 'jsonwebtoken 라이브러리 사용',
                'java': 'java-jwt 또는 jjwt 라이브러리'
            }
        },
        'references': [
            'https://jwt.io/introduction/',
            'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/347.html'
        ]
    },

    # File Upload
    'file_upload': {
        'description': '파일 업로드 취약점은 악성 파일을 서버에 업로드하여 원격 코드 실행이 가능한 취약점입니다.',
        'owasp': ['A04:2025'],
        'cwe': ['CWE-434'],
        'remediation': {
            'steps': [
                '파일 확장자 화이트리스트 검증',
                'MIME 타입 및 매직 넘버 검증',
                '업로드 디렉토리 실행 권한 제거',
                '파일명 재생성 (UUID 사용)',
                '파일 크기 제한',
                '별도의 스토리지 서버 사용',
                '안티바이러스 스캔'
            ],
            'code_examples': {
                'vulnerable': 'file.save(uploaded_file.filename)',
                'secure': 'file.save(f"{uuid.uuid4()}.{allowed_extension}")'
            },
            'framework_specific': {
                'django': 'django-cleanup 및 pillow 라이브러리',
                'express': 'multer 미들웨어 설정',
                'php': 'move_uploaded_file() 사용'
            }
        },
        'references': [
            'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
            'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/434.html'
        ]
    },

    # Path Traversal
    'path_traversal': {
        'description': '경로 순회 공격은 ../와 같은 문자를 사용하여 제한된 디렉토리 외부의 파일에 접근하는 취약점입니다.',
        'owasp': ['A01:2025'],
        'cwe': ['CWE-22'],
        'remediation': {
            'steps': [
                '사용자 입력에서 경로 구분자 제거',
                '절대 경로 사용 및 검증',
                'chroot jail 또는 샌드박스 사용',
                '파일 접근 화이트리스트 구현',
                '심볼릭 링크 따라가지 않기'
            ],
            'code_examples': {
                'vulnerable': 'open(f"/files/{user_input}")',
                'secure': 'open(os.path.join("/files", os.path.basename(user_input)))'
            },
            'framework_specific': {
                'python': 'pathlib.Path.resolve() 사용',
                'node': 'path.normalize() 및 path.join() 사용',
                'java': 'File.getCanonicalPath() 검증'
            }
        },
        'references': [
            'https://owasp.org/www-community/attacks/Path_Traversal',
            'https://cwe.mitre.org/data/definitions/22.html'
        ]
    },

    # REST API Security
    'rest_api_security': {
        'description': 'REST API 보안은 인증, 권한 부여, 속도 제한 등 다양한 보안 측면을 포함합니다.',
        'owasp': ['A01:2025', 'A07:2025'],
        'cwe': ['CWE-284'],
        'remediation': {
            'steps': [
                'OAuth 2.0 또는 JWT 기반 인증',
                'API 키 관리 및 회전',
                'Rate Limiting 구현',
                'API 버저닝',
                'CORS 정책 올바르게 설정',
                'GraphQL의 경우 쿼리 깊이 제한'
            ],
            'code_examples': {
                'headers': {
                    'Authorization': 'Bearer <token>',
                    'X-API-Key': '<api-key>',
                    'Content-Type': 'application/json'
                }
            },
            'framework_specific': {
                'django': 'Django REST Framework 사용',
                'express': 'express-rate-limit 미들웨어',
                'fastapi': 'FastAPI의 내장 보안 기능 활용'
            }
        },
        'references': [
            'https://owasp.org/www-project-api-security/',
            'https://swagger.io/specification/',
            'https://www.rfc-editor.org/rfc/rfc6749'
        ]
    },

    # Session Security
    'session_security': {
        'description': '세션 관리 취약점은 세션 하이재킹, 세션 고정 등의 공격을 가능하게 합니다.',
        'owasp': ['A07:2025'],
        'cwe': ['CWE-384'],
        'remediation': {
            'steps': [
                '로그인 후 세션 ID 재생성',
                'HTTPS에서만 세션 쿠키 전송 (Secure 플래그)',
                'HttpOnly 플래그로 XSS 방지',
                'SameSite 속성 설정',
                '세션 타임아웃 구현',
                '동시 세션 제한'
            ],
            'code_examples': {
                'cookie': 'Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict'
            },
            'framework_specific': {
                'django': 'SESSION_COOKIE_SECURE = True',
                'express': 'express-session 설정',
                'php': 'session_regenerate_id(true)'
            }
        },
        'references': [
            'https://owasp.org/www-community/attacks/Session_fixation',
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/384.html'
        ]
    },

    # 기본 가이드 (매핑되지 않은 스캐너용)
    'default': {
        'description': '보안 검사 결과입니다.',
        'remediation': {
            'steps': [
                '보안 모범 사례를 따라 구현하세요',
                '정기적인 보안 업데이트 적용',
                '보안 테스트 자동화'
            ]
        },
        'references': [
            'https://owasp.org/',
            'https://cwe.mitre.org/'
        ]
    }
}

def get_guide(scanner_id):
    """
    스캐너 ID에 해당하는 가이드 정보 반환

    Args:
        scanner_id: 스캐너 식별자

    Returns:
        dict: 가이드 정보
    """
    return SCANNER_GUIDES.get(scanner_id, SCANNER_GUIDES['default'])