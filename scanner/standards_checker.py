"""
Advanced Web Standards Checker
웹 표준 검사를 위한 고급 함수들
"""
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


def generate_standards_metadata():
    """웹 표준 검사 메타데이터 생성"""
    return [
        {
            'id': 'html_validation',
            'name': 'HTML 유효성 검사',
            'icon': '📄',
            'field': 'html_errors',
            'description': 'HTML 마크업 유효성 검증',
            'weight': 2
        },
        {
            'id': 'css_validation',
            'name': 'CSS 유효성 검사',
            'icon': '🎨',
            'field': 'css_errors',
            'description': 'CSS 스타일시트 유효성 검증',
            'weight': 2
        },
        {
            'id': 'js_validation',
            'name': 'JavaScript 검사',
            'icon': '⚙️',
            'field': 'js_errors',
            'description': 'JavaScript 오류 및 경고 검사',
            'weight': 2
        },
        {
            'id': 'seo_check',
            'name': 'SEO 최적화',
            'icon': '🔍',
            'field': 'seo_issues',
            'description': '검색 엔진 최적화 검사',
            'weight': 1
        },
        {
            'id': 'performance_check',
            'name': '성능 검사',
            'icon': '⚡',
            'field': 'page_performance',
            'description': '페이지 로드 성능 측정',
            'weight': 1
        }
    ]


def check_seo_advanced(soup, url, response):
    """고급 SEO 검사"""
    vulnerabilities = []
    meta_tags = {}
    score = 100

    # 1. Title 태그 검사
    title = soup.find('title')
    if not title or not title.string:
        vulnerabilities.append({'type': 'title', 'severity': 'critical', 'message': 'Title 태그가 없거나 비어있습니다.'})
        score -= 20
    else:
        title_text = title.string.strip()
        meta_tags['title'] = title_text

        if len(title_text) < 10:
            vulnerabilities.append({'type': 'title', 'severity': 'high', 'message': f'Title이 너무 짧습니다 ({len(title_text)}자). 10자 이상 권장.'})
            score -= 10
        elif len(title_text) > 70:
            vulnerabilities.append({'type': 'title', 'severity': 'medium', 'message': f'Title이 너무 깁니다 ({len(title_text)}자). 70자 이하 권장.'})
            score -= 5

    # 2. Meta Description
    meta_desc = soup.find('meta', attrs={'name': 'description'})
    if not meta_desc or not meta_desc.get('content'):
        vulnerabilities.append({'type': 'meta_description', 'severity': 'high', 'message': 'Meta description이 없습니다.'})
        score -= 15
    else:
        desc_text = meta_desc.get('content', '').strip()
        meta_tags['description'] = desc_text

        if len(desc_text) < 50:
            vulnerabilities.append({'type': 'meta_description', 'severity': 'medium', 'message': f'Meta description이 너무 짧습니다 ({len(desc_text)}자). 50~160자 권장.'})
            score -= 5
        elif len(desc_text) > 160:
            vulnerabilities.append({'type': 'meta_description', 'severity': 'low', 'message': f'Meta description이 너무 깁니다 ({len(desc_text)}자). 160자 이하 권장.'})
            score -= 3

    # 3. H1 태그 검사
    h1_tags = soup.find_all('h1')
    if not h1_tags:
        vulnerabilities.append({'type': 'h1', 'severity': 'high', 'message': 'H1 태그가 없습니다.'})
        score -= 10
    elif len(h1_tags) > 1:
        vulnerabilities.append({'type': 'h1', 'severity': 'medium', 'message': f'H1 태그가 {len(h1_tags)}개입니다. 1개 권장.'})
        score -= 5
    else:
        h1_text = h1_tags[0].get_text().strip()
        if len(h1_text) < 10:
            vulnerabilities.append({'type': 'h1', 'severity': 'low', 'message': 'H1 텍스트가 너무 짧습니다.'})
            score -= 3

    # 4. 제목 구조 검사 (H1-H6)
    heading_structure = check_heading_hierarchy(soup)
    if not heading_structure['valid']:
        vulnerabilities.extend(heading_structure['issues'])
        score -= heading_structure['score_penalty']

    # 5. 이미지 Alt 속성
    images = soup.find_all('img')
    images_without_alt = [img for img in images if not img.get('alt')]
    if images_without_alt:
        vulnerabilities.append({
            'type': 'img_alt',
            'severity': 'medium',
            'message': f'{len(images_without_alt)}개의 이미지에 alt 속성이 없습니다.',
            'count': len(images_without_alt),
            'total': len(images)
        })
        score -= min(10, len(images_without_alt) * 2)

    # 6. 언어 속성 (lang)
    html_tag = soup.find('html')
    if not html_tag or not html_tag.get('lang'):
        vulnerabilities.append({'type': 'lang', 'severity': 'medium', 'message': '<html> 태그에 lang 속성이 없습니다.'})
        score -= 5

    # 7. Canonical URL
    canonical = soup.find('link', {'rel': 'canonical'})
    if canonical:
        meta_tags['canonical'] = canonical.get('href')
    else:
        vulnerabilities.append({'type': 'canonical', 'severity': 'low', 'message': 'Canonical URL이 설정되지 않았습니다.'})
        score -= 3

    # 8. Meta Robots
    meta_robots = soup.find('meta', attrs={'name': 'robots'})
    if meta_robots:
        meta_tags['robots'] = meta_robots.get('content')

    # 9. Viewport Meta 태그 (모바일 최적화)
    viewport = soup.find('meta', attrs={'name': 'viewport'})
    if not viewport:
        vulnerabilities.append({'type': 'viewport', 'severity': 'high', 'message': 'Viewport meta 태그가 없습니다. 모바일 최적화 필요.'})
        score -= 10
    else:
        meta_tags['viewport'] = viewport.get('content')

    # 10. Charset 선언
    charset = soup.find('meta', attrs={'charset': True})
    if not charset:
        charset_alt = soup.find('meta', attrs={'http-equiv': 'Content-Type'})
        if not charset_alt:
            vulnerabilities.append({'type': 'charset', 'severity': 'medium', 'message': '문자 인코딩이 명시되지 않았습니다.'})
            score -= 5

    # 11. Open Graph 태그
    og_tags = check_open_graph(soup)
    meta_tags['og'] = og_tags['tags']
    if og_tags['issues']:
        vulnerabilities.extend(og_tags['issues'])
        score -= og_tags['score_penalty']

    # 12. Twitter Card
    twitter_tags = check_twitter_card(soup)
    meta_tags['twitter'] = twitter_tags['tags']
    if twitter_tags['issues']:
        vulnerabilities.extend(twitter_tags['issues'])

    # 13. Favicon
    favicon = soup.find('link', {'rel': 'icon'}) or soup.find('link', {'rel': 'shortcut icon'})
    if not favicon:
        vulnerabilities.append({'type': 'favicon', 'severity': 'low', 'message': 'Favicon이 설정되지 않았습니다.'})
        score -= 2

    # 14. 외부 리소스 (External Resources)
    external_resources = check_external_resources(soup, url)
    if external_resources['issues']:
        vulnerabilities.extend(external_resources['issues'])
        score -= external_resources['score_penalty']

    return {
        'overall_score': max(0, score),
        'vulnerabilities': vulnerabilities,
        'meta_tags': meta_tags
    }

# SEO 스캐너 메타데이터
check_seo_advanced.metadata = {
    'id': 'seo_check',
    'name': 'SEO 최적화',
    'icon': '🔍',
    'description': '검색 엔진 최적화 검사',
    'weight': 1,
    'field': 'seo_issues'
}


def check_heading_hierarchy(soup):
    """제목 계층 구조 검사"""
    issues = []
    score_penalty = 0

    headings = []
    for level in range(1, 7):
        tags = soup.find_all(f'h{level}')
        for tag in tags:
            headings.append({'level': level, 'text': tag.get_text().strip()[:50]})

    if not headings:
        return {'valid': True, 'issues': [], 'score_penalty': 0}

    # H1 없이 H2부터 시작하는지 검사
    if headings and headings[0]['level'] != 1:
        issues.append({
            'type': 'heading_hierarchy',
            'severity': 'medium',
            'message': f'제목이 H{headings[0]["level"]}부터 시작합니다. H1부터 시작해야 합니다.'
        })
        score_penalty += 5

    # 제목 레벨 건너뛰기 검사
    for i in range(len(headings) - 1):
        current_level = headings[i]['level']
        next_level = headings[i + 1]['level']

        if next_level > current_level + 1:
            issues.append({
                'type': 'heading_hierarchy',
                'severity': 'low',
                'message': f'제목 레벨을 건너뜁니다: H{current_level} → H{next_level}. 순차적으로 사용 권장.'
            })
            score_penalty += 2
            break  # 한 번만 경고

    return {
        'valid': len(issues) == 0,
        'issues': issues,
        'score_penalty': min(score_penalty, 10)
    }


def check_open_graph(soup):
    """Open Graph 메타 태그 검사"""
    tags = {}
    issues = []
    score_penalty = 0

    required_og_tags = ['og:title', 'og:type', 'og:url', 'og:image']

    for tag_name in required_og_tags:
        og_tag = soup.find('meta', property=tag_name)
        if og_tag and og_tag.get('content'):
            tags[tag_name] = og_tag.get('content')
        else:
            issues.append({
                'type': 'open_graph',
                'severity': 'low',
                'message': f'Open Graph 태그 {tag_name}이(가) 없습니다. SNS 공유 최적화 권장.'
            })
            score_penalty += 1

    # Optional tags
    optional_tags = ['og:description', 'og:site_name']
    for tag_name in optional_tags:
        og_tag = soup.find('meta', property=tag_name)
        if og_tag and og_tag.get('content'):
            tags[tag_name] = og_tag.get('content')

    return {
        'tags': tags,
        'issues': issues,
        'score_penalty': min(score_penalty, 5)
    }


def check_twitter_card(soup):
    """Twitter Card 메타 태그 검사"""
    tags = {}
    issues = []

    twitter_tags = ['twitter:card', 'twitter:title', 'twitter:description', 'twitter:image']

    for tag_name in twitter_tags:
        twitter_tag = soup.find('meta', attrs={'name': tag_name})
        if twitter_tag and twitter_tag.get('content'):
            tags[tag_name] = twitter_tag.get('content')

    # Twitter Card가 전혀 없으면 경고
    if not tags:
        issues.append({
            'type': 'twitter_card',
            'severity': 'low',
            'message': 'Twitter Card 태그가 없습니다. SNS 공유 최적화 권장.'
        })

    return {
        'tags': tags,
        'issues': issues
    }


def check_external_resources(soup, base_url):
    """외부 리소스 검사"""
    issues = []
    score_penalty = 0

    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc

    # CSS 파일
    css_links = soup.find_all('link', {'rel': 'stylesheet'})
    external_css = 0
    for link in css_links:
        href = link.get('href')
        if href and '://' in href:
            parsed = urlparse(href)
            if parsed.netloc != base_domain:
                external_css += 1

    # JavaScript 파일
    script_tags = soup.find_all('script', {'src': True})
    external_js = 0
    for script in script_tags:
        src = script.get('src')
        if src and '://' in src:
            parsed = urlparse(src)
            if parsed.netloc != base_domain:
                external_js += 1

    total_external = external_css + external_js

    if total_external > 10:
        issues.append({
            'type': 'external_resources',
            'severity': 'low',
            'message': f'외부 리소스가 {total_external}개 있습니다. (CSS: {external_css}, JS: {external_js}). 성능 저하 가능성.'
        })
        score_penalty = min(5, total_external // 3)

    return {
        'issues': issues,
        'score_penalty': score_penalty
    }


def check_html_structure(soup, html_text):
    """HTML 구조 검증"""
    vulnerabilities = []
    score = 100

    # 1. DOCTYPE 선언
    if not html_text.strip().lower().startswith('<!doctype'):
        vulnerabilities.append({
            'type': 'doctype',
            'severity': 'high',
            'message': 'DOCTYPE 선언이 없습니다.',
            'line': 1
        })
        score -= 10

    # 2. <html> 태그
    html_tag = soup.find('html')
    if not html_tag:
        vulnerabilities.append({
            'type': 'html_tag',
            'severity': 'critical',
            'message': '<html> 태그가 없습니다.',
            'line': None
        })
        score -= 15

    # 3. <head> 태그
    head_tag = soup.find('head')
    if not head_tag:
        vulnerabilities.append({
            'type': 'head_tag',
            'severity': 'high',
            'message': '<head> 태그가 없습니다.',
            'line': None
        })
        score -= 10

    # 4. <body> 태그
    body_tag = soup.find('body')
    if not body_tag:
        vulnerabilities.append({
            'type': 'body_tag',
            'severity': 'high',
            'message': '<body> 태그가 없습니다.',
            'line': None
        })
        score -= 10

    # 5. 중복 ID 검사
    duplicate_ids = check_duplicate_ids(soup)
    if duplicate_ids:
        for dup_id in duplicate_ids:
            vulnerabilities.append({
                'type': 'duplicate_id',
                'severity': 'medium',
                'message': f'ID "{dup_id}"가 중복 사용되었습니다.',
                'line': None
            })
            score -= 5

    # 6. 폼 검증
    form_issues = check_forms(soup)
    for issue in form_issues:
        issue['severity'] = 'low'
        vulnerabilities.append(issue)
        score -= 2

    # 7. 깨진 링크 (간단한 검사)
    broken_links = check_broken_links_simple(soup)
    for link in broken_links:
        link['severity'] = 'low'
        vulnerabilities.append(link)
        score -= 1

    return {
        'overall_score': max(0, score),
        'vulnerabilities': vulnerabilities
    }

# HTML 구조 검증 메타데이터
check_html_structure.metadata = {
    'id': 'html_validation',
    'name': 'HTML 유효성 검사',
    'icon': '📄',
    'field': 'html_errors',
    'description': 'HTML 마크업 유효성 검증',
    'weight': 2
}


def check_duplicate_ids(soup):
    """중복 ID 검사"""
    ids = {}
    duplicates = set()

    for tag in soup.find_all(id=True):
        tag_id = tag.get('id')
        if tag_id in ids:
            duplicates.add(tag_id)
        else:
            ids[tag_id] = True

    return list(duplicates)


def check_forms(soup):
    """폼 검증"""
    warnings = []

    forms = soup.find_all('form')
    for idx, form in enumerate(forms):
        # action 속성 검사
        if not form.get('action'):
            warnings.append({
                'type': 'form',
                'message': f'폼 #{idx+1}에 action 속성이 없습니다.',
                'line': None
            })

        # method 속성
        method = form.get('method', 'get').lower()
        if method not in ['get', 'post']:
            warnings.append({
                'type': 'form',
                'message': f'폼 #{idx+1}의 method가 올바르지 않습니다: {method}',
                'line': None
            })

    return warnings


def check_broken_links_simple(soup):
    """깨진 링크 간단 검사"""
    warnings = []

    links = soup.find_all('a', href=True)
    for link in links:
        href = link.get('href')

        # 빈 링크
        if not href or href == '#':
            warnings.append({
                'type': 'link',
                'message': f'빈 링크가 있습니다: {link.get_text()[:30]}',
                'line': None
            })

    return warnings[:5]  # 최대 5개만


def check_css_resources(soup, base_url):
    """CSS 리소스 검사"""
    vulnerabilities = []
    score = 100

    css_links = soup.find_all('link', {'rel': 'stylesheet'})

    if len(css_links) > 10:
        vulnerabilities.append({
            'type': 'css_count',
            'severity': 'low',
            'message': f'CSS 파일이 {len(css_links)}개입니다. 병합 권장 (성능 최적화).'
        })
        score -= 5

    # 인라인 스타일 검사
    inline_styles = soup.find_all(style=True)
    if len(inline_styles) > 20:
        vulnerabilities.append({
            'type': 'inline_styles',
            'severity': 'low',
            'message': f'인라인 스타일이 {len(inline_styles)}개 있습니다. CSS 파일 사용 권장.'
        })
        score -= 5

    return {
        'overall_score': max(0, score),
        'vulnerabilities': vulnerabilities
    }

# CSS 분석 메타데이터
check_css_resources.metadata = {
    'id': 'css_validation',
    'name': 'CSS 유효성 검사',
    'icon': '🎨',
    'field': 'css_errors',
    'description': 'CSS 스타일시트 유효성 검증',
    'weight': 2
}


def check_javascript(soup, base_url):
    """JavaScript 검사"""
    vulnerabilities = []
    score = 100

    script_tags = soup.find_all('script')

    # 인라인 스크립트 검사
    inline_scripts = [s for s in script_tags if not s.get('src') and s.string]

    if len(inline_scripts) > 10:
        vulnerabilities.append({
            'type': 'inline_scripts',
            'message': f'인라인 스크립트가 {len(inline_scripts)}개 있습니다. 외부 파일 사용 권장.',
            'severity': 'low'
        })
        score -= 5

    # console.log 검사 (프로덕션에서는 제거해야 함)
    for script in inline_scripts:
        if script.string and 'console.log' in script.string:
            vulnerabilities.append({
                'type': 'console_log',
                'severity': 'low',
                'message': '인라인 스크립트에 console.log가 있습니다. 프로덕션에서 제거 권장.'
            })
            score -= 3
            break

    # 외부 스크립트
    external_scripts = [s for s in script_tags if s.get('src')]

    if len(external_scripts) > 15:
        vulnerabilities.append({
            'type': 'script_count',
            'message': f'외부 JavaScript 파일이 {len(external_scripts)}개입니다. 병합 권장.',
            'severity': 'low'
        })
        score -= 5

    return {
        'overall_score': max(0, score),
        'vulnerabilities': vulnerabilities
    }

# JavaScript 검사 메타데이터
check_javascript.metadata = {
    'id': 'js_validation',
    'name': 'JavaScript 검사',
    'icon': '⚙️',
    'field': 'js_errors',
    'description': 'JavaScript 오류 및 경고 검사',
    'weight': 2
}


def calculate_standards_score_advanced(standards_result, seo_data, html_validation, css_data, js_data):
    """웹 표준 점수 계산 (고급 버전)"""
    # 각 검사의 overall_score를 가중치로 평균 계산
    scores = [
        (seo_data.get('overall_score', 100), 0.3),  # SEO 30%
        (html_validation.get('overall_score', 100), 0.3),  # HTML 30%
        (css_data.get('overall_score', 100), 0.2),  # CSS 20%
        (js_data.get('overall_score', 100), 0.2)  # JavaScript 20%
    ]

    weighted_score = sum(score * weight for score, weight in scores)

    return max(0, min(100, int(weighted_score)))
