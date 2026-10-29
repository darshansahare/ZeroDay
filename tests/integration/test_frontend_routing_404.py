"""
Integration Tests for ZeroDay Frontend Routing and Custom 404 Behavior.
Verifies that:
- Known frontend routes return HTTP 200 with HTML SPA bundle.
- Unknown frontend routes return real HTTP 404 with HTML SPA bundle (for client-side custom 404 rendering).
- API routes never return HTML on 404; they strictly return JSON {"detail": "Not Found"}.
"""

import pytest
from fastapi.testclient import TestClient
from main import app


@pytest.fixture
def main_client():
    return TestClient(app)


def test_landing_route_returns_200(main_client):
    """GET / should serve the SPA bundle with HTTP 200."""
    response = main_client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_arena_route_returns_200(main_client):
    """GET /arena should serve the SPA bundle with HTTP 200."""
    response = main_client.get("/arena")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_benchmarks_route_returns_200(main_client):
    """GET /benchmarks should serve the SPA bundle with HTTP 200."""
    response = main_client.get("/benchmarks")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_unknown_frontend_route_returns_real_404_html(main_client):
    """Unknown frontend paths must return real HTTP 404 status while serving the SPA HTML."""
    response = main_client.get("/unknown-route")
    assert response.status_code == 404
    assert "text/html" in response.headers.get("content-type", "")
    assert "<html" in response.text.lower()


def test_deep_unknown_frontend_route_returns_real_404_html(main_client):
    """Nested unknown paths must return real HTTP 404 with HTML SPA bundle."""
    response = main_client.get("/attack-surface/scanner/missing-node")
    assert response.status_code == 404
    assert "text/html" in response.headers.get("content-type", "")


def test_unknown_api_route_returns_404_json_not_html(main_client):
    """Unknown API routes must NEVER return frontend HTML; must return standard 404 JSON."""
    response = main_client.get("/api/nonexistent-endpoint-xyz")
    assert response.status_code == 404
    assert "application/json" in response.headers.get("content-type", "")
    assert response.json()["detail"] == "Not Found"


def test_favicon_ico_served(main_client):
    """GET /favicon.ico should return HTTP 200 with image/x-icon content."""
    response = main_client.get("/favicon.ico")
    assert response.status_code == 200
    assert "image" in response.headers.get("content-type", "")
    assert len(response.content) > 1000


def test_favicon_svg_served(main_client):
    """GET /favicon.svg should return HTTP 200 with image/svg+xml content."""
    response = main_client.get("/favicon.svg")
    assert response.status_code == 200
    assert "image/svg+xml" in response.headers.get("content-type", "")
    assert b"<svg" in response.content


def test_png_favicons_and_icons_served(main_client):
    """PNG icons (32x32, apple-touch, 192, 512) must return HTTP 200 image/png."""
    for path in ["/favicon-32x32.png", "/favicon-16x16.png", "/apple-touch-icon.png", "/icon-192.png", "/icon-512.png"]:
        resp = main_client.get(path)
        assert resp.status_code == 200, f"Failed for {path}"
        assert "image/png" in resp.headers.get("content-type", "")
        assert resp.content.startswith(b"\x89PNG")


def test_site_webmanifest_served(main_client):
    """GET /site.webmanifest must return HTTP 200 with valid manifest JSON."""
    response = main_client.get("/site.webmanifest")
    assert response.status_code == 200
    assert "manifest" in response.headers.get("content-type", "") or "json" in response.headers.get("content-type", "")
    data = response.json()
    assert data["name"] == "ZeroDay - Autonomous Security Platform"
    assert len(data["icons"]) >= 2


def test_og_social_preview_image_served(main_client):
    """GET /og-image.png must return HTTP 200 with valid 1200x630 PNG."""
    from PIL import Image
    import io

    response = main_client.get("/og-image.png")
    assert response.status_code == 200
    assert "image/png" in response.headers.get("content-type", "")
    assert response.content.startswith(b"\x89PNG")
    assert len(response.content) > 10000

    img = Image.open(io.BytesIO(response.content))
    assert img.size == (1200, 630)


def test_seo_metadata_in_homepage_html(main_client):
    """GET / must include baseline static Open Graph, Twitter, and SEO tags."""
    response = main_client.get("/")
    assert response.status_code == 200
    html = response.text

    # Title & description
    assert "<title>ZeroDay</title>" in html
    assert 'name="description"' in html
    assert "Analyze code for security vulnerabilities" in html

    # Open Graph tags
    assert 'property="og:title"' in html
    assert 'ZeroDay' in html
    assert 'property="og:type" content="website"' in html
    assert 'property="og:image"' in html
    assert "/og-image.png" in html
    assert 'property="og:image:width" content="1200"' in html
    assert 'property="og:image:height" content="630"' in html

    # Twitter Card tags
    assert 'name="twitter:card" content="summary_large_image"' in html
    assert 'name="twitter:title"' in html
    assert 'name="twitter:image"' in html



def test_documentation_route_returns_200(main_client):
    """GET /documentation should serve the SPA bundle with HTTP 200."""
    response = main_client.get("/documentation")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_legacy_docs_route_redirects_to_documentation(main_client):
    """GET /docs must redirect (301) to canonical /documentation."""
    response = main_client.get("/docs", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers.get("location") == "/documentation"


def test_hackathon_route_returns_200(main_client):
    """GET /hackathon should serve the SPA bundle with HTTP 200."""
    response = main_client.get("/hackathon")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


def test_robots_txt_served(main_client):
    """GET /robots.txt must return HTTP 200 with text/plain containing bot directives."""
    response = main_client.get("/robots.txt")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    text = response.text
    assert "User-agent: *" in text
    assert "ClaudeBot" in text
    assert "Sitemap:" in text


def test_sitemap_xml_served(main_client):
    """GET /sitemap.xml must return HTTP 200 with XML content."""
    response = main_client.get("/sitemap.xml")
    assert response.status_code == 200
    assert "xml" in response.headers.get("content-type", "")
    text = response.text
    assert "<urlset" in text
    assert "/documentation" in text
    assert "/hackathon" in text


def test_llms_txt_served(main_client):
    """GET /llms.txt must return HTTP 200 with text/plain markdown summary."""
    response = main_client.get("/llms.txt")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    text = response.text
    assert "# ZeroDay" in text
    assert "NVIDIA" in text
    assert "Nebius" in text


def test_llms_full_txt_served(main_client):
    """GET /llms-full.txt must return HTTP 200 with comprehensive markdown knowledge."""
    response = main_client.get("/llms-full.txt")
    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")
    text = response.text
    assert "Complete Technical Specification" in text
    assert "CWE-" in text


def test_documentation_subpages_served(main_client):
    """All 6 individual documentation topic pages must return HTTP 200 with SPA HTML."""
    topics = [
        "what-is-zeroday",
        "how-it-works",
        "installing-zeroday",
        "supported-cwes",
        "evaluation-and-benchmarks",
        "security-and-limits",
    ]
    for topic in topics:
        resp = main_client.get(f"/documentation/{topic}")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")


def test_legacy_docs_subpage_redirects(main_client):
    """Legacy /docs/{topic} must issue 301 redirect to /documentation/{topic}."""
    resp = main_client.get("/docs/what-is-zeroday", follow_redirects=False)
    assert resp.status_code == 301
    assert resp.headers.get("location") == "/documentation/what-is-zeroday"
