# tests/test_app.py

import pytest
from app.py import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.secret_key = 'test_secret_key'

    with app.test_client() as client:
        with app.app_context():
            yield client

def test_home_redirects_to_login(client):
    """Unauthenticated user should be redirected to login page."""
    response = client.get('/', follow_redirects=False)
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

def test_login_page_renders(client):
    """Check if login page loads correctly."""
    response = client.get('/login')
    assert response.status_code == 200
    assert b"login" in response.data.lower()

def test_register_page_renders(client):
    """Check if register page loads correctly."""
    response = client.get('/register')
    assert response.status_code == 200
    assert b"register" in response.data.lower()
