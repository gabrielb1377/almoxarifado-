"""Check cloud deployment safeguards without touching production data."""
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import db
from main import app


def test_online_requires_attached_volume(tmp_path, monkeypatch):
    monkeypatch.setattr(db, 'DB_PATH', tmp_path / 'almox.db')
    monkeypatch.setenv('ALMOX_REQUIRE_VOLUME', '1')
    monkeypatch.delenv('RAILWAY_VOLUME_MOUNT_PATH', raising=False)
    with pytest.raises(RuntimeError, match='Volume persistente'):
        db.initialize()
    assert not (tmp_path / 'almox.db').exists()


def test_online_requires_admin_password(tmp_path, monkeypatch):
    monkeypatch.setattr(db, 'DB_PATH', tmp_path / 'almox.db')
    monkeypatch.setenv('ALMOX_REQUIRE_VOLUME', '1')
    monkeypatch.setenv('RAILWAY_VOLUME_MOUNT_PATH', str(tmp_path))
    monkeypatch.setenv('ALMOX_ADMIN_EMAIL', 'admin@example.com')
    monkeypatch.delenv('ALMOX_ADMIN_PASSWORD', raising=False)
    with pytest.raises(RuntimeError, match='ALMOX_ADMIN_PASSWORD'):
        db.initialize()


def test_online_bootstrap_and_cookie_security(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(db, 'DB_PATH', tmp_path / 'almox.db')
    monkeypatch.setenv('ALMOX_REQUIRE_VOLUME', '1')
    monkeypatch.setenv('RAILWAY_VOLUME_MOUNT_PATH', str(tmp_path))
    monkeypatch.setenv('ALMOX_ADMIN_PASSWORD', 'SuperUniqueExamplePassword-1234')
    monkeypatch.setenv('ALMOX_ADMIN_EMAIL', 'admin@example.com')
    with TestClient(app) as client:
        output = capsys.readouterr().out
        assert 'SuperUniqueExamplePassword-1234' not in output
        assert 'admin@example.com' in output
        # Base URL is HTTP in tests, yet public hosted mode must mark cookies secure.
        response = client.post('/api/auth/login', json={
            'email': 'admin@example.com', 'password': 'SuperUniqueExamplePassword-1234'
        })
        assert response.status_code == 200
        assert 'Secure' in response.headers.get('set-cookie', '')
        assert response.headers['x-content-type-options'] == 'nosniff'
        assert response.headers['cache-control'] == 'no-store'
        assert (tmp_path / '.csrf_key').exists()
        assert client.get('/api/health').json() == {'status': 'ok'}
