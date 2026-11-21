import random
import string
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

AL = string.ascii_letters + string.digits
_r = random.Random(123)


def rnd(n, alphabet=AL):
    return "".join(_r.choice(alphabet) for _ in range(n))


@pytest.fixture
def fake():
    """Runtime-generated fake secrets (never stored in the repo as literals)."""
    return {
        "gh": "ghp_" + rnd(36), "aws": "AKIA" + rnd(16, string.ascii_uppercase + string.digits),
        "pw": rnd(20), "stripe": "sk_" + "live_" + rnd(24), "email": "asha.nair7@quartzmail.net",
    }


@pytest.fixture
def client(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "TMP_DIR", tmp_path / "tmp")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(config, "INSTANCE_DIR", tmp_path)
    (tmp_path / "tmp").mkdir()
    import app as appmod
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()
