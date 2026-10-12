import os
import json
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import venv

import pytest

from app import __version__, main
from portfw.host import load_settings
from portfw.policy import validate_rules


ROOT = Path(__file__).resolve().parents[1]


def test_install_templates_match_both_roles_and_sample_rules():
    host = load_settings(ROOT / "examples/host-helper.conf")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("PVE_PORTFW_")}
    for line in (ROOT / "examples/panel.env").read_text(encoding="utf-8").splitlines():
        tokens = shlex.split(line, comments=True)
        if tokens:
            key, value = tokens[0].split("=", 1)
            environment[key] = value
    # Import the panel in a fresh process: module-level deployment settings must
    # come from the template, without changing settings used by other tests.
    result = subprocess.run([sys.executable, "-c",
        "import json; from app.config import panel_settings; print(json.dumps(panel_settings().to_dict()))"],
        cwd=ROOT, env=environment, capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == host.to_dict()
    assert environment["PVE_PORTFW_HOST_SSH_TARGET"].endswith("@" + host.gateway)
    rules = json.loads((ROOT / "examples/rules.example.json").read_text(encoding="utf-8"))
    assert validate_rules(rules, host) == rules


def test_beta_api_version_and_permission_step_before_service_start():
    assert __version__ == "0.2.0-beta.1"
    assert main.app.openapi()["info"]["version"] == __version__
    script = (ROOT / "scripts/install-panel.sh").read_text(encoding="utf-8")
    assert script.index('"${APP_DIR}/.venv/bin/pip" install') < script.index("\nprepare_runtime_permissions\n")
    assert script.index("\nprepare_runtime_permissions\n") < script.index("systemctl restart")
    assert 'install -d -m 755 -o root -g "${PANEL_USER}" "${APP_DIR}"' in script


@pytest.mark.skipif(sys.platform != "linux" or not shutil.which("unshare"),
                    reason="Requires Linux user namespaces for isolated root/group permission checks")
def test_root_owned_runtime_is_group_readable_not_group_writable(tmp_path):
    probe = subprocess.run(["unshare", "-Ur", "true"], capture_output=True, text=True)
    if probe.returncode:
        pytest.skip("User namespaces unavailable: " + probe.stderr.strip())
    app_dir = tmp_path / "runtime"
    app_dir.mkdir()
    old_umask = os.umask(0o027)
    try:
        for directory in ("app", "portfw"):
            (app_dir / directory).mkdir()
            (app_dir / directory / "module.py").write_text("value = 1\n", encoding="utf-8")
        venv.EnvBuilder(with_pip=False).create(app_dir / ".venv")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE((app_dir / ".venv").stat().st_mode) == 0o750
    target_before = Path(sys.executable).stat()
    source = (ROOT / "scripts/install-panel.sh").read_text(encoding="utf-8")
    body = source.split("\nprepare_runtime_permissions() {\n", 1)[1].split("\n}\n", 1)[0]
    # Exercise only the permission block as namespace root; never run the installer.
    script = f"APP_DIR={shlex.quote(str(app_dir))}\nPANEL_USER=root\n{body.replace('  local paths=', '  paths=', 1)}"
    result = subprocess.run(["unshare", "-Ur", "bash", "-eu", "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    for directory in ("app", "portfw", ".venv", ".venv/bin"):
        info = (app_dir / directory).stat()
        assert stat.S_IMODE(info.st_mode) == 0o750
        assert info.st_uid == os.getuid() and info.st_gid == os.getgid()
    for path in (app_dir / "app/module.py", app_dir / "portfw/module.py", app_dir / ".venv/pyvenv.cfg"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    target_after = Path(sys.executable).stat()
    assert (target_before.st_mode, target_before.st_uid, target_before.st_gid) == (
        target_after.st_mode, target_after.st_uid, target_after.st_gid)
