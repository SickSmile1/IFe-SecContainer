import os
import urllib.parse
import urllib.request

BASE_URL = os.environ.get("ZAP_TARGET_URL", "http://host.docker.internal:8000")
OPENAPI_URL = os.environ.get("ZAP_OPENAPI_URL", f"{BASE_URL}/openapi.json")
USERNAME = os.environ.get("ZAP_USERNAME", "")
PASSWORD = os.environ.get("ZAP_PASSWORD", "")


def zap_started(zap, target):
    _import_openapi(zap)
    if USERNAME and PASSWORD:
        _setup_auth(zap)
    else:
        print("[zap-hook] ZAP_USERNAME/ZAP_PASSWORD not set — skipping auth setup")
        print("[zap-hook] Set them via docker env to enable authenticated scanning")


def _import_openapi(zap):
    try:
        print(f"[zap-hook] Downloading OpenAPI spec from {OPENAPI_URL} ...")
        req = urllib.request.Request(OPENAPI_URL, headers={"User-Agent": "ZAP"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            spec = resp.read().decode()
        path = "/tmp/openapi.json"
        with open(path, "w") as f:
            f.write(spec)
        zap.openapi.import_file(path)
        print("[zap-hook] OpenAPI spec imported successfully")
    except Exception as e:
        print(f"[zap-hook] Failed to import OpenAPI spec: {e}")


def _setup_auth(zap):
    context_id = zap.context.new_context("playground")

    login_url = f"{BASE_URL}/user/signin"
    login_data = "username={%username%}&password={%password%}"
    method_config = (
        f"loginUrl={urllib.parse.quote(login_url, safe='')}"
        f"&loginRequestData={urllib.parse.quote(login_data, safe='')}"
    )
    zap.authentication.set_authentication_method(
        context_id,
        "formBasedAuthentication",
        method_config,
    )
    print(f"[zap-hook] Auth method configured: formBasedAuthentication → {login_url}")

    user_id = zap.users.new_user(context_id, "zap-user")
    zap.users.set_authentication_credentials(
        context_id,
        user_id,
        {"username": USERNAME, "password": PASSWORD},
    )
    zap.users.set_user_enabled(context_id, user_id, True)

    zap.forcedUser.set_forced_user(context_id, user_id)
    zap.forcedUser.set_forced_user_mode_enabled(True)

    print(f"[zap-hook] Auth configured for {USERNAME} (context={context_id}, user={user_id})")
