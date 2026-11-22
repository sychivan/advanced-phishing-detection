"""Private workspace settings for the local PhishGuard backend."""

import argparse
from getpass import getpass, GetPassWarning
import json
import os
from pathlib import Path
import secrets
import tempfile
import warnings


CONFIG_PATH = Path(__file__).resolve().parents[1] / ".env.phishguard.json"
GMAIL_REDIRECT_URI = "http://127.0.0.1:5000/gmail/callback"
GOOGLE_KEYS = ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET")
SETTINGS = {
    *GOOGLE_KEYS, "GOOGLE_REDIRECT_URI", "PHISHGUARD_SESSION_SECRET",
    "DEMO_EMAIL", "DEMO_PASSWORD", "ADMIN_EMAIL", "AI_MODEL_URL",
    "PHISHGUARD_DB_PATH", "PHISHGUARD_CORS_ORIGINS",
}


def read_settings(path=CONFIG_PATH):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (ValueError, OSError):
        raise ValueError("Local PhishGuard configuration is unreadable or invalid JSON.") from None
    if (not isinstance(data, dict) or set(data) - SETTINGS
            or not all(isinstance(value, str) and "\0" not in value for value in data.values())):
        raise ValueError("Local PhishGuard configuration must contain supported setting names and string values.")
    return data


def load_local_config(path=CONFIG_PATH):
    for name, value in read_settings(path).items():
        os.environ.setdefault(name, value)


def save_settings(data, path=CONFIG_PATH):
    # Replace the file only after the complete new configuration is on disk.
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                     prefix=".env.phishguard-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            stream.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def google_export(path):
    try:
        client = json.loads(path.read_text(encoding="utf-8"))["web"]
        redirects = client["redirect_uris"]
        if not isinstance(redirects, list) or GMAIL_REDIRECT_URI not in redirects:
            raise ValueError
        values = {name: client[field] for name, field in zip(GOOGLE_KEYS, ("client_id", "client_secret"))}
        if not all(isinstance(value, str) and value.strip() and "\0" not in value for value in values.values()):
            raise ValueError
    except (KeyError, TypeError, ValueError, OSError):
        raise ValueError("Use a Google Web application export listing the exact local Gmail callback.") from None
    return values


def existing_settings(path):
    settings = read_settings(path)
    settings.update({name: os.environ[name] for name in SETTINGS if os.environ.get(name)})
    return settings


def fill_missing(settings, names, prompt):
    for name in names:
        if not settings.get(name, "").strip():
            with warnings.catch_warnings():
                warnings.simplefilter("error", GetPassWarning)
                value = prompt(f"{name} (hidden): ").strip()
            if not value or "\0" in value:
                raise ValueError(f"A nonempty {name} is required.")
            settings[name] = value


def provision_demo(path=CONFIG_PATH, *, prompt=getpass):
    settings = existing_settings(path)
    fill_missing(settings, ("DEMO_EMAIL", "DEMO_PASSWORD"), prompt)
    settings.setdefault("AI_MODEL_URL", "http://127.0.0.1:5001/predict")
    save_settings(settings, path)


def provision_gmail(path=CONFIG_PATH, *, export=None, prompt=getpass):
    settings = existing_settings(path)
    if export is not None:
        incoming = google_export(export)
        if any(settings.get(name) and settings[name] != incoming[name] for name in GOOGLE_KEYS):
            raise ValueError("The OAuth export does not match existing settings. Existing settings were left in place.")
        settings.update(incoming)
    fill_missing(settings, GOOGLE_KEYS, prompt)
    settings["GOOGLE_REDIRECT_URI"] = settings.get("GOOGLE_REDIRECT_URI") or GMAIL_REDIRECT_URI
    if settings["GOOGLE_REDIRECT_URI"] != GMAIL_REDIRECT_URI:
        raise ValueError("GOOGLE_REDIRECT_URI must match the exact local Gmail callback for this demo.")
    if not settings.get("PHISHGUARD_SESSION_SECRET"):
        settings["PHISHGUARD_SESSION_SECRET"] = secrets.token_urlsafe(48)
    save_settings(settings, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("setup-demo", "setup-gmail"))
    parser.add_argument("--google-export", type=Path, help="Existing Google Web application JSON export")
    args = parser.parse_args()
    try:
        if args.command == "setup-demo":
            if args.google_export is not None:
                parser.error("--google-export applies to setup-gmail")
            provision_demo()
        else:
            provision_gmail(export=args.google_export)
    except (ValueError, OSError, EOFError, GetPassWarning) as error:
        message = str(error) if isinstance(error, ValueError) else "Could not securely read or save the settings."
        parser.exit(1, message + "\n")
    print("Local settings saved. Restart Flask to apply them.")


if __name__ == "__main__":
    main()
