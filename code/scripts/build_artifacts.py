import json
import os
import pathlib
import subprocess

from app.authz.contracts import AuthorizationInput


def main() -> None:
    destination = pathlib.Path("artifacts")
    destination.mkdir(exist_ok=True)
    bundle = destination / "learning-policy-v1.0.0.tar.gz"
    policy_root = pathlib.Path(os.getenv("POLICY_ROOT", "/policy"))
    subprocess.run(
        ["opa", "build", "--bundle", str(policy_root / "rego"), "--output", str(bundle)],
        check=True,
    )
    schema = destination / "input-v1.json"
    schema.write_text(json.dumps(AuthorizationInput.model_json_schema(), indent=2) + "\n")
    print("Generated versioned policy bundle and schema; neither artifact is signed")


if __name__ == "__main__":
    main()
