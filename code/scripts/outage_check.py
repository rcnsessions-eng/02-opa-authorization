import json
import os
import subprocess
import urllib.error
import urllib.request


def main() -> None:
    base = os.getenv("LEARNING_BASE_URL", "http://127.0.0.1:8221")
    credential = os.getenv("LEARNING_SMOKE_CREDENTIAL", "demo-learner-red")
    subprocess.run(["docker", "compose", "stop", "opa"], check=True)
    try:
        request = urllib.request.Request(
            base + "/v1/learners/learner-red-1/progress",
            headers={"Authorization": "Bearer " + credential, "X-Request-ID": "opa-outage"},
        )
        try:
            response = urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exception:
            response = exception
        with response:
            payload = json.load(response)
            if response.status != 503 or payload["error"]["code"] != "policy_unavailable":
                raise RuntimeError("Policy outage did not fail closed")
            if "completion_percent" in json.dumps(payload):
                raise RuntimeError("Protected fields escaped during policy outage")
    finally:
        subprocess.run(["docker", "compose", "up", "-d", "--wait", "api", "opa"], check=True)
    print("Live OPA outage denied protected data; scoped services restored and healthy")


if __name__ == "__main__":
    main()
