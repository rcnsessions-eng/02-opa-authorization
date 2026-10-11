import os
import pathlib
import subprocess
import tempfile


def main() -> None:
    policy_root = pathlib.Path(os.getenv("POLICY_ROOT", "/policy"))
    policy = (policy_root / "rego/authorization.rego").read_text()
    predicate = "input.resource.tenant_id == input.tenant.id"
    if policy.count(predicate) != 1:
        raise RuntimeError("Expected exactly one resource tenant predicate")
    with tempfile.TemporaryDirectory() as temporary:
        destination = pathlib.Path(temporary) / "unsafe.rego"
        destination.write_text(policy.replace(predicate, "true"))
        result = subprocess.run(
            ["opa", "test", str(destination), str(policy_root / "tests"), "-v"],
            text=True,
            capture_output=True,
            check=False,
        )
        if (
            result.returncode == 0
            or "test_tenant_checked_independently_of_owner: FAIL" not in result.stdout
        ):
            raise RuntimeError("Tenant-removal mutation was not caught by the regression test")
    print("Tenant-condition mutation correctly rejected; source policy unchanged")


if __name__ == "__main__":
    main()
