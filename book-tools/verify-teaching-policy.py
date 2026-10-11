#!/usr/bin/env python3
"""Execute the printed Rego examples and require the tenant mutation to fail."""

import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parent
OPA_IMAGE = "openpolicyagent/opa:1.21.1-static@sha256:4675ab04ad1627f74741d2d9c5142698c79e18b7b09f192587d31d6dba20838e"


def code_blocks(path, language="rego"):
	result = subprocess.run(
		["pandoc", "--from=markdown", "--to=json", str(path)],
		capture_output=True, text=True, check=True,
	)
	return [block["c"][1] for block in json.loads(result.stdout)["blocks"]
			if block["t"] == "CodeBlock" and language in block["c"][0][1]]


def opa(directory, *arguments, check=True):
	command = [
		"docker", "run", "--rm", "--network", "none", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--volume", f"{directory}:/policy:ro", OPA_IMAGE, *arguments,
	]
	return subprocess.run(command, capture_output=True, text=True, check=check, timeout=120)


def benchmark(directory, count, validator):
	result = opa(directory, "eval", "--data", "/policy", "--format", "json",
				 "data.learning.authz.owner_input")
	owner = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
	foreign = copy.deepcopy(owner)
	foreign["resource"]["tenant_id"] = "tenant-b"
	records = {"scope": "in-process Rego microbenchmark, not HTTP/MCP capacity",
			   "opa_image": OPA_IMAGE, "repeat_count": count, "results": {}}
	for outcome, fixture in [("allow", owner), ("deny", foreign)]:
		filename = f"benchmark-{outcome}.json"
		(directory / filename).unlink(missing_ok=True)
		(directory.parent / filename).write_text(json.dumps(fixture) + "\n")
		result = opa(directory.parent, "eval", "--data", "/policy/appendix/policy.rego",
					 "--input", f"/policy/{filename}", "--format", "json",
					 "data.learning.authz.decision")
		decision = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
		assert validator(decision)["allow"] is (outcome == "allow")
		result = opa(directory.parent, "bench", "--data", "/policy/appendix/policy.rego",
					 "--input", f"/policy/{filename}", "--count", str(count),
					 "--format", "json", "data.learning.authz.decision")
		records["results"][outcome] = json.loads(result.stdout)
	destination = ROOT / "artifacts/teaching-policy-benchmark.json"
	destination.parent.mkdir(parents=True, exist_ok=True)
	destination.write_text(json.dumps(records, indent=2) + "\n")
	print("PASS: allow/deny microbenchmark; raw results in artifacts/teaching-policy-benchmark.json")


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--benchmark", action="store_true", help="Run separate allow/deny Rego microbenchmarks")
	parser.add_argument("--benchmark-count", type=int, choices=range(1, 6), default=3)
	arguments = parser.parse_args()
	appendix = code_blocks(ROOT / "manuscript/appendix-E-worked-policy.md")
	chapter = code_blocks(ROOT / "manuscript/ch04-opa-and-rego.md")
	assert len(appendix) == 3 and len(chapter) == 2
	namespace = {}
	handler = code_blocks(ROOT / "manuscript/appendix-F-application-enforcement.md", "python")
	assert len(handler) == 1
	exec(compile(handler[0], "appendix-F-example", "exec"), namespace)
	output = ROOT / "dist/teaching-policy"
	shutil.rmtree(output / "tenant-mutation", ignore_errors=True)
	for filename in ["benchmark-allow.json", "benchmark-deny.json"]:
		(output / "appendix" / filename).unlink(missing_ok=True)
	for name, policy in [("appendix", appendix[0]), ("chapter-structured", chapter[1])]:
		directory = output / name
		directory.mkdir(parents=True, exist_ok=True)
		(directory / "policy.rego").write_text(policy + "\n")
		for index, tests in enumerate(appendix[1:], start=1):
			(directory / f"cases{index}_test.rego").write_text(tests + "\n")
		opa(directory, "check", "/policy")
		result = opa(directory, "test", "/policy", "--verbose", "--fail-on-empty")
		print(f"PASS: {name} policy\n{result.stdout.strip()}")
		for fixture, expected in [("owner_input", True), ("negative_inputs[2]", False)]:
			result = opa(directory, "eval", "--data", "/policy", "--format", "json",
						 f"data.learning.authz.decision with input as data.learning.authz.{fixture}")
			decision = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
			assert namespace["validate_decision"](decision)["allow"] is expected
		print("PASS: actual OPA allow/deny responses satisfy the printed Python contract")
	boolean = output / "chapter-boolean"
	boolean.mkdir(parents=True, exist_ok=True)
	(boolean / "policy.rego").write_text(chapter[0] + "\n")
	(boolean / "boolean_test.rego").write_text(
		'package learning.authz\nimport rego.v1\n'
		'fixture := {"principal": {"id": "learner-a", "type": "human", "tenant_id": "tenant-a"}, '
		'"action": "progress.read", "resource": {"type": "learner-progress", '
		'"owner_id": "learner-a", "tenant_id": "tenant-a"}}\n'
		'test_owner if { allow with input as fixture }\n'
		'test_foreign_tenant if {\n'
		'candidate := object.union(fixture, {"resource": {"tenant_id": "tenant-b"}})\n'
		'not allow with input as candidate\n}\n'
	)
	opa(boolean, "check", "/policy")
	result = opa(boolean, "test", "/policy", "--verbose", "--fail-on-empty")
	print(f"PASS: chapter boolean alternative\n{result.stdout.strip()}")
	guard = "  input.principal.tenant_id == input.resource.tenant_id\n"
	assert appendix[0].count(guard) == 1
	with TemporaryDirectory(prefix="policy-mutation-", dir=output) as temporary:
		mutant = Path(temporary)
		(mutant / "policy.rego").write_text(appendix[0].replace(guard, "") + "\n")
		for index, tests in enumerate(appendix[1:], start=1):
			(mutant / f"cases{index}_test.rego").write_text(tests + "\n")
		opa(mutant, "check", "/policy")
		result = opa(mutant, "test", "/policy", "--verbose", "--fail-on-empty", check=False)
		assert result.returncode != 0 and "FAIL" in result.stdout, result.stdout + result.stderr
	print("PASS: syntactically valid tenant-guard mutation fails the negative tests")
	print("Generated examples: dist/teaching-policy; temporary unsafe mutation removed")
	if arguments.benchmark:
		benchmark(output / "appendix", arguments.benchmark_count, namespace["validate_decision"])


if __name__ == "__main__":
	main()