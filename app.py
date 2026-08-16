import re

from flask import Flask, jsonify, request

app = Flask(__name__)


def is_full_sha(value):
    """Check for exactly 40 lowercase hexadecimal characters."""
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def evaluate_release_gate(data):
    violations = []

    workflow = data.get("workflow") or {}
    image = data.get("image") or {}
    permissions = workflow.get("permissions") or {}

    # ---------------------------------------------------------
    # 1. PERMISSIONS
    # ---------------------------------------------------------

    expected_permissions = {"contents": "read", "packages": "write", "id-token": "none"}

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. PULL REQUEST TRIGGER
    # ---------------------------------------------------------

    if data.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # ---------------------------------------------------------
    # 3. TESTS / MATRIX / FAIL-FAST
    # ---------------------------------------------------------
    # These are release-gate requirements, so check them for
    # both pull_request and push releases.

    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 4. ACTION PINNING
    # ---------------------------------------------------------

    actions = workflow.get("actions") or []

    if not isinstance(actions, list):
        actions = []

    for action in actions:
        if not isinstance(action, dict):
            violations.append("MUTABLE_ACTION")
            break

        owner = action.get("owner")
        ref = action.get("ref")

        # Actions owned by "actions" may use version tags.
        if owner == "actions":
            continue

        # All third-party actions require a full lowercase SHA.
        if not is_full_sha(ref):
            violations.append("MUTABLE_ACTION")
            break

    # ---------------------------------------------------------
    # 5. IMAGE SECURITY
    # ---------------------------------------------------------

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 6. PRODUCTION
    # ---------------------------------------------------------

    if data.get("target") == "production":
        if data.get("event") != "push" or data.get("ref") != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # 7. FINAL DECISION
    # ---------------------------------------------------------

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }


@app.route("/release-gate", methods=["POST"])
def release_gate():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"decision": "block", "violations": []})

    return jsonify(evaluate_release_gate(data))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
