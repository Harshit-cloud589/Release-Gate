from flask import Flask, request, jsonify
import re

app = Flask(__name__)


def is_full_lowercase_sha(value):
    """
    A valid full Git commit SHA for this assignment must be:
    - exactly 40 characters
    - lowercase hexadecimal
    """
    return isinstance(value, str) and bool(
        re.fullmatch(r"[0-9a-f]{40}", value)
    )


def evaluate_release_gate(data):
    violations = []

    workflow = data.get("workflow") or {}
    image = data.get("image") or {}
    permissions = workflow.get("permissions") or {}

    # ---------------------------------------------------------
    # 1. PERMISSIONS
    # ---------------------------------------------------------

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    # Must contain exactly the expected permissions.
    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # ---------------------------------------------------------
    # 2. PULL REQUEST RULES
    # ---------------------------------------------------------

    if data.get("event") == "pull_request":

        # PR must use pull_request, never pull_request_target
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        # Tests must pass, matrix must be complete,
        # and failFast must be false.
        if (
            workflow.get("testsPassed") is not True
            or workflow.get("matrixComplete") is not True
            or workflow.get("failFast") is not False
        ):
            violations.append("TESTS_INCOMPLETE")

    # ---------------------------------------------------------
    # 3. GITHUB ACTION PINNING
    # ---------------------------------------------------------

    actions = workflow.get("actions") or []

    for action in actions:
        owner = action.get("owner")
        ref = action.get("ref")

        # Official actions owned by "actions" may use a tag.
        if owner == "actions":
            continue

        # Every third-party action must use a full 40-character
        # lowercase hexadecimal commit SHA.
        if not is_full_lowercase_sha(ref):
            violations.append("MUTABLE_ACTION")
            break

    # ---------------------------------------------------------
    # 4. DOCKER IMAGE RULES
    # ---------------------------------------------------------

    # Must be multi-stage.
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # Must not run as root.
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # Safe secret modes are only:
    #   none
    #   buildkit
    secret_mode = image.get("secretMode")

    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # Must have zero critical vulnerabilities.
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # Image must be digest pinned.
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---------------------------------------------------------
    # 5. PRODUCTION RULES
    # ---------------------------------------------------------

    if data.get("target") == "production":

        # Production must be a push to main.
        if (
            data.get("event") != "push"
            or data.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        # Production requires environment approval.
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # FINAL DECISION
    # ---------------------------------------------------------

    if violations:
        decision = "block"
    else:
        decision = "promote"

    return {
        "decision": decision,
        "violations": violations
    }


# -------------------------------------------------------------
# POST /release-gate
# -------------------------------------------------------------

@app.route("/release-gate", methods=["POST"])
def release_gate():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "decision": "block",
            "violations": ["INVALID_REQUEST"]
        }), 400

    result = evaluate_release_gate(data)

    return jsonify(result)


# Optional health endpoint
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000
    )
