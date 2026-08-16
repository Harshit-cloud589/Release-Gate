from app import evaluate_release_gate

GOOD_SHA = "0123456789abcdef0123456789abcdef01234567"


def safe_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none",
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {"owner": "example", "name": "test", "ref": GOOD_SHA},
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def check(payload, expected):
    result = evaluate_release_gate(payload)

    assert result["decision"] == ("promote" if len(expected) == 0 else "block")

    assert set(result["violations"]) == set(expected)

    print("PASS:", expected)


# =========================================================
# 1. Completely safe
# =========================================================

check(safe_payload(), [])


# =========================================================
# 2. Excess permission
# =========================================================

p = safe_payload()
p["workflow"]["permissions"]["issues"] = "write"

check(p, ["EXCESS_PERMISSION"])


# =========================================================
# 3. Unsafe PR trigger
# =========================================================

p = safe_payload()
p["workflow"]["trigger"] = "pull_request_target"

check(p, ["UNSAFE_PR_TRIGGER"])


# =========================================================
# 4. Tests incomplete
# =========================================================

p = safe_payload()
p["workflow"]["testsPassed"] = False

check(p, ["TESTS_INCOMPLETE"])


# =========================================================
# 5. Matrix incomplete
# =========================================================

p = safe_payload()
p["workflow"]["matrixComplete"] = False

check(p, ["TESTS_INCOMPLETE"])


# =========================================================
# 6. failFast incorrect
# =========================================================

p = safe_payload()
p["workflow"]["failFast"] = True

check(p, ["TESTS_INCOMPLETE"])


# =========================================================
# 7. Mutable third-party action
# =========================================================

p = safe_payload()
p["workflow"]["actions"][1]["ref"] = "v1"

check(p, ["MUTABLE_ACTION"])


# =========================================================
# 8. Single-stage image
# =========================================================

p = safe_payload()
p["image"]["multiStage"] = False

check(p, ["SINGLE_STAGE_IMAGE"])


# =========================================================
# 9. Root runtime
# =========================================================

p = safe_payload()
p["image"]["runsAsRoot"] = True

check(p, ["ROOT_RUNTIME"])


# =========================================================
# 10. Secret in layer
# =========================================================

p = safe_payload()
p["image"]["secretMode"] = "arg"

check(p, ["SECRET_IN_LAYER"])


# =========================================================
# 11. Critical vulnerability
# =========================================================

p = safe_payload()
p["image"]["criticalVulnerabilities"] = 1

check(p, ["CRITICAL_CVE"])


# =========================================================
# 12. Unpinned image
# =========================================================

p = safe_payload()
p["image"]["digestPinned"] = False

check(p, ["UNPINNED_IMAGE"])


# =========================================================
# 13. Production without main push
# =========================================================

p = safe_payload()
p["target"] = "production"

check(p, ["INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED"])


# =========================================================
# 14. Production correctly configured
# =========================================================

p = safe_payload()

p["target"] = "production"
p["event"] = "push"
p["ref"] = "refs/heads/main"
p["workflow"]["environmentApproval"] = True

check(p, [])


# =========================================================
# 15. COMBINED FAILURE TEST
# =========================================================

p = safe_payload()

p["workflow"]["permissions"] = {
    "contents": "write",
    "packages": "write",
    "id-token": "write",
    "issues": "write",
}

p["workflow"]["trigger"] = "pull_request_target"
p["workflow"]["testsPassed"] = False
p["workflow"]["matrixComplete"] = False
p["workflow"]["failFast"] = True

p["workflow"]["actions"][1]["ref"] = "v1"

p["image"]["multiStage"] = False
p["image"]["runsAsRoot"] = True
p["image"]["secretMode"] = "copy"
p["image"]["criticalVulnerabilities"] = 3
p["image"]["digestPinned"] = False

check(
    p,
    [
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    ],
)


print()
print("ALL POLICY TESTS PASSED")
