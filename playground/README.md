# Playground Vulnerable Microservice (`auth_service`)

This playground microservice provides an intentional, reproducible security vulnerability (CWE-89 SQL Injection) designed to verify the complete autonomous remediation lifecycle of the Autonomous Security Agent.

---

## Vulnerability Detail
- **Location:** `playground/auth_service/service.py:38`
- **Classification:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Description:** Direct f-string interpolation into SQLite queries allows an unauthenticated attacker to bypass authentication using injection strings such as `' OR '1'='1`.

---

## Local Reproduction

Run the test suite directly:

```bash
pytest playground/auth_service/test_service.py -v
```

### Expected Vulnerability Failure Output

```
FAILED playground/auth_service/test_service.py::test_sql_injection_bypass_prevented
AssertionError: Vulnerability detected: SQL injection authentication bypass succeeded!
assert {'id': '1', 'role': 'admin', 'username': 'admin'} is None
```

---

## Autonomous Agent Remediation

Feed the pytest failure log directly to the Autonomous Security Agent:

```bash
pytest playground/auth_service/test_service.py 2>&1 | python -m src.cli run --repo="playground/auth_service"
```

The agent executes:
1. **Triage:** Extracts `services/auth/service.py` (or `playground/auth_service/service.py`) and CWE-89.
2. **Context Retrieval:** Reads the source snippet and loads SQL injection defense guidelines.
3. **Patch Synthesis:** Converts string interpolation into parameterized SQLite query:
   ```diff
   - query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
   - cursor.execute(query)
   + query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
   + cursor.execute(query, (username, password))
   ```
4. **Sandbox Validation:** Executes the pytest suite in an isolated Docker container, confirming all 3 tests pass.
5. **PR Creation:** Creates a remediation branch and opens a Pull Request / Merge Request.
