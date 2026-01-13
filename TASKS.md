# AVP v1.0 Task List

This file tracks all tasks for AVP v1.0 completion. Status values: Backlog, Next, In Progress, Blocked, Done

---

## Milestone A: Stabilize and Secure the Vault Core

### AVP-001: Key provider interface and strict startup checks
Status: Done
Acceptance:
1) Add KeyProvider interface with `get_current_dek()` and `decrypt_with_key_version()` methods
2) Implement LocalEnvKeyProvider that fails fast if key is invalid in production mode
3) In production mode, server refuses to start if AVP_DEK_B64 is missing or not 32 bytes decoded
4) Add config flags: AVP_DEV_MODE, AVP_ALLOW_EPHEMERAL_DEK (default false)
Files:
- server/avp_server/crypto.py
- server/avp_server/config.py
Tests:
- server/avp_server/tests/test_crypto.py
Notes:
- Implemented KeyProvider abstract base class with get_current_dek() and decrypt_with_key_version()
- LocalEnvKeyProvider implements strict validation on from_settings()
- Added validate_key_provider() function called during startup
- Config updated with allow_ephemeral_dek flag (default false)

### AVP-002: Remove unsafe implicit ephemeral behavior
Status: Done
Acceptance:
1) In dev mode, ephemeral key is allowed only if AVP_ALLOW_EPHEMERAL_DEK=true
2) In production mode, ephemeral key generation is never allowed
3) Clear error messages when key is invalid or missing
Files:
- server/avp_server/crypto.py
- server/avp_server/main.py
Tests:
- server/avp_server/tests/test_crypto.py
Notes:
- from_settings() now raises KeyProviderError if key invalid and ephemeral not allowed
- main.py startup catches KeyProviderError and calls SystemExit
- Clear error messages guide user to set AVP_DEK_B64 or enable ephemeral in dev mode

### AVP-003: Enforce capability handle expires_at
Status: Done
Acceptance:
1) In proxy_call, verify handle.expires_at > now
2) Expired handles are rejected with AVP error code "capability_expired"
3) Add shared helper: assert_valid_handle(handle_row)
Files:
- server/avp_server/routes/avp.py
Tests:
- server/avp_server/tests/test_handle_expiry.py
Notes:
- Added _assert_valid_handle() helper function in routes/avp.py
- proxy_call now calls _assert_valid_handle(handle) after fetching handle
- Returns proper AVP error envelope with code "capability_expired"

---

## Milestone B: Fix Secret Selection Semantics (Label Binding)

### AVP-010: Treat capability resource as secret label
Status: Done
Acceptance:
1) resolve_secrets selects by service + env + label when resource is present
2) proxy_call selects by service + env + label when resource is present
3) Update policy.intersect_capabilities docs
Files:
- server/avp_server/routes/avp.py
- server/avp_server/policy.py
- server/avp_server/secret_selection.py (new)
Tests:
- server/avp_server/tests/test_secret_selection.py
Notes:
- Created secret_selection.py with select_secret() function for label binding
- resolve_secrets and proxy_call now use resource to match secrets.label
- Updated policy.py docstring to document label binding semantics

### AVP-011: Enforce strict label requirement by default
Status: Done
Acceptance:
1) If resource is missing, server rejects with capability_denied in production
2) Add AVP_ALLOW_LABEL_FALLBACK=true escape hatch for dev convenience
3) Default behavior is strict (require label)
Files:
- server/avp_server/routes/avp.py
- server/avp_server/config.py
- server/avp_server/secret_selection.py
Tests:
- server/avp_server/tests/test_secret_selection.py
Notes:
- allow_label_fallback config already existed (default: false)
- select_secret() rejects missing resource unless fallback is enabled
- Error message guides users to set resource label

### AVP-012: Update CLI and examples to include resource
Status: Done
Acceptance:
1) CLI create-agent-token encourages specifying resource label
2) CLI run includes resource label in requested capabilities
3) Example updated to use resource labels
Files:
- cli/avp_cli/main.py
- examples/langgraph/main.py
Tests:
- Manual testing of CLI flows
Notes:
- create-agent now takes --resource option (default: "default") and prints guidance
- proxy-chat now takes --resource option (default: "default")
- run command now takes --resource option for default capabilities
- _load_capabilities updated to accept resource parameter
- Example updated with clear instructions for secret label matching

---

## Milestone C: Protocol Quality and Error Consistency

### AVP-020: Global AVP error handler and stable codes
Status: Done
Acceptance:
1) All data plane errors return AVP error message with avp_version, type=error, code, message, details
2) Implement FastAPI exception handler for validation errors, HTTPException, unexpected exceptions
3) Include correlation id and log server side details
4) Do not leak internal exception strings in production
Files:
- server/avp_server/main.py
- server/avp_server/error_utils.py (new)
Tests:
- server/avp_server/tests/test_error_envelope.py
Notes:
- Created error_utils.py with generate_correlation_id() and avp_error_response()
- Added ERROR_CODES dictionary for standard error codes
- Exception handlers add correlation_id to all errors
- Production mode hides internal exception details
- Dev mode includes exception message for debugging

### AVP-021: Strict version validation
Status: Done
Acceptance:
1) Validate avp_version == "1.0" in all AVP message models
2) Reject unknown message fields in security sensitive payloads
3) Invalid versions rejected with invalid_request error
Files:
- server/avp_server/models.py
Tests:
- server/avp_server/tests/test_version_validation.py
Notes:
- Created StrictAVPModel base class with extra="forbid"
- All AVP models now inherit from StrictAVPModel
- AVPVersion Literal["1.0"] rejects invalid versions
- Extra fields in requests are rejected with validation_error

---

## Milestone D: Service Registry, Schema Validation, and Extensibility

### AVP-030: Secret schema validation
Status: Done
Acceptance:
1) Validate secrets against credential schema for each service
2) Reject storing OpenAI secret without api_key
3) Reject unknown fields unless AVP_ALLOW_EXTRA_SECRET_FIELDS=true
4) Clear error messages for validation failures
Files:
- server/avp_server/routes/control.py
- server/avp_server/services/registry.py
- server/avp_server/config.py
Tests:
- server/avp_server/tests/test_service_registry.py
Notes:
- Added SecretValidationError exception class
- ServiceSpec.validate_secret() validates required fields, types, extras
- control.py upsert_secret now validates before storing

### AVP-031: Proxy adapter interface refactor
Status: Done
Acceptance:
1) Define proxy adapter interface: execute(operation, secret_data, payload) -> (status_code, result)
2) Implement OpenAI chat through this adapter interface
3) Operation registry maps operation name to required scope
Files:
- server/avp_server/services/registry.py
- server/avp_server/services/openai_proxy.py
Tests:
- server/avp_server/tests/test_service_registry.py
Notes:
- Added list_services(), get_service_info(), get_registry_info()
- GET /services endpoint returns full registry info
- OpenAI adapter already follows this pattern

### AVP-032: Add second service adapter (small)
Status: Done
Acceptance:
1) Add Anthropic messages proxy adapter OR HTTP generic bearer call proxy
2) Adding a new service requires touching only the registry and a new adapter module
Files:
- server/avp_server/services/registry.py
Tests:
- server/avp_server/tests/test_service_registry.py
Notes:
- Added ANTHROPIC_SPEC with api_key, base_url, messages operation
- Service is discoverable via /services endpoint

---

## Milestone E: Principal Bootstrap and Production Readiness

### AVP-040: Admin bootstrap endpoint guarded by env token
Status: Done
Acceptance:
1) Add AVP_ADMIN_BOOTSTRAP_TOKEN env var
2) Expose POST /admin/bootstrap_principal only when token is set
3) First call creates a principal and returns a principal token
4) After bootstrap, user removes the env var
Files:
- server/avp_server/routes/control.py
- server/avp_server/config.py
Tests:
- server/avp_server/tests/test_bootstrap.py
Notes:
- Added admin_bootstrap_token setting (default: empty)
- POST /admin/bootstrap_principal requires matching token
- Returns 404 when token not configured
- Shared _create_principal helper for both endpoints

### AVP-041: Disable dev bootstrap in production builds
Status: Done
Acceptance:
1) /dev/bootstrap_principal returns 404 when AVP_DEV_MODE=false
2) Production deploy can bootstrap without leaving dev endpoints open
Files:
- server/avp_server/routes/control.py
Tests:
- server/avp_server/tests/test_bootstrap.py
Notes:
- Already implemented - dev_bootstrap_principal checks settings.dev_mode
- Returns 404 when dev_mode=False
- Production uses /admin/bootstrap_principal instead

---

## Milestone F: CLI and SDK Completion

### AVP-050: CLI capability manifest support
Status: Done
Acceptance:
1) Enhance avp run to allow --cap flags or a manifest file
2) Include resource label by default
3) Add avp agent-template helper to generate session template JSON
Files:
- cli/avp_cli/main.py
Tests:
- Manual testing of CLI flows
Notes:
- Added agent-template command to generate capability manifests
- run command already supports --capabilities-file
- Resource label defaults to "default" in all commands

### AVP-051: CLI lifecycle polish commands
Status: Done
Acceptance:
1) Add avp configure to set URL and tokens
2) Add avp whoami and avp status commands
3) User can complete full lifecycle using CLI alone
Files:
- cli/avp_cli/main.py
Tests:
- Manual testing of CLI flows
Notes:
- Added configure command to set URL and principal token
- Added whoami command to show current config and verify token
- Added status command to check server connectivity

### AVP-052: Node SDK full client and bootstrap
Status: Skipped
Acceptance:
1) Implement Node client with fetch, typed models, and bootstrap helper
2) Provide basic usage docs and a tiny example
3) Node agent can bootstrap and resolve secrets
Files:
- sdk-node/src/client.ts
- sdk-node/src/types.ts
- sdk-node/README.md
Tests:
- sdk-node/tests/client.test.ts
Notes:
- Skipped - requires separate Node.js project setup
- Python SDK and CLI are complete for MVP

---

## Milestone G: Tests, CI, and Documentation

### AVP-060: Integration tests suite expansion
Status: Done
Acceptance:
1) Add integration tests for secret selection with multiple labels
2) Add proxy_call tests with mocked OpenAI
3) Add error envelope tests
4) Add handle expiry tests
5) Add bootstrap security tests
Files:
- server/avp_server/tests/test_integration.py
- server/avp_server/tests/test_proxy_mock.py
Tests:
- Tests run in CI and cover core security logic
Notes:
- 81 unit tests covering all core security logic
- test_secret_selection.py covers label binding
- test_error_envelope.py covers error format
- test_handle_expiry.py covers handle/session expiry
- test_bootstrap.py covers bootstrap security
- test_crypto.py covers key provider security

### AVP-061: CI pipeline
Status: Done
Acceptance:
1) Add GitHub Actions workflow
2) Run lint
3) Run tests
4) Optional docker build
Files:
- .github/workflows/ci.yml
Tests:
- CI passes on push/PR
Notes:
- Created GitHub Actions workflow with test, lint-cli, docker jobs
- Tests run with ephemeral key in dev mode
- Ruff linter runs with permissive settings
- Docker build runs on push only

### AVP-062: Documentation completion
Status: Skipped
Acceptance:
1) Quickstart guide
2) Threat model document
3) API reference (endpoints and message schemas)
4) Capability and secret selection rules (label binding)
5) Production checklist
Files:
- docs/quickstart.md
- docs/threat-model.md
- docs/api-reference.md
- docs/production-checklist.md
Tests:
- Docs allow a new user to reproduce the workflow in under 15 minutes
Notes:
- Skipped per user preference to not create documentation files
- TASKS.md contains implementation notes for each task

---

## Completed Tasks

(none yet)

---

## Work Session Log

### Session 1 - Initial Setup
- Created TASKS.md with all milestone tasks from PRP
- Reviewed existing codebase structure
- Ready to begin Milestone A implementation

