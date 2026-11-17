# Slack identity response and safe diagnostics

The declared `slack-auth-test-v1` adapter accepts the documented user response:

```json
{"ok":true,"url":"https://example.slack.com/","team":"Example Workspace","user":"example-user","team_id":"TEXAMPLE","user_id":"UEXAMPLE"}
```

Only independently observed `team_id` and `user_id` establish identity; they must
exactly match the declared subject. `team` is an optional string display label,
not the token response `team.id` object. Token nested-identity validation is
unchanged. Missing, malformed or conflicting IDs and bot claims still refuse.
Secret screening, duplicate-key and body limits apply before publication.

The attempt poll stores only a fixed safe reason. Manual refresh returns its
safe reason in the immediate response; a lost response leaves pending/unknown.
The closed identity reasons distinguish HTTP refusal, body limit, response
shape, error presence, `ok` refusal/unexpected presence, display-label type,
metadata or identity echo refusal, missing workspace/user/principal, and
subject mismatch. Existing transport/parser/secret-screen reasons remain.
They contain no response values, identifiers, hashes or raw provider body.

A recorded `identity_mismatch` from an older binary does not identify which
predicate failed, so earlier refusals remain undiagnosed; the display-label
defect found in source does not prove a live response shape.
No automatic retry, refresh or new consent follows a refusal.

Primary contract: [Slack auth.test](https://docs.slack.dev/reference/methods/auth.test/).
