-- Optional upstream method policy, owned by the explicit binding.
CREATE TABLE binding_method_policies (
    agent_id INTEGER NOT NULL,
    registration TEXT NOT NULL,
    policy TEXT NOT NULL,
    PRIMARY KEY (agent_id, registration),
    FOREIGN KEY (agent_id, registration)
        REFERENCES agent_credential_overrides(agent_id, registration) ON DELETE CASCADE
);
