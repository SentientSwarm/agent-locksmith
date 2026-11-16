-- AGENT-281: a route's request policy (which requests it forwards at all).
-- NULL means no policy. No CHECK constraint, so a later policy needs no
-- table rebuild; the daemon refuses every request on a value it does not
-- know. A policy narrows what a route forwards, not where: no authority
-- trigger.
ALTER TABLE registrations ADD COLUMN policy TEXT;
