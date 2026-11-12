-- Brokered routes phase 3: a destination may be an account broker.
-- `broker_json` holds the BrokerSpec; NULL means a plain upstream. On
-- `registrations` it describes the active backend, on
-- `registration_backends` a declared one.
ALTER TABLE registrations ADD COLUMN broker_json TEXT;
ALTER TABLE registration_backends ADD COLUMN broker_json TEXT;

-- Turning a declared backend into a broker (or back) changes what its
-- stashed bindings would authorise, so it discards them like a
-- destination change does.
DROP TRIGGER backend_destination_changed_stash;
CREATE TRIGGER backend_destination_changed_stash
AFTER UPDATE OF upstream, egress, upstream_ca_pem, broker_json ON registration_backends
WHEN OLD.upstream != NEW.upstream OR OLD.egress != NEW.egress
  OR OLD.upstream_ca_pem IS NOT NEW.upstream_ca_pem
  OR (OLD.broker_json IS NULL) IS NOT (NEW.broker_json IS NULL)
BEGIN
    DELETE FROM backend_bindings
     WHERE route = NEW.route AND backend = NEW.name;
END;
