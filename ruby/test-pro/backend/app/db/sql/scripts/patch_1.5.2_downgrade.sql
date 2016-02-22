USE bpac;

ALTER TABLE signature
DROP COLUMN is_editable,
DROP COLUMN created_at,
DROP FOREIGN KEY signature_ibfk_5,
DROP COLUMN author_id;

ALTER TABLE signature_category
DROP COLUMN description;

ALTER TABLE signature_severity
CHANGE COLUMN weight priority  SMALLINT NOT NULL;
