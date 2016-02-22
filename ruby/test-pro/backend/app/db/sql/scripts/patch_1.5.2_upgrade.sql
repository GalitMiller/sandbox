USE bpac;

ALTER TABLE signature
ADD is_editable BOOL AFTER revision,
ADD created_at DATETIME AFTER is_editable,
ADD author_id INT NULL AFTER created_at,
ADD CONSTRAINT signature_ibfk_5
FOREIGN KEY(author_id) REFERENCES user (id);


ALTER TABLE signature_category
ADD description VARCHAR(255) NULL AFTER name;


ALTER TABLE signature_severity
CHANGE COLUMN priority weight SMALLINT NOT NULL;
