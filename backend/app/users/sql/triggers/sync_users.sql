DELIMITER //


USE bricata //


DROP FUNCTION IF EXISTS `EMAIL_TO_LOGIN`;

CREATE FUNCTION EMAIL_TO_LOGIN(email TEXT)
  RETURNS TEXT
  DETERMINISTIC
  LANGUAGE SQL
BEGIN
  SET @at_char_index = INSTR(email, '@');

  IF @at_char_index THEN
    RETURN LEFT(email, @at_char_index - 1);
  ELSE
    RETURN email;
  END IF;
END;


DROP FUNCTION IF EXISTS `DETECT_USER_ROLE`;

CREATE FUNCTION DETECT_USER_ROLE(is_admin TINYINT)
  RETURNS TEXT
  DETERMINISTIC
  LANGUAGE SQL
BEGIN
  IF is_admin THEN
    RETURN 'admin';
  ELSE
    RETURN 'analyst';
  END IF;
END;


DROP TRIGGER IF EXISTS `sync_users_in_bpac_after_create_in_bricata` //

CREATE TRIGGER `sync_users_in_bpac_after_create_in_bricata`
AFTER INSERT ON bricata.users
FOR EACH ROW
BEGIN
  INSERT INTO
    bpac.user
  SET
    id = NEW.id,
    email = NEW.email,
    login = EMAIL_TO_LOGIN(NEW.email),
    name = NEW.name,
    password = NEW.encrypted_password,
    role = DETECT_USER_ROLE(NEW.admin),
    active = NEW.enabled;
END //


DROP TRIGGER IF EXISTS `sync_users_in_bpac_after_update_in_bricata` //

CREATE TRIGGER `sync_users_in_bpac_after_update_in_bricata`
AFTER UPDATE ON bricata.users
FOR EACH ROW
BEGIN
  UPDATE
    bpac.user
  SET
    email = NEW.email,
    login = EMAIL_TO_LOGIN(NEW.email),
    name = NEW.name,
    password = NEW.encrypted_password,
    role = DETECT_USER_ROLE(NEW.admin),
    active = NEW.enabled
  WHERE
    id = NEW.id;
END //


DROP TRIGGER IF EXISTS `sync_users_in_bpac_after_delete_in_bricata` //

CREATE TRIGGER `sync_users_in_bpac_after_delete_in_bricata`
AFTER DELETE ON bricata.users
FOR EACH ROW
BEGIN
  DELETE FROM
    bpac.user
  WHERE
    id = OLD.id;
END //


DELIMITER ;
