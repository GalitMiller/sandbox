DELIMITER //


USE bricata //


DROP FUNCTION IF EXISTS `SAFE_HOSTNAME`;

CREATE FUNCTION SAFE_HOSTNAME(hostname TEXT)
  RETURNS TEXT
  DETERMINISTIC
  LANGUAGE SQL
BEGIN
  SET @column_char_index = INSTR(hostname, ':');

  IF @column_char_index THEN
    RETURN LEFT(hostname, @column_char_index - 1);
  ELSE
    RETURN hostname;
  END IF;
END;


DROP TRIGGER IF EXISTS `sync_sensors_in_bpac_after_create_in_bricata` //

CREATE TRIGGER `sync_sensors_in_bpac_after_create_in_bricata`
AFTER INSERT ON bricata.sensor
FOR EACH ROW
BEGIN
  INSERT INTO
    bpac.sensors
  SET
    id = NEW.sid,
    name = NEW.name,
    hostname = SAFE_HOSTNAME(NEW.hostname),
    ssh_port = 22,
    is_active = 1,
    is_controlled_by_cmc = 0;
END //


DROP TRIGGER IF EXISTS `sync_sensors_in_bpac_after_update_in_bricata` //

CREATE TRIGGER `sync_sensors_in_bpac_after_update_in_bricata`
AFTER UPDATE ON bricata.sensor
FOR EACH ROW
BEGIN
  UPDATE
    bpac.sensors
  SET
    name = NEW.name
  WHERE
    id = NEW.sid;
END //


DROP TRIGGER IF EXISTS `sync_sensors_in_bpac_after_delete_in_bricata` //

CREATE TRIGGER `sync_sensors_in_bpac_after_delete_in_bricata`
AFTER DELETE ON bricata.sensor
FOR EACH ROW
BEGIN
  DELETE FROM
    bpac.sensor_interfaces
  WHERE
    sensor_id = OLD.sid;

  DELETE FROM
    bpac.sensors
  WHERE
    id = OLD.sid;
END //


DELIMITER ;
