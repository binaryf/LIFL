CREATE TABLE `lifl`.`errors` (
  `row` BIGINT NOT NULL AUTO_INCREMENT,
  `operation_id` BIGINT NOT NULL,
  `error_message` VARCHAR(512),
  PRIMARY KEY (`row`)
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE utf8_general_ci;
