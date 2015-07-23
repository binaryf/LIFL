CREATE TABLE `lifl`.`data_dump` (
  `row` BIGINT NOT NULL AUTO_INCREMENT,
  `operation_id` BIGINT NOT NULL,
  `size` INT,
  `offset` INT,
  `write_data` LONGBLOB,
  PRIMARY KEY (`row`)
) ENGINE = InnoDB CHARACTER SET = utf8 COLLATE utf8_general_ci;
