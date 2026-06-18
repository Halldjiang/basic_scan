-- MySQL 8.0+ schema for the Python 3.12 basic network scan script.
-- The main table keeps the original table name and column names used by the legacy script.
-- The optional child table makes interface IPs queryable without parsing JSON.

CREATE DATABASE IF NOT EXISTS `netdev_inventory`
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE `netdev_inventory`;

CREATE TABLE IF NOT EXISTS `ipaddresslist` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ipaddr` VARCHAR(45) NOT NULL COMMENT 'Management IP of the scanned device',
  `localhostname` VARCHAR(255) NOT NULL DEFAULT 'None',
  `interfacelist` JSON NULL COMMENT 'JSON array like [{"Eth1":"10.0.0.1/24"}]',
  `project` VARCHAR(128) NOT NULL DEFAULT 'None',
  `batch` VARCHAR(64) NOT NULL DEFAULT '999',
  `region` VARCHAR(64) DEFAULT NULL,
  `idc` VARCHAR(64) DEFAULT NULL,
  `model` TEXT NULL COMMENT 'Raw sysDescr/model text',
  `SN` JSON NULL COMMENT 'JSON array of serial numbers',
  `platform` VARCHAR(64) NOT NULL DEFAULT 'unknown',
  `bgpid` VARCHAR(45) DEFAULT 'None',
  `bgplocalAS` VARCHAR(32) DEFAULT 'None',
  `peerAS` JSON NULL,
  `peerPrefix` JSON NULL,
  `Device_DC_Loc` VARCHAR(512) DEFAULT NULL,
  `scan_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_ipaddresslist_ipaddr` (`ipaddr`),
  KEY `idx_ipaddresslist_scan_time` (`scan_time`),
  KEY `idx_ipaddresslist_scan_ip` (`scan_time`, `ipaddr`),
  KEY `idx_ipaddresslist_hostname` (`localhostname`),
  KEY `idx_ipaddresslist_region_idc` (`region`, `idc`),
  KEY `idx_ipaddresslist_platform` (`platform`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `ipaddresslist_interfaces` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `inventory_id` BIGINT UNSIGNED NOT NULL,
  `device_ip` VARCHAR(45) NOT NULL,
  `interface_name` VARCHAR(255) NOT NULL,
  `interface_ip` VARCHAR(45) NOT NULL,
  `prefix_len` TINYINT UNSIGNED DEFAULT NULL,
  `ip_cidr` VARCHAR(64) NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_inventory_interface_ip` (`inventory_id`, `interface_name`, `ip_cidr`),
  KEY `idx_interfaces_device_ip` (`device_ip`),
  KEY `idx_interfaces_interface_ip` (`interface_ip`),
  CONSTRAINT `fk_interfaces_inventory`
    FOREIGN KEY (`inventory_id`) REFERENCES `ipaddresslist` (`id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

