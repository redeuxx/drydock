-- drydock at 5daaabf, alembic revision 0015.
-- Made by python -m tests.upgrade_fixture; secrets use its KEY. Do not edit.
BEGIN TRANSACTION;
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO "alembic_version" VALUES('0015');
CREATE TABLE audit_events (
	id INTEGER NOT NULL, 
	ts DATETIME NOT NULL, 
	actor VARCHAR(64), 
	ip VARCHAR(64), 
	action VARCHAR(64) NOT NULL, 
	target VARCHAR(255), 
	outcome VARCHAR(16) NOT NULL, 
	details TEXT NOT NULL, 
	PRIMARY KEY (id)
);
INSERT INTO "audit_events" VALUES(1,'2026-11-03 01:07:32.553688','admin','203.0.113.5','setup.complete','user:1','success','{"source_ip": "203.0.113.5"}');
INSERT INTO "audit_events" VALUES(2,'2026-11-03 01:07:32.655739','admin','203.0.113.5','user.create','user:2','success','{"role": "operator", "username": "ops"}');
INSERT INTO "audit_events" VALUES(3,'2026-11-03 01:07:32.719651','admin','203.0.113.5','user.create','user:3','success','{"role": "viewer", "username": "viewer"}');
INSERT INTO "audit_events" VALUES(4,'2026-11-03 01:07:32.785777','admin','203.0.113.5','user.create','user:4','success','{"role": "admin", "username": "second"}');
INSERT INTO "audit_events" VALUES(5,'2026-11-03 01:07:32.827956','admin','203.0.113.5','host.create','host:1','success','{"enabled": true, "kind": "local", "name": "local", "target": "tcp://127.0.0.1:9"}');
INSERT INTO "audit_events" VALUES(6,'2026-11-03 01:07:32.854947','admin','203.0.113.5','host.create','host:2','success','{"enabled": true, "identity": "generate", "kind": "ssh", "name": "remote", "target": "backup@203.0.113.9:22"}');
INSERT INTO "audit_events" VALUES(7,'2026-11-03 01:07:32.898977','admin','203.0.113.5','storage.create','storage:1','success','{"enabled": true, "kind": "local", "name": "backups", "path": "/tmp/drydock-upgrade/storage"}');
INSERT INTO "audit_events" VALUES(8,'2026-11-03 01:07:32.940157','admin','203.0.113.5','storage.create','storage:2','success','{"enabled": true, "kind": "webdav", "location": "https://dav.example.com/remote.php/dav", "name": "nas"}');
INSERT INTO "audit_events" VALUES(9,'2026-11-03 01:07:32.994962','admin','203.0.113.5','hook.create','hook:1','success','{"argv": ["pg_dump", "-f", "/srv/dump.sql"], "container": "web", "host_id": 1, "log_output": false, "name": "dump", "project": null, "timeout_s": 300, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(10,'2026-11-03 01:07:33.021356','admin','203.0.113.5','hook.create','hook:2','success','{"argv": ["sync"], "container": "db", "host_id": 1, "log_output": false, "name": "app-flush", "project": "app", "timeout_s": 60, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(11,'2026-11-03 01:07:33.456821','admin','203.0.113.5','notification.create','notification:1','success','{"enabled": true, "kind": "ntfy", "name": "ops"}');
INSERT INTO "audit_events" VALUES(12,'2026-11-03 01:07:33.500072','admin','203.0.113.5','job.create','job:1','success','{"consistency_mode": "stop", "copy_first": false, "cron": "0 3 * * 0", "enabled": true, "encrypted": true, "host_id": 1, "images_reference_only_if_pullable": false, "more_targets": [], "name": "web backup", "notifications": ["ops (success, failure)"], "post_hooks": [], "pre_hooks": ["dump"], "retention": "{\"daily\": 7, \"mode\": \"gfs\", \"monthly\": 12, \"weekly\": 4, \"yearly\": 0}", "scope": "all", "skip_mounts": ["bind:/srv/web-cache"], "storage_target_id": 1, "target": "web", "target_type": "container", "timezone": "Europe/Berlin", "uuid": "8786c124-78b7-47a7-a78c-9cdf4b158dc2"}');
INSERT INTO "audit_events" VALUES(13,'2026-11-03 01:07:33.528126','admin','203.0.113.5','job.create','job:2','success','{"consistency_mode": "pause", "copy_first": true, "cron": null, "enabled": true, "encrypted": false, "host_id": 1, "images_reference_only_if_pullable": false, "more_targets": ["container worker"], "name": "app stack", "notifications": [], "post_hooks": ["app-flush"], "pre_hooks": [], "retention": "{\"keep_last\": 3, \"mode\": \"last\"}", "scope": "data", "skip_mounts": [], "storage_target_id": 1, "target": "app", "target_type": "stack", "timezone": null, "uuid": "e05e9630-60d9-43a7-887a-5aed8a8a92dd"}');
CREATE TABLE backups (
	id INTEGER NOT NULL, 
	job_id INTEGER, 
	storage_target_id INTEGER NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	size INTEGER NOT NULL, 
	sha256 VARCHAR(64) NOT NULL, 
	signed BOOLEAN NOT NULL, 
	encrypted BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_backups_name UNIQUE (storage_target_id, name), 
	FOREIGN KEY(job_id) REFERENCES jobs (id) ON DELETE SET NULL, 
	FOREIGN KEY(storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT
);
INSERT INTO "backups" VALUES(1,1,1,'drydock-web-backup-fixture.tar.zst.age',4096,'0000000000000000000000000000000000000000000000000000000000000000',1,1,'2026-11-03 01:07:33.530737');
CREATE TABLE hooks (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	name VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	host_id INTEGER NOT NULL, 
	project VARCHAR(63), 
	container VARCHAR(128) NOT NULL, 
	argv_json TEXT NOT NULL, 
	user VARCHAR(65) NOT NULL, 
	workdir VARCHAR(1024) NOT NULL, 
	timeout_s INTEGER NOT NULL, 
	log_output BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	CONSTRAINT ck_hooks_timeout CHECK (timeout_s BETWEEN 1 AND 3600), 
	UNIQUE (name), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT
);
INSERT INTO "hooks" VALUES(1,'dump',1,NULL,'web','["pg_dump","-f","/srv/dump.sql"]','','',300,0,'2026-11-03 01:07:32.994512','2026-11-03 01:07:32.994066');
INSERT INTO "hooks" VALUES(2,'app-flush',1,'app','db','["sync"]','','',60,0,'2026-11-03 01:07:33.021157','2026-11-03 01:07:33.021057');
CREATE TABLE hosts (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	name VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	kind VARCHAR(8) NOT NULL, 
	docker_url VARCHAR(255), 
	address VARCHAR(255), 
	port INTEGER, 
	username VARCHAR(64), 
	ssh_key_enc TEXT, 
	ssh_public_key TEXT, 
	key_passphrase_enc TEXT, 
	known_host_line TEXT, 
	host_key_fingerprint VARCHAR(128), 
	remote_socket_path VARCHAR(255), 
	api_version VARCHAR(16), 
	last_seen DATETIME, 
	enabled BOOLEAN NOT NULL, 
	CONSTRAINT ck_hosts_kind CHECK (kind IN ('local', 'ssh')), 
	CONSTRAINT ck_hosts_port CHECK (port IS NULL OR port BETWEEN 1 AND 65535), 
	UNIQUE (name)
);
INSERT INTO "hosts" VALUES(1,'local','local','tcp://127.0.0.1:9',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1);
INSERT INTO "hosts" VALUES(2,'remote','ssh',NULL,'203.0.113.9',22,'backup','gAAAAABq6TPU1fehPzlFdxqrIvr8FbU9mdT6MMgcrlzGXVZ8wQ45xBuPiPrwuVlEeT7TDOH0axQ6zC5avn6nsDrrUJZ30v-h3F6L7ETkl5o-U7f7z7qYu0n1okUe6cmsEEbab734q259xg45_xVnLYRnAV82flijFy4pPSDrtm1EtQgD_T95vFE77ksnE5Ne4Tqtatz00uQdouYf1hW6Ld3njv0K7ld2zfsW8I5QkL3DIAV716Q8kh6VhzUcgIUB6NNEH_cY8AEDk0K7_z6_lybErBuK3uSdvu8vD7kIB6kZtEznjp_7OKqD0VQKfD98kfkoZzQzRsKVWZoOcFnxvqQOPMNPeP_wlZrqnzdL24jM2TpTtdhMHzjTnIupCk-sEG7hlrFUxSg0w9itOLX9bnIMWSiTqqR5kVAUWgUXWJquCAGMhto280BadpnQh98cPCcxxrdZXQL40kqL7DfdRgR4Cive_pKf0XMqoNNMHrAeudOMxCVVo2lVXUImjqlQb9zZfH9tzTo5vUFFonzkdb2wY32DbDcTKYcSqpmaJhY9Ait886E0cpcO9OKkN9fPEj3g3VVgSLniqitoIWNZpr_IQ8sZUMyWpw==','ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxNpCHOl8zbT8z13wTxPqAZW8RxtwtBJRoa9kD20xiw drydock',NULL,NULL,NULL,'/var/run/docker.sock',NULL,NULL,1);
CREATE TABLE installation (
	id INTEGER NOT NULL, 
	instance_id VARCHAR(32) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_installation_single_row CHECK (id = 1)
);
INSERT INTO "installation" VALUES(1,'0bff039d883041ca8ee2286109ba2ab9');
CREATE TABLE job_notifications (
	job_id INTEGER NOT NULL, 
	target_id INTEGER NOT NULL, 
	on_success BOOLEAN NOT NULL, 
	on_failure BOOLEAN NOT NULL, 
	PRIMARY KEY (job_id, target_id), 
	FOREIGN KEY(job_id) REFERENCES jobs (id) ON DELETE CASCADE, 
	FOREIGN KEY(target_id) REFERENCES notification_targets (id) ON DELETE CASCADE
);
INSERT INTO "job_notifications" VALUES(1,1,1,1);
CREATE TABLE job_targets (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	job_id INTEGER NOT NULL, 
	position INTEGER NOT NULL, 
	target_type VARCHAR(16) NOT NULL, 
	target VARCHAR(255) NOT NULL, 
	uuid VARCHAR(36) NOT NULL, 
	CONSTRAINT ck_job_targets_target_type CHECK (target_type IN ('container', 'stack')), 
	CONSTRAINT uq_job_targets_uuid UNIQUE (uuid), 
	CONSTRAINT fk_job_targets_job_id_jobs FOREIGN KEY(job_id) REFERENCES jobs (id) ON DELETE CASCADE
);
INSERT INTO "job_targets" VALUES(1,2,1,'container','worker','e0e6c794-5347-439d-b79e-36674550b301');
CREATE TABLE "jobs" (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	uuid VARCHAR(36) NOT NULL, 
	name VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	host_id INTEGER NOT NULL, 
	storage_target_id INTEGER NOT NULL, 
	target_type VARCHAR(16) NOT NULL, 
	target VARCHAR(255) NOT NULL, 
	scope VARCHAR(16) NOT NULL, 
	consistency_mode VARCHAR(16) NOT NULL, 
	images_reference_only_if_pullable BOOLEAN NOT NULL, 
	encrypted BOOLEAN NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	pre_hooks TEXT DEFAULT '[]' NOT NULL, 
	post_hooks TEXT DEFAULT '[]' NOT NULL, retention TEXT DEFAULT '{"keep_last": 7, "mode": "last"}' NOT NULL, cron VARCHAR(100), timezone VARCHAR(64), last_fired_at DATETIME, skip_mounts TEXT DEFAULT '[]' NOT NULL, copy_first BOOLEAN DEFAULT 0 NOT NULL, 
	CONSTRAINT ck_jobs_scope CHECK (scope IN ('config', 'data', 'image', 'all')), 
	CONSTRAINT ck_jobs_target_type CHECK (target_type IN ('container', 'stack')), 
	CONSTRAINT ck_jobs_consistency CHECK (consistency_mode IN ('stop', 'pause', 'live')), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT, 
	UNIQUE (uuid), 
	FOREIGN KEY(storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT, 
	UNIQUE (name)
);
INSERT INTO "jobs" VALUES(1,'8786c124-78b7-47a7-a78c-9cdf4b158dc2','web backup',1,1,'container','web','all','stop',0,1,1,'2026-11-03 01:07:33.497589','2026-11-03 01:07:33.497086','[1]','[]','{"daily": 7, "mode": "gfs", "monthly": 12, "weekly": 4, "yearly": 0}','0 3 * * 0','Europe/Berlin',NULL,'["bind:/srv/web-cache"]',0);
INSERT INTO "jobs" VALUES(2,'e05e9630-60d9-43a7-887a-5aed8a8a92dd','app stack',1,1,'stack','app','data','pause',0,0,1,'2026-11-03 01:07:33.526501','2026-11-03 01:07:33.526100','[]','[2]','{"keep_last": 3, "mode": "last"}',NULL,NULL,NULL,'[]',1);
CREATE TABLE notification_targets (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	name VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	url_enc TEXT NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	CONSTRAINT ck_notification_targets_kind CHECK (kind IN ('webhook', 'email', 'ntfy', 'gotify', 'url')), 
	UNIQUE (name)
);
INSERT INTO "notification_targets" VALUES(1,'ops','ntfy','gAAAAABq6TPVhGvwGWfoLgYJc765CWmXnMwwlk3RYHuslYLXb_r_J9Xzqe_0POXdfKYh_VBonGozl5NDOYGpBIQz73RCbBfIoi6xoHmrhB6Yjic8npK3uHY=',1,'2026-11-03 01:07:33.456408');
CREATE TABLE "runs" (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	job_id INTEGER, 
	kind VARCHAR(16) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	triggered_by VARCHAR(64), 
	stopped_containers_json TEXT NOT NULL, 
	archive_name VARCHAR(255), 
	size INTEGER, 
	sha256 VARCHAR(64), 
	error TEXT, 
	created_at DATETIME NOT NULL, 
	started_at DATETIME, 
	finished_at DATETIME, 
	"plan" TEXT, 
	restore_originals_json TEXT DEFAULT '{}' NOT NULL, paused_containers_json TEXT DEFAULT '[]' NOT NULL, target_uuid VARCHAR(36), target_label VARCHAR(300), dismissed_at DATETIME, first_run_id INTEGER, 
	CONSTRAINT ck_runs_kind CHECK (kind IN ('backup', 'restore')), 
	CONSTRAINT ck_runs_status CHECK (status IN ('queued', 'verifying', 'awaiting_confirmation', 'running', 'done', 'failed', 'cancelled', 'interrupted')), 
	FOREIGN KEY(job_id) REFERENCES jobs (id) ON DELETE SET NULL
);
INSERT INTO "runs" VALUES(1,1,'backup','done','the schedule','[]','drydock-web-backup-fixture.tar.zst.age',4096,NULL,NULL,'2026-11-03 01:07:33.531358','2026-11-03 01:02:33.530030','2026-11-03 01:03:33.530030',NULL,'{}','[]',NULL,NULL,NULL,NULL);
INSERT INTO "runs" VALUES(2,2,'backup','failed','ops','[]',NULL,NULL,NULL,'The host is unreachable.','2026-11-03 01:07:33.531360','2026-11-03 01:04:33.530030','2026-11-03 01:04:33.530030',NULL,'{}','[]',NULL,NULL,NULL,NULL);
INSERT INTO "runs" VALUES(3,NULL,'restore','done','admin','[]','drydock-web-backup-fixture.tar.zst.age',NULL,NULL,NULL,'2026-11-03 01:07:33.531776','2026-11-03 01:05:33.530030','2026-11-03 01:06:33.530030','{}','{}','[]',NULL,NULL,NULL,NULL);
CREATE TABLE sessions (
	id INTEGER NOT NULL, 
	token_sha256 VARCHAR(64) NOT NULL, 
	user_id INTEGER NOT NULL, 
	csrf_token VARCHAR(64) NOT NULL, 
	ip VARCHAR(64), 
	created_at DATETIME NOT NULL, 
	last_seen_at DATETIME NOT NULL, 
	expires_at DATETIME NOT NULL, 
	reauth_at DATETIME, 
	PRIMARY KEY (id), 
	UNIQUE (token_sha256), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);
INSERT INTO "sessions" VALUES(1,'eeb388b7a41b96922841e737a337314b867a9779d0773c668f15def495ca88b9',1,'h6fgbsabQtRru8GjgdYHH4iDmgry1foMFx7USwXfBMQ','203.0.113.5','2026-11-03 01:07:32.554347','2026-11-03 01:07:33.524199','2026-11-03 13:07:32.554347','2026-11-03 01:07:32.554347');
CREATE TABLE "storage_targets" (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	name VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	config_enc TEXT NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	CONSTRAINT ck_storage_targets_kind CHECK (kind IN ('local', 'sftp', 'smb', 'webdav', 'drive')), 
	UNIQUE (name)
);
INSERT INTO "storage_targets" VALUES(1,'backups','local','gAAAAABq6TPUXl38SpTqWJLxmxezimJPhlQu-hHz_WR7czIDtzOZpJvcEps1QoX-8c8gDRrG2fC1kajNm8xWWunhYN8UVR_7jlVGAJ2278Euy16zskukchTnXe8CiqEiHzBseWl_AF0e',1,'2026-11-03 01:07:32.898555');
INSERT INTO "storage_targets" VALUES(2,'nas','webdav','gAAAAABq6TPUYH7tYmTpl4er_CP-W0FRuWtohOiBmoGgIlbqVxVRplLL9iP7T9z9iW9t1ST_1GNAL_NcMpiGiZmK7myw47jrigS28BKqJARjChU74qAMMZld5BR8aJ8BokcWzSdAkNTafMuMskHIOyP-drQ6qGQ87_yLfhuvDRX4EZNSTX-86rJGqFnTluigZsQrS5wJOGssa8uagBrLmogeg0Mz1VVz9KbA325Sq2M7hKmLbXuRk_oUrreDkj2nzR2r2ZpdgxKjO3gmLde_2O-0IJXXolP9Fg==',1,'2026-11-03 01:07:32.939860');
CREATE TABLE uploads (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	user_id INTEGER, 
	name VARCHAR(255) NOT NULL, 
	declared_size INTEGER NOT NULL, 
	received INTEGER NOT NULL, 
	path VARCHAR(1024) NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	created_at DATETIME NOT NULL, 
	expires_at DATETIME NOT NULL, 
	CONSTRAINT ck_uploads_status CHECK (status IN ('receiving', 'complete')), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL
);
INSERT INTO "uploads" VALUES(1,1,'drydock-web-backup-fixture.tar.zst.age',4096,4096,'/data/staging/uploads/fixture','complete','2026-11-03 01:07:33.532330','2126-10-10 01:07:33.530030');
CREATE TABLE users (
	id INTEGER NOT NULL, 
	username VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role INTEGER NOT NULL, 
	disabled BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, feed_read_at DATETIME, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_users_role CHECK (role IN (10, 20, 30, 40)), 
	UNIQUE (username)
);
INSERT INTO "users" VALUES(1,'admin','$argon2id$v=19$m=65536,t=3,p=4$Vl+my+QE3fbTKsREbX7yLA$bkkud8O5ZcZ0WUsclJiMVxPycekF7ew3ONOf07G+Z+8',40,0,'2026-11-03 01:07:32.552755',NULL);
INSERT INTO "users" VALUES(2,'ops','$argon2id$v=19$m=65536,t=3,p=4$YrygU8YICvEpgSWxVQqs2g$0L0kMXEfYk8NbcCdASME7JDPBx5mJSPQ6B05Fe2ZQC4',20,0,'2026-11-03 01:07:32.655452',NULL);
INSERT INTO "users" VALUES(3,'viewer','$argon2id$v=19$m=65536,t=3,p=4$b/fcIRFyhTd/xETLygC4DQ$eymtc2EW3f5XXvA6tuRTB82UQCLmnY1xZ8J4WS02a4E',10,0,'2026-11-03 01:07:32.719389',NULL);
INSERT INTO "users" VALUES(4,'second','$argon2id$v=19$m=65536,t=3,p=4$7ja5MsSC5HiBoGrN+R5vMA$Q4seK58rNKf6OsxhxsE+xR0x9MAz1sAyya0UaE+1I+g',30,0,'2026-11-03 01:07:32.785478',NULL);
CREATE INDEX ix_sessions_user_id ON sessions (user_id);
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE INDEX ix_backups_job_id ON backups (job_id);
CREATE INDEX ix_backups_storage_target_id ON backups (storage_target_id);
CREATE INDEX ix_runs_job_id ON runs (job_id);
CREATE INDEX ix_runs_status ON runs (status);
CREATE INDEX ix_hooks_host_id ON hooks (host_id);
CREATE INDEX ix_jobs_host_id ON jobs (host_id);
CREATE INDEX ix_jobs_storage_target_id ON jobs (storage_target_id);
CREATE INDEX ix_job_notifications_target_id ON job_notifications (target_id);
CREATE INDEX ix_uploads_user_id ON uploads (user_id);
CREATE INDEX ix_runs_finished_at ON runs (finished_at);
CREATE INDEX ix_audit_events_action_ts ON audit_events (action, ts);
CREATE INDEX ix_job_targets_job_id ON job_targets (job_id);
CREATE INDEX ix_runs_first_run_id ON runs (first_run_id);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('runs',3);
INSERT INTO "sqlite_sequence" VALUES('jobs',2);
INSERT INTO "sqlite_sequence" VALUES('storage_targets',2);
INSERT INTO "sqlite_sequence" VALUES('hosts',2);
INSERT INTO "sqlite_sequence" VALUES('hooks',2);
INSERT INTO "sqlite_sequence" VALUES('notification_targets',1);
INSERT INTO "sqlite_sequence" VALUES('job_targets',1);
INSERT INTO "sqlite_sequence" VALUES('uploads',1);
COMMIT;
