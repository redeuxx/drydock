-- drydock at 399eefd-dirty, alembic revision 0020.
-- Made by python -m tests.upgrade_fixture; secrets use its KEY. Do not edit.
BEGIN TRANSACTION;
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO "alembic_version" VALUES('0020');
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
INSERT INTO "audit_events" VALUES(1,'2026-11-06 06:20:45.588533','admin','203.0.113.5','setup.complete','user:1','success','{"source_ip": "203.0.113.5"}');
INSERT INTO "audit_events" VALUES(2,'2026-11-06 06:20:45.682359','admin','203.0.113.5','user.create','user:2','success','{"role": "operator", "username": "ops"}');
INSERT INTO "audit_events" VALUES(3,'2026-11-06 06:20:45.738614','admin','203.0.113.5','user.create','user:3','success','{"role": "viewer", "username": "viewer"}');
INSERT INTO "audit_events" VALUES(4,'2026-11-06 06:20:45.794774','admin','203.0.113.5','user.create','user:4','success','{"role": "admin", "username": "second"}');
INSERT INTO "audit_events" VALUES(5,'2026-11-06 06:20:45.835163','admin','203.0.113.5','host.create','host:1','success','{"enabled": true, "kind": "local", "name": "local", "target": "tcp://127.0.0.1:9"}');
INSERT INTO "audit_events" VALUES(6,'2026-11-06 06:20:45.865957','admin','203.0.113.5','host.create','host:2','success','{"enabled": true, "identity": "generate", "kind": "ssh", "name": "remote", "target": "backup@203.0.113.9:22"}');
INSERT INTO "audit_events" VALUES(7,'2026-11-06 06:20:45.908334','admin','203.0.113.5','storage.create','storage:1','success','{"enabled": true, "kind": "local", "name": "backups", "path": "/tmp/drydock-upgrade/storage"}');
INSERT INTO "audit_events" VALUES(8,'2026-11-06 06:20:45.949246','admin','203.0.113.5','storage.create','storage:2','success','{"enabled": true, "kind": "webdav", "location": "https://dav.example.com/remote.php/dav", "name": "nas"}');
INSERT INTO "audit_events" VALUES(9,'2026-11-06 06:20:46.001918','admin','203.0.113.5','hook.create','hook:1','success','{"argv": ["pg_dump", "-f", "/srv/dump.sql"], "container": "web", "host_id": 1, "log_output": false, "name": "dump", "project": null, "timeout_s": 300, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(10,'2026-11-06 06:20:46.027144','admin','203.0.113.5','hook.create','hook:2','success','{"argv": ["sync"], "container": "db", "host_id": 1, "log_output": false, "name": "app-flush", "project": "app", "timeout_s": 60, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(11,'2026-11-06 06:20:46.387798','admin','203.0.113.5','notification.create','notification:1','success','{"enabled": true, "kind": "ntfy", "name": "ops"}');
INSERT INTO "audit_events" VALUES(12,'2026-11-06 06:20:46.416662','admin','203.0.113.5','job.create','job:1','success','{"consistency_mode": "stop", "copy_first": false, "cron": "0 3 * * 0", "enabled": true, "encrypted": true, "host_id": 1, "images_reference_only_if_pullable": false, "more_targets": [], "name": "web backup", "notifications": ["ops (success, failure)"], "post_hooks": [], "pre_hooks": ["dump"], "retention": "{\"daily\": 7, \"mode\": \"gfs\", \"monthly\": 12, \"weekly\": 4, \"yearly\": 0}", "scope": "all", "skip_mounts": ["bind:/srv/web-cache"], "storage_target_id": 1, "target": "web", "target_type": "container", "timezone": "Europe/Berlin", "uuid": "79955293-b05f-4b73-b342-d21dd2fadc3a"}');
INSERT INTO "audit_events" VALUES(13,'2026-11-06 06:20:46.438131','admin','203.0.113.5','job.create','job:2','success','{"consistency_mode": "pause", "copy_first": true, "cron": null, "enabled": true, "encrypted": false, "host_id": 1, "images_reference_only_if_pullable": false, "more_targets": ["container worker"], "name": "app stack", "notifications": [], "post_hooks": ["app-flush"], "pre_hooks": [], "retention": "{\"keep_last\": 3, \"mode\": \"last\"}", "scope": "data", "skip_mounts": [], "storage_target_id": 1, "target": "app", "target_type": "stack", "timezone": null, "uuid": "15f058f7-cbf6-4f0d-9325-cae30576f06c"}');
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
INSERT INTO "backups" VALUES(1,1,1,'drydock-web-backup-fixture.tar.zst.age',4096,'0000000000000000000000000000000000000000000000000000000000000000',1,1,'2026-11-06 06:20:46.440436');
CREATE TABLE docker_events (
	id INTEGER NOT NULL, 
	host_id INTEGER NOT NULL, 
	time_ns BIGINT NOT NULL, 
	action VARCHAR(32) NOT NULL, 
	container_id VARCHAR(64) NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	image VARCHAR(255) NOT NULL, 
	exit_code INTEGER, 
	health VARCHAR(16), 
	PRIMARY KEY (id), 
	CONSTRAINT uq_docker_events_event UNIQUE (host_id, time_ns, container_id, action), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE CASCADE
);
INSERT INTO "docker_events" VALUES(1,1,1793815200000000000,'create','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','web','nginx:1.27',NULL,NULL);
INSERT INTO "docker_events" VALUES(2,1,1793815200000000001,'start','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','web','nginx:1.27',NULL,NULL);
INSERT INTO "docker_events" VALUES(3,1,1793815200000000002,'die','ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','web','nginx:1.27',0,NULL);
CREATE TABLE health_acks (
	host_id INTEGER NOT NULL, 
	container_id VARCHAR(64) NOT NULL, 
	acked_at DATETIME NOT NULL, 
	acked_by VARCHAR(64) NOT NULL, 
	PRIMARY KEY (host_id, container_id), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE CASCADE
);
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
INSERT INTO "hooks" VALUES(1,'dump',1,NULL,'web','["pg_dump","-f","/srv/dump.sql"]','','',300,0,'2026-11-06 06:20:46.001595','2026-11-06 06:20:46.001088');
INSERT INTO "hooks" VALUES(2,'app-flush',1,'app','db','["sync"]','','',60,0,'2026-11-06 06:20:46.026956','2026-11-06 06:20:46.026870');
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
	enabled BOOLEAN NOT NULL, alerts_enabled BOOLEAN DEFAULT 0 NOT NULL, alert_target_id INTEGER, 
	CONSTRAINT ck_hosts_kind CHECK (kind IN ('local', 'ssh')), 
	CONSTRAINT ck_hosts_port CHECK (port IS NULL OR port BETWEEN 1 AND 65535), 
	UNIQUE (name)
);
INSERT INTO "hosts" VALUES(1,'local','local','tcp://127.0.0.1:9',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,1,1,1);
INSERT INTO "hosts" VALUES(2,'remote','ssh',NULL,'203.0.113.9',22,'backup','gAAAAABq7XG9E3A444Xd4TbtGa9w0mhy3wTAUwzP6KekRAqBEAzrfe4hbhLII7d9Qicaq9n1XKZ0eG-dSCJHFhMSkh0bnZwI4nIhfqpF276FxuISNw7vgqWWGVHgTtlqZ20YPc5yQt_GHAA7wRsJvOrOr-_yoTF9axkSV1uXxICM56n39mON2YpouyWEqTogXga6nb_Dtb3mZh-BwAGK0PECRSPpR6HLgYpvEb3j18MHuefYSOpuIztxn7Ozjsurj-uwqNE_Kv1nmPp2bHBZANIdvcIqZOlcbAVwcFoTLMf8BPo3KIrcBCQzjx9GeGXyJ35sivPRPYYUvUeM8HlNtCgLiAO3pURgPfvej9zeOJmXTx-1XB3TFkRce5Hm4mDCYpJCKqbwYC6dpbP_E5GSjPeC3YBZDuGlliQozwCyEtrcfpMvqLwCCZRyxKd_BUvwG9CxuUDjOM7_S65GDV8CyD0sp4w_y6Zp1xhQZx2KprC6CKFl0XQiFDacU1NQjr9aGXSggtxGf394_lYR8rh7LY7DgVzeFYfw4fi4E8jY7LuT9OuxsJV_t5U37Cr39WoQfKOwNfsqn4Y8-qjvMeefFuMbGii4D7DgMg==','ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBZ+mN4rj/V5CLAdYkC/Q/dOYdBkQG5rrAWZ/dhUTVpp drydock',NULL,NULL,NULL,'/var/run/docker.sock',NULL,NULL,1,0,NULL);
CREATE TABLE installation (
	id INTEGER NOT NULL, 
	instance_id VARCHAR(32) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_installation_single_row CHECK (id = 1)
);
INSERT INTO "installation" VALUES(1,'14ec36a069744c5bb624ec3c88b082c1');
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
INSERT INTO "job_targets" VALUES(1,2,1,'container','worker','e9b66efe-cb33-4def-b6da-cba9d1cf37ba');
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
	FOREIGN KEY(storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT, 
	UNIQUE (name), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT, 
	UNIQUE (uuid)
);
INSERT INTO "jobs" VALUES(1,'79955293-b05f-4b73-b342-d21dd2fadc3a','web backup',1,1,'container','web','all','stop',0,1,1,'2026-11-06 06:20:46.413902','2026-11-06 06:20:46.413379','[1]','[]','{"daily": 7, "mode": "gfs", "monthly": 12, "weekly": 4, "yearly": 0}','0 3 * * 0','Europe/Berlin',NULL,'["bind:/srv/web-cache"]',0);
INSERT INTO "jobs" VALUES(2,'15f058f7-cbf6-4f0d-9325-cae30576f06c','app stack',1,1,'stack','app','data','pause',0,0,1,'2026-11-06 06:20:46.436558','2026-11-06 06:20:46.436175','[]','[2]','{"keep_last": 3, "mode": "last"}',NULL,NULL,NULL,'[]',1);
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
INSERT INTO "notification_targets" VALUES(1,'ops','ntfy','gAAAAABq7XG-TM_8Ll6MSzNbjiTj86MVcPwzc9kX1cmNLT0X6_fggxMVbyG4FI6q8cSRxImyGq_hY92qpzeh9Fz84p0PngzgVVDjuJBs3wjOs7X7v6PNihQ=',1,'2026-11-06 06:20:46.387316');
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
	restore_originals_json TEXT DEFAULT '{}' NOT NULL, 
	paused_containers_json TEXT DEFAULT '[]' NOT NULL, 
	target_uuid VARCHAR(36), 
	target_label VARCHAR(300), 
	dismissed_at DATETIME, 
	first_run_id INTEGER, 
	CONSTRAINT ck_runs_status CHECK (status IN ('queued', 'verifying', 'awaiting_confirmation', 'running', 'done', 'failed', 'cancelled', 'interrupted')), 
	CONSTRAINT ck_runs_kind CHECK (kind IN ('backup', 'restore', 'update')), 
	FOREIGN KEY(job_id) REFERENCES jobs (id) ON DELETE SET NULL
);
INSERT INTO "runs" VALUES(1,1,'backup','done','the schedule','[]','drydock-web-backup-fixture.tar.zst.age',4096,NULL,NULL,'2026-11-06 06:20:46.441199','2026-11-06 06:15:46.439839','2026-11-06 06:16:46.439839',NULL,'{}','[]',NULL,NULL,NULL,NULL);
INSERT INTO "runs" VALUES(2,2,'backup','failed','ops','[]',NULL,NULL,NULL,'The host is unreachable.','2026-11-06 06:20:46.441201','2026-11-06 06:17:46.439839','2026-11-06 06:17:46.439839',NULL,'{}','[]',NULL,NULL,NULL,NULL);
INSERT INTO "runs" VALUES(3,NULL,'restore','done','admin','[]','drydock-web-backup-fixture.tar.zst.age',NULL,NULL,NULL,'2026-11-06 06:20:46.441685','2026-11-06 06:18:46.439839','2026-11-06 06:19:46.439839','{}','{}','[]',NULL,NULL,NULL,NULL);
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
INSERT INTO "sessions" VALUES(1,'63b10a7d3d672059ff858dd91f758d1c2cce3e120f4a0fb5c45d93233548136e',1,'vF7sIFOZSUJkz9Cnq-sgq_szXNNOrZwSZqBvnyg0d3M','203.0.113.5','2026-11-06 06:20:45.589076','2026-11-06 06:20:46.434520','2026-11-06 18:20:45.589076','2026-11-06 06:20:45.589076');
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
INSERT INTO "storage_targets" VALUES(1,'backups','local','gAAAAABq7XG9SKoR0Rf_EA47t0wtGxtithUd_z4gl6BJiDcE3dTBxLeQzHYRszhHmQO3cNJrw8R3sURY5VujX1-9ZvJQ_wcrbQRQZiPLcSi9a6PTjZAo7Y1vOxokkD_ZpZwTwIKFh6vQ',1,'2026-11-06 06:20:45.907846');
INSERT INTO "storage_targets" VALUES(2,'nas','webdav','gAAAAABq7XG9JRFCsC4anBmFbnKlhNjCtrhmdunsUCrWD-kdF3PnmF1DyoNyF43zoTnfX6q9Oca-tR2pbsIHgM11UGSMzLwG5-qqInj6MQbOd-i6eWGeCL54uqhjH8S0S0dGOZriL-VrGRAJ4k_YCSfDzjgx7SQMXmKpgxLk1QXAVIgLeCLojG5ihbHIwkAHcMFMGQJn5pDby2U2y5KosjgZgg3T_xsiJ9HxPU8kIXR8hhqVjeXeHzpjguy-X9Pc_wwVq3PDo1LbtjPvIvDfb4qV-4ARhGe0Kg==',1,'2026-11-06 06:20:45.948906');
CREATE TABLE update_policies (
	id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 
	name VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	host_id INTEGER NOT NULL, 
	target_type VARCHAR(16) NOT NULL, 
	target VARCHAR(255) NOT NULL, 
	cron VARCHAR(100) NOT NULL, 
	timezone VARCHAR(64), 
	backup_job_id INTEGER, 
	stop_on_failed_backup BOOLEAN NOT NULL, 
	notify_target_id INTEGER, 
	notify_success BOOLEAN NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	last_fired_at DATETIME, 
	created_at DATETIME NOT NULL, 
	updated_at DATETIME NOT NULL, 
	CONSTRAINT ck_update_policies_target_type CHECK (target_type IN ('container', 'stack')), 
	UNIQUE (name), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT, 
	FOREIGN KEY(backup_job_id) REFERENCES jobs (id) ON DELETE SET NULL, 
	FOREIGN KEY(notify_target_id) REFERENCES notification_targets (id) ON DELETE SET NULL
);
INSERT INTO "update_policies" VALUES(1,'web weekly',1,'container','web','0 4 * * 0','Europe/Berlin',1,1,1,1,1,NULL,'2026-11-06 06:20:46.444376','2026-11-06 06:20:46.444377');
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
INSERT INTO "uploads" VALUES(1,1,'drydock-web-backup-fixture.tar.zst.age',4096,4096,'/data/staging/uploads/fixture','complete','2026-11-06 06:20:46.442142','2126-10-13 06:20:46.439839');
CREATE TABLE users (
	id INTEGER NOT NULL, 
	username VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role INTEGER NOT NULL, 
	disabled BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, feed_read_at DATETIME, hosts_collapsed BOOLEAN DEFAULT 0 NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_users_role CHECK (role IN (10, 20, 30, 40)), 
	UNIQUE (username)
);
INSERT INTO "users" VALUES(1,'admin','$argon2id$v=19$m=65536,t=3,p=4$4/u1WKgDWDu8MR7ivN/jjg$/LSNjmdxrqlp70EtTErc1sG+TcA/5Wz0wdfMkV58FHc',40,0,'2026-11-06 06:20:45.587371',NULL,0);
INSERT INTO "users" VALUES(2,'ops','$argon2id$v=19$m=65536,t=3,p=4$UOwARp3CMNuYtwHeyGeZeg$ah5IFkdVNUvI868WXv/ar/+sc6TnLnM6WcLvqKYnCxM',20,0,'2026-11-06 06:20:45.682057',NULL,0);
INSERT INTO "users" VALUES(3,'viewer','$argon2id$v=19$m=65536,t=3,p=4$8zq22TE1IV/JQxsVEma0Gw$RE8Nh9ZAclDE5c97Si0Q16OnF9rUenYKaHm6eRXbeD8',10,0,'2026-11-06 06:20:45.738264',NULL,0);
INSERT INTO "users" VALUES(4,'second','$argon2id$v=19$m=65536,t=3,p=4$ZnsfdKZwnKj+0zERkB4E/g$/RvvBwQPgBSPGH40yc50sI7YmZHN28avsFblEvFPjdI',30,0,'2026-11-06 06:20:45.794473',NULL,0);
CREATE INDEX ix_sessions_user_id ON sessions (user_id);
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE INDEX ix_backups_job_id ON backups (job_id);
CREATE INDEX ix_backups_storage_target_id ON backups (storage_target_id);
CREATE INDEX ix_hooks_host_id ON hooks (host_id);
CREATE INDEX ix_jobs_host_id ON jobs (host_id);
CREATE INDEX ix_jobs_storage_target_id ON jobs (storage_target_id);
CREATE INDEX ix_job_notifications_target_id ON job_notifications (target_id);
CREATE INDEX ix_uploads_user_id ON uploads (user_id);
CREATE INDEX ix_audit_events_action_ts ON audit_events (action, ts);
CREATE INDEX ix_job_targets_job_id ON job_targets (job_id);
CREATE INDEX ix_docker_events_time ON docker_events (time_ns, id);
CREATE INDEX ix_runs_finished_at ON runs (finished_at);
CREATE INDEX ix_runs_job_id ON runs (job_id);
CREATE INDEX ix_runs_first_run_id ON runs (first_run_id);
CREATE INDEX ix_runs_status ON runs (status);
CREATE INDEX ix_update_policies_host_id ON update_policies (host_id);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('jobs',2);
INSERT INTO "sqlite_sequence" VALUES('storage_targets',2);
INSERT INTO "sqlite_sequence" VALUES('runs',3);
INSERT INTO "sqlite_sequence" VALUES('hosts',2);
INSERT INTO "sqlite_sequence" VALUES('hooks',2);
INSERT INTO "sqlite_sequence" VALUES('notification_targets',1);
INSERT INTO "sqlite_sequence" VALUES('job_targets',1);
INSERT INTO "sqlite_sequence" VALUES('uploads',1);
INSERT INTO "sqlite_sequence" VALUES('update_policies',1);
COMMIT;
