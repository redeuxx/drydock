-- drydock at c4a6873, alembic revision 0014.
-- Made by python -m tests.upgrade_fixture; secrets use its KEY. Do not edit.
BEGIN TRANSACTION;
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO "alembic_version" VALUES('0014');
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
INSERT INTO "audit_events" VALUES(1,'2026-11-02 04:55:23.068698','admin','203.0.113.5','setup.complete','user:1','success','{"source_ip": "203.0.113.5"}');
INSERT INTO "audit_events" VALUES(2,'2026-11-02 04:55:23.175180','admin','203.0.113.5','user.create','user:2','success','{"role": "operator", "username": "ops"}');
INSERT INTO "audit_events" VALUES(3,'2026-11-02 04:55:23.235261','admin','203.0.113.5','user.create','user:3','success','{"role": "viewer", "username": "viewer"}');
INSERT INTO "audit_events" VALUES(4,'2026-11-02 04:55:23.295799','admin','203.0.113.5','user.create','user:4','success','{"role": "admin", "username": "second"}');
INSERT INTO "audit_events" VALUES(5,'2026-11-02 04:55:23.335312','admin','203.0.113.5','host.create','host:1','success','{"enabled": true, "kind": "local", "name": "local", "target": "tcp://127.0.0.1:9"}');
INSERT INTO "audit_events" VALUES(6,'2026-11-02 04:55:23.358600','admin','203.0.113.5','host.create','host:2','success','{"enabled": true, "identity": "generate", "kind": "ssh", "name": "remote", "target": "backup@203.0.113.9:22"}');
INSERT INTO "audit_events" VALUES(7,'2026-11-02 04:55:23.397310','admin','203.0.113.5','storage.create','storage:1','success','{"enabled": true, "kind": "local", "name": "backups", "path": "/tmp/drydock-upgrade/storage"}');
INSERT INTO "audit_events" VALUES(8,'2026-11-02 04:55:23.432948','admin','203.0.113.5','storage.create','storage:2','success','{"enabled": true, "kind": "webdav", "location": "https://dav.example.com/remote.php/dav", "name": "nas"}');
INSERT INTO "audit_events" VALUES(9,'2026-11-02 04:55:23.482153','admin','203.0.113.5','hook.create','hook:1','success','{"argv": ["pg_dump", "-f", "/srv/dump.sql"], "container": "web", "host_id": 1, "log_output": false, "name": "dump", "project": null, "timeout_s": 300, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(10,'2026-11-02 04:55:23.503251','admin','203.0.113.5','hook.create','hook:2','success','{"argv": ["sync"], "container": "db", "host_id": 1, "log_output": false, "name": "app-flush", "project": "app", "timeout_s": 60, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(11,'2026-11-02 04:55:23.941360','admin','203.0.113.5','notification.create','notification:1','success','{"enabled": true, "kind": "ntfy", "name": "ops"}');
INSERT INTO "audit_events" VALUES(12,'2026-11-02 04:55:23.979615','admin','203.0.113.5','job.create','job:1','success','{"consistency_mode": "stop", "copy_first": false, "cron": "0 3 * * 0", "enabled": true, "encrypted": true, "host_id": 1, "images_reference_only_if_pullable": false, "more_targets": [], "name": "web backup", "notifications": ["ops (success, failure)"], "post_hooks": [], "pre_hooks": ["dump"], "retention": "{\"daily\": 7, \"mode\": \"gfs\", \"monthly\": 12, \"weekly\": 4, \"yearly\": 0}", "scope": "all", "skip_mounts": ["bind:/srv/web-cache"], "storage_target_id": 1, "target": "web", "target_type": "container", "timezone": "Europe/Berlin", "uuid": "dc288a06-f7f7-4187-849a-17effbac1000"}');
INSERT INTO "audit_events" VALUES(13,'2026-11-02 04:55:24.004332','admin','203.0.113.5','job.create','job:2','success','{"consistency_mode": "pause", "copy_first": true, "cron": null, "enabled": true, "encrypted": false, "host_id": 1, "images_reference_only_if_pullable": false, "more_targets": ["container worker"], "name": "app stack", "notifications": [], "post_hooks": ["app-flush"], "pre_hooks": [], "retention": "{\"keep_last\": 3, \"mode\": \"last\"}", "scope": "data", "skip_mounts": [], "storage_target_id": 1, "target": "app", "target_type": "stack", "timezone": null, "uuid": "26869db5-a620-43b3-b2bf-ae8221ba7149"}');
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
INSERT INTO "backups" VALUES(1,1,1,'drydock-web-backup-fixture.tar.zst.age',4096,'0000000000000000000000000000000000000000000000000000000000000000',1,1,'2026-11-02 04:55:24.006543');
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
INSERT INTO "hooks" VALUES(1,'dump',1,NULL,'web','["pg_dump","-f","/srv/dump.sql"]','','',300,0,'2026-11-02 04:55:23.481826','2026-11-02 04:55:23.481314');
INSERT INTO "hooks" VALUES(2,'app-flush',1,'app','db','["sync"]','','',60,0,'2026-11-02 04:55:23.503051','2026-11-02 04:55:23.502952');
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
INSERT INTO "hosts" VALUES(2,'remote','ssh',NULL,'203.0.113.9',22,'backup','gAAAAABq6Be7V40cZgf07yzKSPn_qzUD2qp9Einhe-TgSflrgfzwvLs2ghSZI1rQJJA3Cet6mP4M8n8T7ZKzSQrnBy_eoVa_BQf-XOGGIecisHX59zNXgcv4MJ1bvypSg4tl9WX2dnnwKVmNpoAd1DVi5YAYLwmZPA5BOL0vmZ7er1llPxDIp6ZD9b0BemXAzsNfddY3Wyaqp4OtDHRrODMhxFSci8j_LPRNgNJiWVh-eS-6yXx3-TOqzlKSM8dZikb9VVe9ii7JhCyrfMNr3efLQG4-Og2ZZnXyWjt7hT6xjvHUbM77ez2V7Zd_RsIXzlPSQ1X4n5ScfVZiaD79s1zrr69j9Np7W87oQAO0ExP2_Z_1BSVMybBeqSBbB7Pjl-vBjwI_RKwNposaPJWKCsQJ7lsGotO3fZS0uRnVbWw8CEUPXPqSOQMsQ9lkEEMwrIv0svcU7l74BGYcsLxD8fLldvbKjr3cWHNXX9UZoZGAw71g2cP-gTvGVZGwd_LUxXRv7xn58N4GxuvED8HlnHeNg-m-HnuXPgQuLkCdgfBPkfGnJuiiWMrA8wgJjmx6Lm7M6u-wN4n7702qQwehe3WCIbIGZkVcCA==','ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILyFTYF98bzv4YEGhVjDD4kPAKrHuKIxW+USCqAQuUoQ drydock',NULL,NULL,NULL,'/var/run/docker.sock',NULL,NULL,1);
CREATE TABLE installation (
	id INTEGER NOT NULL, 
	instance_id VARCHAR(32) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_installation_single_row CHECK (id = 1)
);
INSERT INTO "installation" VALUES(1,'c588da43075e4d2ca9798fd254f59800');
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
INSERT INTO "job_targets" VALUES(1,2,1,'container','worker','d7c70fcb-5752-40c1-9ab3-172a9a06f469');
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
	UNIQUE (name), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT, 
	FOREIGN KEY(storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT, 
	UNIQUE (uuid)
);
INSERT INTO "jobs" VALUES(1,'dc288a06-f7f7-4187-849a-17effbac1000','web backup',1,1,'container','web','all','stop',0,1,1,'2026-11-02 04:55:23.977044','2026-11-02 04:55:23.976502','[1]','[]','{"daily": 7, "mode": "gfs", "monthly": 12, "weekly": 4, "yearly": 0}','0 3 * * 0','Europe/Berlin',NULL,'["bind:/srv/web-cache"]',0);
INSERT INTO "jobs" VALUES(2,'26869db5-a620-43b3-b2bf-ae8221ba7149','app stack',1,1,'stack','app','data','pause',0,0,1,'2026-11-02 04:55:24.002745','2026-11-02 04:55:24.002355','[]','[2]','{"keep_last": 3, "mode": "last"}',NULL,NULL,NULL,'[]',1);
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
INSERT INTO "notification_targets" VALUES(1,'ops','ntfy','gAAAAABq6Be7Zq7iutuCofIiG4x5uX9RvO05bc5i0OsKh7jOBwAVjQrMn1SIKcpDaT9UNPw2ZLNlRJJ27qap47M07LrDCCOUcYnEU5Y-uQqS5FSiFVSwW2w=',1,'2026-11-02 04:55:23.940927');
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
	restore_originals_json TEXT DEFAULT '{}' NOT NULL, paused_containers_json TEXT DEFAULT '[]' NOT NULL, target_uuid VARCHAR(36), target_label VARCHAR(300), 
	CONSTRAINT ck_runs_kind CHECK (kind IN ('backup', 'restore')), 
	CONSTRAINT ck_runs_status CHECK (status IN ('queued', 'verifying', 'awaiting_confirmation', 'running', 'done', 'failed', 'cancelled', 'interrupted')), 
	FOREIGN KEY(job_id) REFERENCES jobs (id) ON DELETE SET NULL
);
INSERT INTO "runs" VALUES(1,1,'backup','done','the schedule','[]','drydock-web-backup-fixture.tar.zst.age',4096,NULL,NULL,'2026-11-02 04:55:24.007063','2026-11-02 04:50:24.005836','2026-11-02 04:51:24.005836',NULL,'{}','[]',NULL,NULL);
INSERT INTO "runs" VALUES(2,2,'backup','failed','ops','[]',NULL,NULL,NULL,'The host is unreachable.','2026-11-02 04:55:24.007064','2026-11-02 04:52:24.005836','2026-11-02 04:52:24.005836',NULL,'{}','[]',NULL,NULL);
INSERT INTO "runs" VALUES(3,NULL,'restore','done','admin','[]','drydock-web-backup-fixture.tar.zst.age',NULL,NULL,NULL,'2026-11-02 04:55:24.007497','2026-11-02 04:53:24.005836','2026-11-02 04:54:24.005836','{}','{}','[]',NULL,NULL);
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
INSERT INTO "sessions" VALUES(1,'c8719907c9ddf7eeff3f5bcc95530e69fc5b19cddee1a63e4fd11b39a1d8d653',1,'GYGt2d64m7wNt4tcW_eXmoeL8_hP4FlpSCTj70V8Yy8','203.0.113.5','2026-11-02 04:55:23.069437','2026-11-02 04:55:24.000622','2026-11-02 16:55:23.069437','2026-11-02 04:55:23.069437');
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
INSERT INTO "storage_targets" VALUES(1,'backups','local','gAAAAABq6Be7zov1HECqMCmG8MBDTGPV-wsRf2_8WBr2OugesGF5O5N8sIyR7DqEUU8MXXKmAHaKlVA1A6iJa3Uvt0Ht-wO69LrEoLOdQksjkYrBmcMznTib6df0jCxkLfsrKC2UwN0H',1,'2026-11-02 04:55:23.396939');
INSERT INTO "storage_targets" VALUES(2,'nas','webdav','gAAAAABq6Be7WclohyAileTzSM9rTnzJe9wW4tfnwZP6_Tgjl6ePsINlV9bNTIk1oehDiIqOTYxCGFp9SPmy4w0_8waDS3qQQMA8aA0P0Iq7adk9ACzyQA9EUBgfIP1QBMDqC59OkH3MXhc28iJ6pzhqFaMIT__UykUmiz3XcwpS9czCQoPoOQqwGC7ok7Mi5jEjSj3GdxbVCtqxvH8QWQbBLIX1FpR7ZCD_yEgwjln1CNpXosD5iJbCADbmay0GHStwqi1Fj7xn8scDvdLWBX7iPjRVD_hYOw==',1,'2026-11-02 04:55:23.432608');
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
INSERT INTO "uploads" VALUES(1,1,'drydock-web-backup-fixture.tar.zst.age',4096,4096,'/data/staging/uploads/fixture','complete','2026-11-02 04:55:24.007862','2126-10-09 04:55:24.005836');
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
INSERT INTO "users" VALUES(1,'admin','$argon2id$v=19$m=65536,t=3,p=4$e00ck/qywqwX6z8I50tu5g$V3iPZRtKnCXBQbAL2EZe/wJCUMqUBSS7DuokNeaxpgs',40,0,'2026-11-02 04:55:23.067636',NULL);
INSERT INTO "users" VALUES(2,'ops','$argon2id$v=19$m=65536,t=3,p=4$PiEHg/RDfoRonKspQePRtA$NWXTBd/P7cD4Br4HBIb967F8i1F12fY1suyrvB4aEY8',20,0,'2026-11-02 04:55:23.174885',NULL);
INSERT INTO "users" VALUES(3,'viewer','$argon2id$v=19$m=65536,t=3,p=4$SjIiXh/mTNSV7bqVtlbLlQ$ktIvaZcOoaN7k/XOFwir0TtwVGyiyRe9TOAT1qbvET0',10,0,'2026-11-02 04:55:23.234999',NULL);
INSERT INTO "users" VALUES(4,'second','$argon2id$v=19$m=65536,t=3,p=4$3RHZZFycbcfEGWEqD/2sEw$9UF0Qa2Me66oCMJWMvMBm7qzlvp4VFNRiu8whGCO2fU',30,0,'2026-11-02 04:55:23.295519',NULL);
CREATE INDEX ix_sessions_user_id ON sessions (user_id);
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE INDEX ix_backups_job_id ON backups (job_id);
CREATE INDEX ix_backups_storage_target_id ON backups (storage_target_id);
CREATE INDEX ix_runs_job_id ON runs (job_id);
CREATE INDEX ix_runs_status ON runs (status);
CREATE INDEX ix_hooks_host_id ON hooks (host_id);
CREATE INDEX ix_jobs_storage_target_id ON jobs (storage_target_id);
CREATE INDEX ix_jobs_host_id ON jobs (host_id);
CREATE INDEX ix_job_notifications_target_id ON job_notifications (target_id);
CREATE INDEX ix_uploads_user_id ON uploads (user_id);
CREATE INDEX ix_runs_finished_at ON runs (finished_at);
CREATE INDEX ix_audit_events_action_ts ON audit_events (action, ts);
CREATE INDEX ix_job_targets_job_id ON job_targets (job_id);
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
