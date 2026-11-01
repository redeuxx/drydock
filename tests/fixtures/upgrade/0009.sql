-- drydock at 035b27b, alembic revision 0009.
-- Made by python -m tests.upgrade_fixture; secrets use its KEY. Do not edit.
BEGIN TRANSACTION;
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO "alembic_version" VALUES('0009');
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
INSERT INTO "audit_events" VALUES(1,'2026-11-01 02:32:28.883347','admin','203.0.113.5','setup.complete','user:1','success','{"source_ip": "203.0.113.5"}');
INSERT INTO "audit_events" VALUES(2,'2026-11-01 02:32:28.992597','admin','203.0.113.5','user.create','user:2','success','{"role": "operator", "username": "ops"}');
INSERT INTO "audit_events" VALUES(3,'2026-11-01 02:32:29.052757','admin','203.0.113.5','user.create','user:3','success','{"role": "viewer", "username": "viewer"}');
INSERT INTO "audit_events" VALUES(4,'2026-11-01 02:32:29.115226','admin','203.0.113.5','user.create','user:4','success','{"role": "admin", "username": "second"}');
INSERT INTO "audit_events" VALUES(5,'2026-11-01 02:32:29.155211','admin','203.0.113.5','host.create','host:1','success','{"enabled": true, "kind": "local", "name": "local", "target": "tcp://127.0.0.1:9"}');
INSERT INTO "audit_events" VALUES(6,'2026-11-01 02:32:29.179711','admin','203.0.113.5','host.create','host:2','success','{"enabled": true, "identity": "generate", "kind": "ssh", "name": "remote", "target": "backup@203.0.113.9:22"}');
INSERT INTO "audit_events" VALUES(7,'2026-11-01 02:32:29.216984','admin','203.0.113.5','storage.create','storage:1','success','{"enabled": true, "kind": "local", "name": "backups", "path": "/tmp/drydock-upgrade/storage"}');
INSERT INTO "audit_events" VALUES(8,'2026-11-01 02:32:29.254093','admin','203.0.113.5','storage.create','storage:2','success','{"enabled": true, "kind": "webdav", "location": "https://dav.example.com/remote.php/dav", "name": "nas"}');
INSERT INTO "audit_events" VALUES(9,'2026-11-01 02:32:29.300430','admin','203.0.113.5','hook.create','hook:1','success','{"argv": ["pg_dump", "-f", "/srv/dump.sql"], "container": "web", "host_id": 1, "log_output": false, "name": "dump", "project": null, "timeout_s": 300, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(10,'2026-11-01 02:32:29.322879','admin','203.0.113.5','hook.create','hook:2','success','{"argv": ["sync"], "container": "db", "host_id": 1, "log_output": false, "name": "app-flush", "project": "app", "timeout_s": 60, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(11,'2026-11-01 02:32:29.700518','admin','203.0.113.5','notification.create','notification:1','success','{"enabled": true, "kind": "ntfy", "name": "ops"}');
INSERT INTO "audit_events" VALUES(12,'2026-11-01 02:32:29.745100','admin','203.0.113.5','job.create','job:1','success','{"consistency_mode": "stop", "cron": "0 3 * * 0", "enabled": true, "encrypted": true, "host_id": 1, "images_reference_only_if_pullable": false, "name": "web backup", "notifications": ["ops (success, failure)"], "post_hooks": [], "pre_hooks": ["dump"], "retention": "{\"daily\": 7, \"mode\": \"gfs\", \"monthly\": 12, \"weekly\": 4, \"yearly\": 0}", "scope": "all", "storage_target_id": 1, "target": "web", "target_type": "container", "timezone": "Europe/Berlin", "uuid": "00c3bad8-0e7a-4146-8bd8-394785abfdb0"}');
INSERT INTO "audit_events" VALUES(13,'2026-11-01 02:32:29.769076','admin','203.0.113.5','job.create','job:2','success','{"consistency_mode": "pause", "cron": null, "enabled": true, "encrypted": false, "host_id": 1, "images_reference_only_if_pullable": false, "name": "app stack", "notifications": [], "post_hooks": ["app-flush"], "pre_hooks": [], "retention": "{\"keep_last\": 3, \"mode\": \"last\"}", "scope": "data", "storage_target_id": 1, "target": "app", "target_type": "stack", "timezone": null, "uuid": "13e2d1a4-5bce-418e-864d-a08aa5770549"}');
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
INSERT INTO "backups" VALUES(1,1,1,'drydock-web-backup-fixture.tar.zst.age',4096,'0000000000000000000000000000000000000000000000000000000000000000',1,1,'2026-11-01 02:32:29.771335');
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
INSERT INTO "hooks" VALUES(1,'dump',1,NULL,'web','["pg_dump","-f","/srv/dump.sql"]','','',300,0,'2026-11-01 02:32:29.300130','2026-11-01 02:32:29.299694');
INSERT INTO "hooks" VALUES(2,'app-flush',1,'app','db','["sync"]','','',60,0,'2026-11-01 02:32:29.322677','2026-11-01 02:32:29.322577');
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
INSERT INTO "hosts" VALUES(2,'remote','ssh',NULL,'203.0.113.9',22,'backup','gAAAAABq5qS90BGMFK8NE9hUG07e2cNpMgcnVZCAVJG0q2WwE90H6HGhZszSe4SvWXcccDwhwoJyIb6EpO5H2hHis_A3hEf13gMYzL3w8Kc_Vb_w7Fs60S80GmytyRzjYxI0Oo-AYtPPsyNY0XoN9n-LrNSvnc8p_yjm73bHuxFDx-vgkLL9T5HOFdiJHvrUapi81pjBP8PRtTXoj9vBbbd-1-x_LV-vJuM8emsIxEM9N3dUTRV9m9bSb5MFcudfxLOKLksKMXc-pjm3cncs_wtI8MzQdSm_Q9JWA0gQ0IjnolahSDntrmaY2jEWzRKzk9VN5lmrcEvnhvsDNH-6ospMf2g_CIotIgpnsT4oDvuOHIzBjr70y8lDbKjJmAN48rDBpUVhHNaotnT9kLvQAJa83J62v_VGQ5HuqIzZnb7r1N8ZxpkKNfHd28R9COZIJ1eVXoIAvkGMIszL_Yj395Q94ur62lfVE78Mytwyq_WACZFxzOLT4xEDWlZNtaHVqnOV6dwx9w91ti0a3rl1Bdvj4fk9hPcRd_c-09d3RVAhkzkr7chue3TQ5M0TDQMyuyZmOsqJhcwF31xhD7XXRPTuZGa5DJ-1NA==','ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMIPBxQmrhakZblENb1h6A+yRtNI5VHbiB9YQilryWC drydock',NULL,NULL,NULL,'/var/run/docker.sock',NULL,NULL,1);
CREATE TABLE installation (
	id INTEGER NOT NULL, 
	instance_id VARCHAR(32) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_installation_single_row CHECK (id = 1)
);
INSERT INTO "installation" VALUES(1,'5d80d1b939994422b46de5936c2e65ab');
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
	post_hooks TEXT DEFAULT '[]' NOT NULL, retention TEXT DEFAULT '{"keep_last": 7, "mode": "last"}' NOT NULL, cron VARCHAR(100), timezone VARCHAR(64), last_fired_at DATETIME, 
	CONSTRAINT ck_jobs_scope CHECK (scope IN ('config', 'data', 'image', 'all')), 
	CONSTRAINT ck_jobs_target_type CHECK (target_type IN ('container', 'stack')), 
	CONSTRAINT ck_jobs_consistency CHECK (consistency_mode IN ('stop', 'pause', 'live')), 
	UNIQUE (name), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT, 
	FOREIGN KEY(storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT, 
	UNIQUE (uuid)
);
INSERT INTO "jobs" VALUES(1,'00c3bad8-0e7a-4146-8bd8-394785abfdb0','web backup',1,1,'container','web','all','stop',0,1,1,'2026-11-01 02:32:29.742365','2026-11-01 02:32:29.741846','[1]','[]','{"daily": 7, "mode": "gfs", "monthly": 12, "weekly": 4, "yearly": 0}','0 3 * * 0','Europe/Berlin',NULL);
INSERT INTO "jobs" VALUES(2,'13e2d1a4-5bce-418e-864d-a08aa5770549','app stack',1,1,'stack','app','data','pause',0,0,1,'2026-11-01 02:32:29.768530','2026-11-01 02:32:29.768427','[]','[2]','{"keep_last": 3, "mode": "last"}',NULL,NULL,NULL);
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
INSERT INTO "notification_targets" VALUES(1,'ops','ntfy','gAAAAABq5qS98t0nEZa16HHzBGrxwmE3Y_Q0SGc1ogXjtK4UfIo9MBsCb7dYJlmHsKd5oZHkH18t1tIj7tYpVwdJ8c_lserMVZ763t0R7goNvEdQ8roD58Y=',1,'2026-11-01 02:32:29.700132');
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
	restore_originals_json TEXT DEFAULT '{}' NOT NULL, paused_containers_json TEXT DEFAULT '[]' NOT NULL, 
	CONSTRAINT ck_runs_kind CHECK (kind IN ('backup', 'restore')), 
	CONSTRAINT ck_runs_status CHECK (status IN ('queued', 'verifying', 'awaiting_confirmation', 'running', 'done', 'failed', 'cancelled', 'interrupted')), 
	FOREIGN KEY(job_id) REFERENCES jobs (id) ON DELETE SET NULL
);
INSERT INTO "runs" VALUES(1,1,'backup','done','the schedule','[]','drydock-web-backup-fixture.tar.zst.age',4096,NULL,NULL,'2026-11-01 02:32:29.771869','2026-11-01 02:27:29.770585','2026-11-01 02:28:29.770585',NULL,'{}','[]');
INSERT INTO "runs" VALUES(2,2,'backup','failed','ops','[]',NULL,NULL,NULL,'The host is unreachable.','2026-11-01 02:32:29.771870','2026-11-01 02:29:29.770585','2026-11-01 02:29:29.770585',NULL,'{}','[]');
INSERT INTO "runs" VALUES(3,NULL,'restore','done','admin','[]','drydock-web-backup-fixture.tar.zst.age',NULL,NULL,NULL,'2026-11-01 02:32:29.772353','2026-11-01 02:30:29.770585','2026-11-01 02:31:29.770585','{}','{}','[]');
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
INSERT INTO "sessions" VALUES(1,'dfd90b109f9a26c7f03673d5625a08b2235b8fa3c0427679c0211a5303a14f9a',1,'SsVWOBjXsQhY8jX9Xrzyse82MDyfP8yPevduYrWmLtw','203.0.113.5','2026-11-01 02:32:28.884213','2026-11-01 02:32:29.766731','2026-11-01 14:32:28.884213','2026-11-01 02:32:28.884213');
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
INSERT INTO "storage_targets" VALUES(1,'backups','local','gAAAAABq5qS9y9j7FcWX319gzzNTEYbExioFJIL_6zUA6I976BiEJThZk-mNlu3EgdzTC-0vzAuixFdpU3kRR-PqyOZFZH2ZSzUjgl7aRsH-DmIL8rDzvdD9Y5718Vo88_KRm-sQUPUy',1,'2026-11-01 02:32:29.216621');
INSERT INTO "storage_targets" VALUES(2,'nas','webdav','gAAAAABq5qS9WDf9TeRJFLz8Oq0bduJOegGDo4acgt9m1klaByZhjJW1OF_RLLwiNbFxjj-dmDNNrdrejbxqbmhTf07hW_i1DxR3Nihob5dwaiMIQRjqn8RDhqe-tQ2hChdFr8qHy3KYPUoYWzXxizJYQ2fGFbYC0F3x_uNu0eY_kkfHO8egqQZKH-dzw96wY0zSqop3Ed2ld7hmj82-Adnh1c7tJczp9SZ8TWj2fD5lLV0WU2UkXQRWvWoIP5aLYyIAQK9W_1af',1,'2026-11-01 02:32:29.253795');
CREATE TABLE users (
	id INTEGER NOT NULL, 
	username VARCHAR(64) COLLATE "NOCASE" NOT NULL, 
	password_hash VARCHAR(255) NOT NULL, 
	role INTEGER NOT NULL, 
	disabled BOOLEAN NOT NULL, 
	created_at DATETIME NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_users_role CHECK (role IN (10, 20, 30, 40)), 
	UNIQUE (username)
);
INSERT INTO "users" VALUES(1,'admin','$argon2id$v=19$m=65536,t=3,p=4$YW2zG42qwkBjafBFEAVOwQ$uVoDqmLCAqLS93wV8IUK2fESdLyia6zneCqaeuf8+mc',40,0,'2026-11-01 02:32:28.882504');
INSERT INTO "users" VALUES(2,'ops','$argon2id$v=19$m=65536,t=3,p=4$1O3AYe2aP2Xx4kBMlgwmHw$gvrKQJnmHQNiyVMijhSG5Bocb/6Zq3ns/vL/nw6nz7U',20,0,'2026-11-01 02:32:28.992341');
INSERT INTO "users" VALUES(3,'viewer','$argon2id$v=19$m=65536,t=3,p=4$ZOw65kLWEqoAa8borpqDyQ$CNmllSJKhVjELXYbH8T0OHoGptNyXn0nEhlbP9WWrV8',10,0,'2026-11-01 02:32:29.052515');
INSERT INTO "users" VALUES(4,'second','$argon2id$v=19$m=65536,t=3,p=4$HBw5K/ha2+sILp5RqStiVg$V9nNoFY7iTTKyYshy/914s5+asKJwkEI5na1BlsRaJE',30,0,'2026-11-01 02:32:29.114861');
CREATE INDEX ix_sessions_user_id ON sessions (user_id);
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE INDEX ix_backups_job_id ON backups (job_id);
CREATE INDEX ix_backups_storage_target_id ON backups (storage_target_id);
CREATE INDEX ix_runs_status ON runs (status);
CREATE INDEX ix_runs_job_id ON runs (job_id);
CREATE INDEX ix_hooks_host_id ON hooks (host_id);
CREATE INDEX ix_jobs_storage_target_id ON jobs (storage_target_id);
CREATE INDEX ix_jobs_host_id ON jobs (host_id);
CREATE INDEX ix_job_notifications_target_id ON job_notifications (target_id);
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('runs',3);
INSERT INTO "sqlite_sequence" VALUES('jobs',2);
INSERT INTO "sqlite_sequence" VALUES('storage_targets',2);
INSERT INTO "sqlite_sequence" VALUES('hosts',2);
INSERT INTO "sqlite_sequence" VALUES('hooks',2);
INSERT INTO "sqlite_sequence" VALUES('notification_targets',1);
COMMIT;
