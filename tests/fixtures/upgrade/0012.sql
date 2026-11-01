-- drydock after bc7152a (feed), alembic revision 0012.
-- Made by python -m tests.upgrade_fixture; secrets use its KEY. Do not edit.
BEGIN TRANSACTION;
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO "alembic_version" VALUES('0012');
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
INSERT INTO "audit_events" VALUES(1,'2026-11-01 15:49:34.868703','admin','203.0.113.5','setup.complete','user:1','success','{"source_ip": "203.0.113.5"}');
INSERT INTO "audit_events" VALUES(2,'2026-11-01 15:49:34.971744','admin','203.0.113.5','user.create','user:2','success','{"role": "operator", "username": "ops"}');
INSERT INTO "audit_events" VALUES(3,'2026-11-01 15:49:35.032117','admin','203.0.113.5','user.create','user:3','success','{"role": "viewer", "username": "viewer"}');
INSERT INTO "audit_events" VALUES(4,'2026-11-01 15:49:35.092758','admin','203.0.113.5','user.create','user:4','success','{"role": "admin", "username": "second"}');
INSERT INTO "audit_events" VALUES(5,'2026-11-01 15:49:35.133948','admin','203.0.113.5','host.create','host:1','success','{"enabled": true, "kind": "local", "name": "local", "target": "tcp://127.0.0.1:9"}');
INSERT INTO "audit_events" VALUES(6,'2026-11-01 15:49:35.157694','admin','203.0.113.5','host.create','host:2','success','{"enabled": true, "identity": "generate", "kind": "ssh", "name": "remote", "target": "backup@203.0.113.9:22"}');
INSERT INTO "audit_events" VALUES(7,'2026-11-01 15:49:35.196849','admin','203.0.113.5','storage.create','storage:1','success','{"enabled": true, "kind": "local", "name": "backups", "path": "/tmp/drydock-upgrade/storage"}');
INSERT INTO "audit_events" VALUES(8,'2026-11-01 15:49:35.233069','admin','203.0.113.5','storage.create','storage:2','success','{"enabled": true, "kind": "webdav", "location": "https://dav.example.com/remote.php/dav", "name": "nas"}');
INSERT INTO "audit_events" VALUES(9,'2026-11-01 15:49:35.283826','admin','203.0.113.5','hook.create','hook:1','success','{"argv": ["pg_dump", "-f", "/srv/dump.sql"], "container": "web", "host_id": 1, "log_output": false, "name": "dump", "project": null, "timeout_s": 300, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(10,'2026-11-01 15:49:35.305093','admin','203.0.113.5','hook.create','hook:2','success','{"argv": ["sync"], "container": "db", "host_id": 1, "log_output": false, "name": "app-flush", "project": "app", "timeout_s": 60, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(11,'2026-11-01 15:49:35.671245','admin','203.0.113.5','notification.create','notification:1','success','{"enabled": true, "kind": "ntfy", "name": "ops"}');
INSERT INTO "audit_events" VALUES(12,'2026-11-01 15:49:35.708659','admin','203.0.113.5','job.create','job:1','success','{"consistency_mode": "stop", "cron": "0 3 * * 0", "enabled": true, "encrypted": true, "host_id": 1, "images_reference_only_if_pullable": false, "name": "web backup", "notifications": ["ops (success, failure)"], "post_hooks": [], "pre_hooks": ["dump"], "retention": "{\"daily\": 7, \"mode\": \"gfs\", \"monthly\": 12, \"weekly\": 4, \"yearly\": 0}", "scope": "all", "skip_mounts": ["bind:/srv/web-cache"], "storage_target_id": 1, "target": "web", "target_type": "container", "timezone": "Europe/Berlin", "uuid": "056ad039-3a0e-4f79-a47f-d36bf3904edb"}');
INSERT INTO "audit_events" VALUES(13,'2026-11-01 15:49:35.732717','admin','203.0.113.5','job.create','job:2','success','{"consistency_mode": "pause", "cron": null, "enabled": true, "encrypted": false, "host_id": 1, "images_reference_only_if_pullable": false, "name": "app stack", "notifications": [], "post_hooks": ["app-flush"], "pre_hooks": [], "retention": "{\"keep_last\": 3, \"mode\": \"last\"}", "scope": "data", "skip_mounts": [], "storage_target_id": 1, "target": "app", "target_type": "stack", "timezone": null, "uuid": "f64a8352-f475-4362-8fd5-91cd85b6c89f"}');
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
INSERT INTO "backups" VALUES(1,1,1,'drydock-web-backup-fixture.tar.zst.age',4096,'0000000000000000000000000000000000000000000000000000000000000000',1,1,'2026-11-01 15:49:35.735047');
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
INSERT INTO "hooks" VALUES(1,'dump',1,NULL,'web','["pg_dump","-f","/srv/dump.sql"]','','',300,0,'2026-11-01 15:49:35.283306','2026-11-01 15:49:35.282769');
INSERT INTO "hooks" VALUES(2,'app-flush',1,'app','db','["sync"]','','',60,0,'2026-11-01 15:49:35.304806','2026-11-01 15:49:35.304698');
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
INSERT INTO "hosts" VALUES(2,'remote','ssh',NULL,'203.0.113.9',22,'backup','gAAAAABq51-PvAbmKdzULK13642kjItpeW5MFQJjiXRxABAMeF2x9HV8jD-tsLXoi8R1Us-ppC3PImCKKbH5B8PznmXFzrby9OaahyJr6kraI-NHqEKQbRPAdPGyVOGOktdo-mM_akaL_-RxY7nQbV_Bv_ic1en-_zet_BQwHU9ipfLU5iJ9FsfnJye9O6dirYcfuazOYCB3jLmi9U49OJRbsXU3c8gQ9Q1tJ3sDhpOMir8szhs9HaE-xr25G290LZmuCpoj1yn5h5fxzhuq8RANdIkLtyIqpDzeEseXav0F_25PDhoUF0XA1vmN5wu9Wt1UV5wFCWIgrNr6FMVcdwe3dNbfd6_G_S9Dc6TKiGXMf_2iO2Lf_hTqloDhEi3WVA-qnH69b1EvHdmKhl9nKUzAmT0P9F2nt-Ta5UoUTTEA5uq-Oq9_c9zWZc88XMm0ryl4SiF2Bko6UUIw9LInAO4DUvlvh73vVpK1RgcQV7_2PbJnbiTZL3CcnBz_eenbVXQ6TBCMSGWO6QOXy1jUP5x5VPWHT02fB1xEgQDMA7heWiHQBcTPCZMQFnU4NiQP3CzP_BE1T--y5y2C0fRwgAXkkB-ee5aFmg==','ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILyNc47AosmuAvu/CSa4iMlAE+Zi4TtR+baNs8Ezidp8 drydock',NULL,NULL,NULL,'/var/run/docker.sock',NULL,NULL,1);
CREATE TABLE installation (
	id INTEGER NOT NULL, 
	instance_id VARCHAR(32) NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_installation_single_row CHECK (id = 1)
);
INSERT INTO "installation" VALUES(1,'c3078906b9d8443aaf43c6a65d2a2578');
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
	post_hooks TEXT DEFAULT '[]' NOT NULL, retention TEXT DEFAULT '{"keep_last": 7, "mode": "last"}' NOT NULL, cron VARCHAR(100), timezone VARCHAR(64), last_fired_at DATETIME, skip_mounts TEXT DEFAULT '[]' NOT NULL, 
	CONSTRAINT ck_jobs_scope CHECK (scope IN ('config', 'data', 'image', 'all')), 
	CONSTRAINT ck_jobs_target_type CHECK (target_type IN ('container', 'stack')), 
	CONSTRAINT ck_jobs_consistency CHECK (consistency_mode IN ('stop', 'pause', 'live')), 
	UNIQUE (name), 
	FOREIGN KEY(storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT, 
	UNIQUE (uuid), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT
);
INSERT INTO "jobs" VALUES(1,'056ad039-3a0e-4f79-a47f-d36bf3904edb','web backup',1,1,'container','web','all','stop',0,1,1,'2026-11-01 15:49:35.706450','2026-11-01 15:49:35.705981','[1]','[]','{"daily": 7, "mode": "gfs", "monthly": 12, "weekly": 4, "yearly": 0}','0 3 * * 0','Europe/Berlin',NULL,'["bind:/srv/web-cache"]');
INSERT INTO "jobs" VALUES(2,'f64a8352-f475-4362-8fd5-91cd85b6c89f','app stack',1,1,'stack','app','data','pause',0,0,1,'2026-11-01 15:49:35.731912','2026-11-01 15:49:35.731464','[]','[2]','{"keep_last": 3, "mode": "last"}',NULL,NULL,NULL,'[]');
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
INSERT INTO "notification_targets" VALUES(1,'ops','ntfy','gAAAAABq51-P2Kehm-sxrqKH9egBMmwRjkZijA0f1qKSsp-8L4pGWjIe3kWQn0azGiCgYCUjb7mTL0G8YitDyUiKIImktTKKfGjyACIO0GwoYiY_5oF4SJE=',1,'2026-11-01 15:49:35.670837');
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
INSERT INTO "runs" VALUES(1,1,'backup','done','the schedule','[]','drydock-web-backup-fixture.tar.zst.age',4096,NULL,NULL,'2026-11-01 15:49:35.735618','2026-11-01 15:44:35.734246','2026-11-01 15:45:35.734246',NULL,'{}','[]');
INSERT INTO "runs" VALUES(2,2,'backup','failed','ops','[]',NULL,NULL,NULL,'The host is unreachable.','2026-11-01 15:49:35.735619','2026-11-01 15:46:35.734246','2026-11-01 15:46:35.734246',NULL,'{}','[]');
INSERT INTO "runs" VALUES(3,NULL,'restore','done','admin','[]','drydock-web-backup-fixture.tar.zst.age',NULL,NULL,NULL,'2026-11-01 15:49:35.736118','2026-11-01 15:47:35.734246','2026-11-01 15:48:35.734246','{}','{}','[]');
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
INSERT INTO "sessions" VALUES(1,'c158de12ac5627195b86c61a9a4f7cc7f6aa00dcf87bbbf4962702829ddc4179',1,'gu8_M_mfOLyv7kp_D9Brud7p_eOEeC3eaLdaFFey69I','203.0.113.5','2026-11-01 15:49:34.869389','2026-11-01 15:49:35.729422','2026-11-02 03:49:34.869389','2026-11-01 15:49:34.869389');
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
INSERT INTO "storage_targets" VALUES(1,'backups','local','gAAAAABq51-P-L2Rc-loLr6oMXTSjhlKfhGkpnngW4VqeoHBRoY6bq9YfqBt2-8UTIeWXrZC92bfkscoN9ReAJ1htTHQBqUkd8Lp1IQM2ww_j3gwnSccX5dGl2dKWLPJLaBAYK8rCH-J',1,'2026-11-01 15:49:35.196453');
INSERT INTO "storage_targets" VALUES(2,'nas','webdav','gAAAAABq51-PRjTAOwrfJRveSahKeDpCCKt08yx9KkxhmHUZ0RfzxYLIMFlxBvA4TrQlwRgvy3kozijoE2u88nwHGuXL6w55R7IZ10QIftNP7xIRR2TWo3-Rg9xbMAtCuTDV-uxk-QIlvYptojArCP-Zshh0oZO7rezr9rhwoqz2p4c_SUHn9nW3RU6IUR-aucEFnih93Q-fZFXWTA38sC5ijAA7AbuGWHkxinj-VZL-IVIEZYTWzHtljxDXr3hG4jaku7gGb2rwivRHrIKhcbZTC4MDXUEy4Q==',1,'2026-11-01 15:49:35.232758');
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
INSERT INTO "uploads" VALUES(1,1,'drydock-web-backup-fixture.tar.zst.age',4096,4096,'/data/staging/uploads/fixture','complete','2026-11-01 15:49:35.736493','2126-10-08 15:49:35.734246');
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
INSERT INTO "users" VALUES(1,'admin','$argon2id$v=19$m=65536,t=3,p=4$NFm82FD4dy+cUgsQzyZHtA$gzkiZSWvB5+TKvNSAAYD3GEZGE5gyTShFbUV2qbft9U',40,0,'2026-11-01 15:49:34.867832',NULL);
INSERT INTO "users" VALUES(2,'ops','$argon2id$v=19$m=65536,t=3,p=4$5GkLQgfVLb0f32NyEUKMbQ$ygLf2TXdHd1pgn20HkkNj8Di7xV+6pD1WDLEBZh9WEU',20,0,'2026-11-01 15:49:34.971439',NULL);
INSERT INTO "users" VALUES(3,'viewer','$argon2id$v=19$m=65536,t=3,p=4$JL9UyKaYQGhlsy4wSB4njA$eifepYaxvE8H4ZKzoiTFcRJ5gULkgzQjDZXX8q1q0A4',10,0,'2026-11-01 15:49:35.031833',NULL);
INSERT INTO "users" VALUES(4,'second','$argon2id$v=19$m=65536,t=3,p=4$PRVzvPWrtPSvoaU3b2ZhFg$I4rYJ3W/yNb+BTTo5/B6tuDozXutKxR/moKehMQy8Ys',30,0,'2026-11-01 15:49:35.092498',NULL);
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
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('runs',3);
INSERT INTO "sqlite_sequence" VALUES('jobs',2);
INSERT INTO "sqlite_sequence" VALUES('storage_targets',2);
INSERT INTO "sqlite_sequence" VALUES('hosts',2);
INSERT INTO "sqlite_sequence" VALUES('hooks',2);
INSERT INTO "sqlite_sequence" VALUES('notification_targets',1);
INSERT INTO "sqlite_sequence" VALUES('uploads',1);
COMMIT;
