-- drydock at update policy tags (after d5334d4), alembic revision 0022.
-- Made by python -m tests.upgrade_fixture; secrets use its KEY. Do not edit.
BEGIN TRANSACTION;
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO "alembic_version" VALUES('0022');
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
INSERT INTO "audit_events" VALUES(1,'2026-11-07 18:14:17.352126','admin','203.0.113.5','setup.complete','user:1','success','{"source_ip": "203.0.113.5"}');
INSERT INTO "audit_events" VALUES(2,'2026-11-07 18:14:17.457255','admin','203.0.113.5','user.create','user:2','success','{"role": "operator", "username": "ops"}');
INSERT INTO "audit_events" VALUES(3,'2026-11-07 18:14:17.516918','admin','203.0.113.5','user.create','user:3','success','{"role": "viewer", "username": "viewer"}');
INSERT INTO "audit_events" VALUES(4,'2026-11-07 18:14:17.579204','admin','203.0.113.5','user.create','user:4','success','{"role": "admin", "username": "second"}');
INSERT INTO "audit_events" VALUES(5,'2026-11-07 18:14:17.623173','admin','203.0.113.5','host.create','host:1','success','{"enabled": true, "kind": "local", "name": "local", "target": "tcp://127.0.0.1:9"}');
INSERT INTO "audit_events" VALUES(6,'2026-11-07 18:14:17.650377','admin','203.0.113.5','host.create','host:2','success','{"enabled": true, "identity": "generate", "kind": "ssh", "name": "remote", "target": "backup@203.0.113.9:22"}');
INSERT INTO "audit_events" VALUES(7,'2026-11-07 18:14:17.694575','admin','203.0.113.5','storage.create','storage:1','success','{"enabled": true, "kind": "local", "name": "backups", "path": "/tmp/drydock-upgrade/storage"}');
INSERT INTO "audit_events" VALUES(8,'2026-11-07 18:14:17.733323','admin','203.0.113.5','storage.create','storage:2','success','{"enabled": true, "kind": "webdav", "location": "https://dav.example.com/remote.php/dav", "name": "nas"}');
INSERT INTO "audit_events" VALUES(9,'2026-11-07 18:14:17.786078','admin','203.0.113.5','hook.create','hook:1','success','{"argv": ["pg_dump", "-f", "/srv/dump.sql"], "container": "web", "host_id": 1, "log_output": false, "name": "dump", "project": null, "timeout_s": 300, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(10,'2026-11-07 18:14:17.813502','admin','203.0.113.5','hook.create','hook:2','success','{"argv": ["sync"], "container": "db", "host_id": 1, "log_output": false, "name": "app-flush", "project": "app", "timeout_s": 60, "user": "", "workdir": ""}');
INSERT INTO "audit_events" VALUES(11,'2026-11-07 18:14:18.247206','admin','203.0.113.5','notification.create','notification:1','success','{"enabled": true, "kind": "ntfy", "name": "ops"}');
INSERT INTO "audit_events" VALUES(12,'2026-11-07 18:14:18.288866','admin','203.0.113.5','job.create','job:1','success','{"consistency_mode": "stop", "copy_first": false, "cron": "0 3 * * 0", "enabled": true, "encrypted": true, "host_id": 1, "images_reference_only_if_pullable": false, "more_targets": [], "name": "web backup", "notifications": ["ops (success, failure)"], "post_hooks": [], "pre_hooks": ["dump"], "retention": "{\"daily\": 7, \"mode\": \"gfs\", \"monthly\": 12, \"weekly\": 4, \"yearly\": 0}", "scope": "all", "skip_mounts": ["bind:/srv/web-cache"], "storage_target_id": 1, "target": "web", "target_type": "container", "timezone": "Europe/Berlin", "uuid": "8b25a545-8fbe-41eb-96b6-40c38d37690a"}');
INSERT INTO "audit_events" VALUES(13,'2026-11-07 18:14:18.319361','admin','203.0.113.5','job.create','job:2','success','{"consistency_mode": "pause", "copy_first": true, "cron": null, "enabled": true, "encrypted": false, "host_id": 1, "images_reference_only_if_pullable": false, "more_targets": ["container worker"], "name": "app stack", "notifications": [], "post_hooks": ["app-flush"], "pre_hooks": [], "retention": "{\"keep_last\": 3, \"mode\": \"last\"}", "scope": "data", "skip_mounts": [], "storage_target_id": 1, "target": "app", "target_type": "stack", "timezone": null, "uuid": "d7304da9-6390-47f9-8d55-132b65b2fe28"}');
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
INSERT INTO "backups" VALUES(1,1,1,'drydock-web-backup-fixture.tar.zst.age',4096,'0000000000000000000000000000000000000000000000000000000000000000',1,1,'2026-11-07 18:14:18.321669');
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
INSERT INTO "hooks" VALUES(1,'dump',1,NULL,'web','["pg_dump","-f","/srv/dump.sql"]','','',300,0,'2026-11-07 18:14:17.785719','2026-11-07 18:14:17.785104');
INSERT INTO "hooks" VALUES(2,'app-flush',1,'app','db','["sync"]','','',60,0,'2026-11-07 18:14:17.813248','2026-11-07 18:14:17.813144');
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
INSERT INTO "hosts" VALUES(2,'remote','ssh',NULL,'203.0.113.9',22,'backup','gAAAAABq72p53MjLFOs5WC9CHdnZL4Fao2UzdyRNoh31issETgwTtmbnhaLySkYLoESpHB8XJntExVRhkYvXbSS-LnqIj9iFCCdqE-DdJxZnWirLzgBVJEiUOb_ghkaGVgpXQj1tkhbrJBOX1m1BiF76YoNU2q5JAO9DwG8dj1UAI3V1BRiT3OZkEZxLUPrtLgU-8frPqOXTi9lw5DZbrn8DTZvHeJAOmLhKN_5ExG8WqAPngqgQWDj01nNvJSD_db7UUCfUfl2wEoW7bPBMA4sRnx4g5GLjP-rzGfqqZpp4j90UEbVx5JglGA10HZMX-jjDD6LweHYsarffo5bKcNL0ExKaeORtSEcAchF9XsfdeHgb7V7-Hcpc223Rrad8CSDfAIpsar9vsFPSr0wp71Ca0q0wb-8-DWJDY84BoBhxzgbYIeVGwnBOZPi9Coia9tEHxBDUxNR_QDYTllcrNNvSEj1VT8jr9dyk3NrGSZFkSCgiAkOXuQPdiF1_TPcaZcSXx4ShdALcZBPLVBPqNhJZGhBk77_Ks2o7unappI9nYNPVefHY26Qog_S4kthFc85XoIsNkDOcJ62ckxWHLj-jcNCvnzGhKg==','ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMzBRgmoxYlBh0ZPPuoXXIBfjt4l083ICHP5PXbmPOKF drydock',NULL,NULL,NULL,'/var/run/docker.sock',NULL,NULL,1,0,NULL);
CREATE TABLE installation (
	id INTEGER NOT NULL, 
	instance_id VARCHAR(32) NOT NULL, update_check_hours INTEGER DEFAULT '6' NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT ck_installation_single_row CHECK (id = 1)
);
INSERT INTO "installation" VALUES(1,'13156adfada24845bff69065f070dc63',6);
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
INSERT INTO "job_targets" VALUES(1,2,1,'container','worker','2946b343-cf7f-4c31-90c2-a708b28fa4f4');
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
	UNIQUE (uuid), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT, 
	UNIQUE (name), 
	FOREIGN KEY(storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT
);
INSERT INTO "jobs" VALUES(1,'8b25a545-8fbe-41eb-96b6-40c38d37690a','web backup',1,1,'container','web','all','stop',0,1,1,'2026-11-07 18:14:18.286286','2026-11-07 18:14:18.285624','[1]','[]','{"daily": 7, "mode": "gfs", "monthly": 12, "weekly": 4, "yearly": 0}','0 3 * * 0','Europe/Berlin',NULL,'["bind:/srv/web-cache"]',0);
INSERT INTO "jobs" VALUES(2,'d7304da9-6390-47f9-8d55-132b65b2fe28','app stack',1,1,'stack','app','data','pause',0,0,1,'2026-11-07 18:14:18.316949','2026-11-07 18:14:18.316537','[]','[2]','{"keep_last": 3, "mode": "last"}',NULL,NULL,NULL,'[]',1);
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
INSERT INTO "notification_targets" VALUES(1,'ops','ntfy','gAAAAABq72p63hVv0rQDljKXaZMuRhSw4qYiOV4OzX3flrEToZjX2huQnz90vfcoilXYeU_w139phCLMh_pFpEUewGp7BfZgVe2K-601j7EqhWTP402OwgA=',1,'2026-11-07 18:14:18.246728');
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
INSERT INTO "runs" VALUES(1,1,'backup','done','the schedule','[]','drydock-web-backup-fixture.tar.zst.age',4096,NULL,NULL,'2026-11-07 18:14:18.322217','2026-11-07 18:09:18.321075','2026-11-07 18:10:18.321075',NULL,'{}','[]',NULL,NULL,NULL,NULL);
INSERT INTO "runs" VALUES(2,2,'backup','failed','ops','[]',NULL,NULL,NULL,'The host is unreachable.','2026-11-07 18:14:18.322218','2026-11-07 18:11:18.321075','2026-11-07 18:11:18.321075',NULL,'{}','[]',NULL,NULL,NULL,NULL);
INSERT INTO "runs" VALUES(3,NULL,'restore','done','admin','[]','drydock-web-backup-fixture.tar.zst.age',NULL,NULL,NULL,'2026-11-07 18:14:18.322711','2026-11-07 18:12:18.321075','2026-11-07 18:13:18.321075','{}','{}','[]',NULL,NULL,NULL,NULL);
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
INSERT INTO "sessions" VALUES(1,'075c710b117806c776a1a73f9fab1a0c003fcaa07c677c4e8c3c8531b1055382',1,'ym4mnkTSYBji6uPpR49dlwJ2NxR9BPzaA3Ms9BCn5Zw','203.0.113.5','2026-11-07 18:14:17.352691','2026-11-07 18:14:18.314171','2026-11-08 06:14:17.352691','2026-11-07 18:14:17.352691');
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
INSERT INTO "storage_targets" VALUES(1,'backups','local','gAAAAABq72p5eJEJSXPe9rrT44cr6Wc_jCndFKIB_VHYdikBQlqKikfZhxp0CJrd_Jxhm_dvTWw6cOAN2r2WztsuF6sIGKRSvrLPilu_NqcpwPPDgBREvhECFtyE1-AM4HJGrDHtkfa1',1,'2026-11-07 18:14:17.694209');
INSERT INTO "storage_targets" VALUES(2,'nas','webdav','gAAAAABq72p57Q-oxlkaEQP_1SlvbsrOENaZRdWvgGZ2zAmxXkdsvTo1oFlPIhWEfHrGmlVcnjWd_D-DR-4zlXekbseqY0onsGu9Ldk-9iL2PAW2PzfAIHFuDtI8II_jzR3P2l_qGzNTVYLjy9QC47Qn2NGSGUZDHist0geAku9yOHWg8NA5nG_3cBMv2nJIH1qAgWfnpbwtEZJF4rFlKH8NR8ALtnph0fE2FktJG4x5H6ZNSbky6ewmYydAoYwM5NEl1O5lqF3bFCHyLg-ny5YLgGWsA982Uw==',1,'2026-11-07 18:14:17.733039');
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
	updated_at DATETIME NOT NULL, tag VARCHAR(128), main_service VARCHAR(255), 
	CONSTRAINT ck_update_policies_target_type CHECK (target_type IN ('container', 'stack')), 
	UNIQUE (name), 
	FOREIGN KEY(host_id) REFERENCES hosts (id) ON DELETE RESTRICT, 
	FOREIGN KEY(backup_job_id) REFERENCES jobs (id) ON DELETE SET NULL, 
	FOREIGN KEY(notify_target_id) REFERENCES notification_targets (id) ON DELETE SET NULL
);
INSERT INTO "update_policies" VALUES(1,'web weekly',1,'container','web','0 4 * * 0','Europe/Berlin',1,1,1,1,1,NULL,'2026-11-07 18:14:18.324923','2026-11-07 18:14:18.324925',NULL,NULL);
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
INSERT INTO "uploads" VALUES(1,1,'drydock-web-backup-fixture.tar.zst.age',4096,4096,'/data/staging/uploads/fixture','complete','2026-11-07 18:14:18.323160','2126-10-14 18:14:18.321075');
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
INSERT INTO "users" VALUES(1,'admin','$argon2id$v=19$m=65536,t=3,p=4$Nfndy4T+SchC0Sas5peuFQ$zuqGTPCt5e+4p8OKE3uKXADYcWDEDgYYl1FLhfsBTlM',40,0,'2026-11-07 18:14:17.351073',NULL,0);
INSERT INTO "users" VALUES(2,'ops','$argon2id$v=19$m=65536,t=3,p=4$uPrCWJdBx3a2hCp7vvjPHQ$mPcXsS2baUBTavEwTN2HlJ3KFtFTM5HCobCKh3MpumU',20,0,'2026-11-07 18:14:17.456912',NULL,0);
INSERT INTO "users" VALUES(3,'viewer','$argon2id$v=19$m=65536,t=3,p=4$lTSPMt+AmgMmfDA76filvA$EPKRA0cmgzwho+wM3pllZYrD6MV7WUS3q1Kqyk1sius',10,0,'2026-11-07 18:14:17.516585',NULL,0);
INSERT INTO "users" VALUES(4,'second','$argon2id$v=19$m=65536,t=3,p=4$HCSfUHGBTxckfq4zrLKDhw$hMl6bQNQQXQCUA21E3L/krDuryjUSf7XeH5ashPOvVY',30,0,'2026-11-07 18:14:17.578937',NULL,0);
CREATE INDEX ix_sessions_user_id ON sessions (user_id);
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE INDEX ix_backups_job_id ON backups (job_id);
CREATE INDEX ix_backups_storage_target_id ON backups (storage_target_id);
CREATE INDEX ix_hooks_host_id ON hooks (host_id);
CREATE INDEX ix_jobs_storage_target_id ON jobs (storage_target_id);
CREATE INDEX ix_jobs_host_id ON jobs (host_id);
CREATE INDEX ix_job_notifications_target_id ON job_notifications (target_id);
CREATE INDEX ix_uploads_user_id ON uploads (user_id);
CREATE INDEX ix_audit_events_action_ts ON audit_events (action, ts);
CREATE INDEX ix_job_targets_job_id ON job_targets (job_id);
CREATE INDEX ix_docker_events_time ON docker_events (time_ns, id);
CREATE INDEX ix_runs_job_id ON runs (job_id);
CREATE INDEX ix_runs_finished_at ON runs (finished_at);
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
