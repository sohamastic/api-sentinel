CREATE TABLE `audit` (
	`id` text PRIMARY KEY NOT NULL,
	`at` integer NOT NULL,
	`rule` text NOT NULL,
	`mode` text NOT NULL,
	`reason` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_audit_at` ON `audit` (`at`);--> statement-breakpoint
CREATE TABLE `events` (
	`id` text PRIMARY KEY NOT NULL,
	`at` integer NOT NULL,
	`method` text NOT NULL,
	`endpoint` text NOT NULL,
	`identity` text NOT NULL,
	`action` text NOT NULL,
	`status` integer NOT NULL,
	`duration` integer NOT NULL,
	`findings` text NOT NULL,
	`scenario` text,
	`reviewed` integer DEFAULT 0 NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_events_at` ON `events` (`at`);--> statement-breakpoint
CREATE INDEX `idx_events_endpoint_at` ON `events` (`endpoint`,`at`);--> statement-breakpoint
CREATE TABLE `policies` (
	`id` text PRIMARY KEY NOT NULL,
	`mode` text NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `rate_buckets` (
	`key` text PRIMARY KEY NOT NULL,
	`window` integer NOT NULL,
	`count` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_rate_buckets_window` ON `rate_buckets` (`window`);--> statement-breakpoint
CREATE TABLE `settings` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL
);
