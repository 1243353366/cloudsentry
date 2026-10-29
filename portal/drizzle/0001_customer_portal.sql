CREATE TABLE `customer_connections` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ownerId` int NOT NULL,
	`provider` enum('cloudflare','aws','render','railway') NOT NULL,
	`label` varchar(128) NOT NULL,
	`scopeId` varchar(128) NOT NULL,
	`region` varchar(64),
	`credentialsCiphertext` mediumtext NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `customer_connections_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `customer_oauth_states` (
	`id` int AUTO_INCREMENT NOT NULL,
	`stateHash` varchar(64) NOT NULL,
	`provider` enum('google','github','microsoft') NOT NULL,
	`origin` varchar(255) NOT NULL,
	`nonce` varchar(128) NOT NULL,
	`verifierCiphertext` mediumtext NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`expiresAt` timestamp NOT NULL,
	`usedAt` timestamp,
	CONSTRAINT `customer_oauth_states_id` PRIMARY KEY(`id`),
	CONSTRAINT `customer_oauth_states_stateHash_unique` UNIQUE(`stateHash`)
);
--> statement-breakpoint
CREATE TABLE `customer_scans` (
	`id` int AUTO_INCREMENT NOT NULL,
	`ownerId` int NOT NULL,
	`connectionId` int,
	`provider` enum('cloudflare','aws','render','railway') NOT NULL,
	`status` enum('completed') NOT NULL DEFAULT 'completed',
	`connectionLabel` varchar(128),
	`reportCiphertext` mediumtext NOT NULL,
	`summaryCiphertext` mediumtext,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `customer_scans_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `customer_sessions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`origin` varchar(255) NOT NULL,
	`tokenHash` varchar(64) NOT NULL,
	`csrfTokenHash` varchar(64) NOT NULL,
	`csrfTokenCiphertext` mediumtext NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`expiresAt` timestamp NOT NULL,
	`revokedAt` timestamp,
	CONSTRAINT `customer_sessions_id` PRIMARY KEY(`id`),
	CONSTRAINT `customer_sessions_tokenHash_unique` UNIQUE(`tokenHash`)
);
--> statement-breakpoint
ALTER TABLE `users` ADD `provider` varchar(16);--> statement-breakpoint
CREATE INDEX `customer_connections_owner_idx` ON `customer_connections` (`ownerId`);--> statement-breakpoint
CREATE INDEX `customer_oauth_states_expiry_idx` ON `customer_oauth_states` (`expiresAt`);--> statement-breakpoint
CREATE INDEX `customer_scans_owner_created_idx` ON `customer_scans` (`ownerId`,`createdAt`);--> statement-breakpoint
CREATE INDEX `customer_sessions_user_expiry_idx` ON `customer_sessions` (`userId`,`expiresAt`);--> statement-breakpoint
CREATE INDEX `users_provider_openId_idx` ON `users` (`provider`,`openId`);