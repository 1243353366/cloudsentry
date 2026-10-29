-- Existing rows and ciphertext columns are preserved. These widening changes only
-- remove enum constraints that cannot represent the managed identity or local imports.
ALTER TABLE `customer_oauth_states` MODIFY COLUMN `provider` varchar(16) NOT NULL;--> statement-breakpoint
ALTER TABLE `customer_connections` MODIFY COLUMN `provider` varchar(16) NOT NULL;--> statement-breakpoint
ALTER TABLE `customer_scans` MODIFY COLUMN `provider` varchar(16) NOT NULL;--> statement-breakpoint
ALTER TABLE `customer_scans` MODIFY COLUMN `status` varchar(16) NOT NULL DEFAULT 'completed';
