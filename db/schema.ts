import { sqliteTable, text, integer, index } from 'drizzle-orm/sqlite-core';
export const policies = sqliteTable('policies', {
  id: text('id').primaryKey(),
  mode: text('mode').notNull(),
  updatedAt: integer('updated_at').notNull(),
});
export const events = sqliteTable(
  'events',
  {
    id: text('id').primaryKey(),
    at: integer('at').notNull(),
    method: text('method').notNull(),
    endpoint: text('endpoint').notNull(),
    identity: text('identity').notNull(),
    action: text('action').notNull(),
    status: integer('status').notNull(),
    duration: integer('duration').notNull(),
    findings: text('findings').notNull(),
    scenario: text('scenario'),
    reviewed: integer('reviewed').notNull().default(0),
  },
  (t) => [
    index('idx_events_at').on(t.at),
    index('idx_events_endpoint_at').on(t.endpoint, t.at),
  ],
);
export const rateBuckets = sqliteTable(
  'rate_buckets',
  {
    key: text('key').primaryKey(),
    window: integer('window').notNull(),
    count: integer('count').notNull(),
  },
  (t) => [index('idx_rate_buckets_window').on(t.window)],
);
export const audit = sqliteTable(
  'audit',
  {
    id: text('id').primaryKey(),
    at: integer('at').notNull(),
    rule: text('rule').notNull(),
    mode: text('mode').notNull(),
    reason: text('reason').notNull(),
  },
  (t) => [index('idx_audit_at').on(t.at)],
);
export const settings = sqliteTable('settings', {
  key: text('key').primaryKey(),
  value: text('value').notNull(),
});
