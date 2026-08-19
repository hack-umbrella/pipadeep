/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-pentest`: every
 * pentest write must honor the exploration discipline — records carry the
 * session id of an existing goal row, and every edge references source/target
 * nodes of the exact kinds its kind demands, all within one session. The store
 * enforces the same rules at its write boundary, so a violation here means a
 * write path bypassed the store or landed a torn record.
 * @module @pipadeep/dsh-pentest/invariant
 */
const PACKAGE_NAME = '@pipadeep/dsh-pentest';
const DOMAIN_NAME = 'pentest';
/** Tables whose records must reference an existing goal row of the session. */
const GOAL_OWNED_TABLES = ['intents', 'facts', 'findings', 'assets', 'edges'];
/** The source table an edge kind anchors on (validated for the same session). */
const SOURCE_TABLE_OF_EDGE = {
    spawns: 'goals',
    yields: 'intents',
    derived_from: 'facts',
    proves: 'intents',
    parent: 'assets',
};
/** The target table an edge kind points at. */
const TARGET_TABLE_OF_EDGE = {
    spawns: 'intents',
    yields: 'facts',
    derived_from: 'intents',
    proves: 'findings',
    parent: 'assets',
};
/** Cordis companion plugin name. */
export const name = 'dsh-pentest-invariant';
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants'];
/** Install the exploration-graph checks against the open pentest domain. */
const install = Object.assign((ctx, fail) => {
    ctx.on('domain/changed', (change) => {
        if (change.domain !== DOMAIN_NAME || change.operation !== 'put')
            return;
        const domain = ctx.storage.form('domain').get(DOMAIN_NAME);
        if (domain === undefined) {
            return fail(`domain/changed for '${DOMAIN_NAME}' emitted while that domain is not open`);
        }
        if (change.table === 'goals') {
            const goal = change.value;
            if (goal.sessionId !== change.key) {
                return fail(`goals row key '${change.key}' does not match its sessionId`);
            }
            return;
        }
        if (!GOAL_OWNED_TABLES.includes(change.table))
            return;
        const record = change.value;
        const goal = [...domain.table('goals').entries()].find(([, row]) => row.sessionId === record.sessionId);
        if (goal === undefined) {
            return fail(`'${DOMAIN_NAME}'.'${change.table}'['${change.key}'] references unknown session '${record.sessionId}'`);
        }
        const sameSession = (tableName, id) => {
            if (tableName === 'goals') {
                return goal[1].id === id;
            }
            const row = domain.table(tableName).get(id);
            return row !== undefined && row.sessionId === record.sessionId;
        };
        if (change.table === 'edges') {
            const edge = record;
            if (!sameSession(SOURCE_TABLE_OF_EDGE[edge.kind], edge.sourceId)) {
                return fail(`'${DOMAIN_NAME}'.edges['${change.key}'] ${edge.kind} source '${edge.sourceId}' is not a same-session ${SOURCE_TABLE_OF_EDGE[edge.kind]} row`);
            }
            if (!sameSession(TARGET_TABLE_OF_EDGE[edge.kind], edge.targetId)) {
                return fail(`'${DOMAIN_NAME}'.edges['${change.key}'] ${edge.kind} target '${edge.targetId}' is not a same-session ${TARGET_TABLE_OF_EDGE[edge.kind]} row`);
            }
            return;
        }
        if (change.table === 'findings') {
            const affectedAssetId = record.affectedAssetId;
            if (affectedAssetId !== undefined && !sameSession('assets', affectedAssetId)) {
                return fail(`'${DOMAIN_NAME}'.findings['${change.key}'] references unknown asset '${affectedAssetId}'`);
            }
        }
    }, { global: true });
}, { inject: ['storage'] });
/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx) => Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install));
//# sourceMappingURL=invariant.js.map