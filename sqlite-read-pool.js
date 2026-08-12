const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const { availableParallelism } = require('os');

if (!isMainThread && workerData?.sqliteReadWorker) {
    const Database = require('better-sqlite3');
    const database = new Database(workerData.dbPath, { readonly: true, fileMustExist: true });
    database.pragma('query_only = ON');
    database.pragma('busy_timeout = 30000');
    database.function('comment_is_hidden', { deterministic: true }, (content, blockWordsJson) => {
        const text = String(content ?? '').normalize('NFKC').toLowerCase();
        if (!text) return 0;
        let blockWords = [];
        try { blockWords = JSON.parse(blockWordsJson || '[]'); } catch {}
        const trimmed = text.trim();
        const compact = trimmed.replace(/\s+/g, '');
        return /^\d+$/.test(compact)
            || /^[a-z]+$/.test(trimmed)
            || /^已[\p{L}\p{N}]{0,8}下载(?:成功|完成|了)?[!！。.]*$/u.test(compact)
            || blockWords.some(word => text.includes(String(word).normalize('NFKC').toLowerCase()))
            ? 1 : 0;
    });
    const statements = new Map();

    parentPort.on('message', ({ id, method, sql, params }) => {
        try {
            if (!statements.has(sql)) statements.set(sql, database.prepare(sql));
            const statement = statements.get(sql);
            const result = method === 'get' ? statement.get(...params) : statement.all(...params);
            parentPort.postMessage({ id, result });
        } catch (error) {
            parentPort.postMessage({ id, error: { message: error.message, code: error.code } });
        }
    });
} else {
    class SqliteReadPool {
        constructor(dbPath) {
            const configured = Number.parseInt(process.env.SQLITE_READ_WORKERS || '', 10);
            this.size = Number.isFinite(configured)
                ? Math.min(Math.max(configured, 1), 32)
                : Math.min(Math.max(availableParallelism() - 1, 2), 8);
            this.dbPath = dbPath;
            this.nextId = 1;
            this.tasks = new Map();
            this.workers = Array.from({ length: this.size }, () => this.createWorker());
        }

        createWorker() {
            const state = { pending: 0, worker: null };
            state.worker = new Worker(__filename, {
                workerData: { sqliteReadWorker: true, dbPath: this.dbPath }
            });
            state.worker.on('message', message => {
                const task = this.tasks.get(message.id);
                if (!task) return;
                this.tasks.delete(message.id);
                task.state.pending -= 1;
                if (message.error) {
                    const error = new Error(message.error.message);
                    error.code = message.error.code;
                    task.reject(error);
                } else {
                    task.resolve(message.result);
                }
            });
            state.worker.on('error', error => {
                for (const [id, task] of this.tasks) {
                    if (task.state !== state) continue;
                    this.tasks.delete(id);
                    task.reject(error);
                }
                state.pending = 0;
            });
            return state;
        }

        run(method, sql, params = []) {
            const state = this.workers.reduce((best, item) => item.pending < best.pending ? item : best);
            const id = this.nextId++;
            state.pending += 1;
            return new Promise((resolve, reject) => {
                this.tasks.set(id, { resolve, reject, state });
                state.worker.postMessage({ id, method, sql, params });
            });
        }

        all(sql, params) {
            return this.run('all', sql, params);
        }

        get(sql, params) {
            return this.run('get', sql, params);
        }

        close() {
            return Promise.all(this.workers.map(state => state.worker.terminate()));
        }
    }

    module.exports = { SqliteReadPool };
}
