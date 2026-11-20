'use strict';
/**
 * Ограничители нагрузки на основе «ведра токенов» (token bucket).
 *
 * Нужны для трёх вещей:
 *   - защита TCP-сервера от флуда пакетами/байтами с одного соединения;
 *   - защита аутентификации от перебора пароля;
 *   - защита HTTP-панели от флуда запросами.
 *
 * Счётчики живут в памяти процесса: при нескольких инстансах сервера лимит
 * нужно выносить в общее хранилище (Redis и т.п.).
 */

/** Одно ведро: не более capacity токенов, восполнение refillPerSecond в секунду. */
class TokenBucket {
    constructor({ capacity, refillPerSecond, now = () => Date.now() }) {
        if (!(capacity > 0)) throw new Error('TokenBucket: capacity должен быть > 0');
        if (!(refillPerSecond > 0)) throw new Error('TokenBucket: refillPerSecond должен быть > 0');

        this.capacity = capacity;
        this.refillPerSecond = refillPerSecond;
        this.tokens = capacity;
        this.updatedAt = now();
        this._now = now;
    }

    /** Списывает count токенов. false — значит, превышен лимит. */
    tryRemove(count = 1) {
        const now = this._now();
        const elapsed = Math.max(0, now - this.updatedAt) / 1000;
        this.updatedAt = now;
        this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refillPerSecond);

        if (this.tokens >= count) {
            this.tokens -= count;
            return true;
        }
        return false;
    }
}

/**
 * Набор ведер по ключу (IP, пара IP+UIN и т.п.).
 * Ограничивает размер памяти: при превышении maxKeys вытесняются самые
 * старые записи (Map в Node хранит пары в порядке вставки).
 */
class KeyedRateLimiter {
    constructor({ capacity, refillPerSecond, maxKeys = 10000, now = () => Date.now() }) {
        this.maxKeys = maxKeys;
        this._now = now;
        this._buckets = new Map();
        this._options = { capacity, refillPerSecond };
    }

    allow(key, count = 1) {
        let bucket = this._buckets.get(key);
        if (!bucket) {
            if (this._buckets.size >= this.maxKeys) this._evictOldest();
            bucket = new TokenBucket({ ...this._options, now: this._now });
            this._buckets.set(key, bucket);
        }
        return bucket.tryRemove(count);
    }

    /** Снимает штраф за успешное действие, чтобы легитимный клиент не копил долг. */
    reset(key) {
        this._buckets.delete(key);
    }

    get size() {
        return this._buckets.size;
    }

    _evictOldest(count = 1) {
        const iterator = this._buckets.keys();
        for (let i = 0; i < count; i++) {
            const oldest = iterator.next();
            if (oldest.done) break;
            this._buckets.delete(oldest.value);
        }
    }

    clear() {
        this._buckets.clear();
    }
}

/**
 * Периодическая уборка: снимает потолок памяти на длинноживущих
 * глобальных ограничителях (перебор пароля, HTTP-флуд).
 * Возвращает таймер с unref(), чтобы не держать процесс живым.
 */
function startJanitor(limiters, intervalMs = 60000) {
    const timer = setInterval(() => {
        for (const limiter of limiters) {
            if (limiter.size > limiter.maxKeys) limiter.clear();
        }
    }, intervalMs);

    if (timer.unref) timer.unref();
    return timer;
}

module.exports = { TokenBucket, KeyedRateLimiter, startJanitor };