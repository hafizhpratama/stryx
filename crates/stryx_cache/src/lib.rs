//! Content-hash caching primitives. Used to deduplicate function summaries
//! and LLM responses across runs. See ADR-0005 for the key shape.

use dashmap::DashMap;
use std::sync::Arc;

/// A blake3 content key. Cheap to clone (it's a `[u8; 32]` wrapper).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey(pub blake3::Hash);

impl CacheKey {
    pub fn hash(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes))
    }

    pub fn as_hex(&self) -> String {
        self.0.to_hex().to_string()
    }
}

/// Synchronous cache backend. Implementations must be cheap to clone (the
/// engine clones them across rayon workers).
pub trait CacheBackend<V>: Send + Sync
where
    V: Clone + Send + Sync,
{
    fn get(&self, key: &CacheKey) -> Option<V>;
    fn put(&self, key: CacheKey, value: V);
}

/// In-process cache backed by `dashmap`. Fine for a single CLI invocation;
/// not durable across runs.
pub struct InMemoryCache<V> {
    inner: Arc<DashMap<CacheKey, V>>,
}

impl<V> InMemoryCache<V> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<V> Default for InMemoryCache<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> Clone for InMemoryCache<V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V> CacheBackend<V> for InMemoryCache<V>
where
    V: Clone + Send + Sync,
{
    fn get(&self, key: &CacheKey) -> Option<V> {
        self.inner.get(key).map(|v| v.clone())
    }

    fn put(&self, key: CacheKey, value: V) {
        self.inner.insert(key, value);
    }
}
