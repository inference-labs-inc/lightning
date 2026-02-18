use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone)]
pub struct Connection {
    pub id: String,
    pub endpoint: String,
    pub created_at: u64,
}

impl Connection {
    pub fn new(id: String, endpoint: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            id,
            endpoint,
            created_at: now,
        }
    }
}

#[derive(Debug)]
pub struct ConnectionPool {
    connections: Arc<RwLock<HashMap<String, Connection>>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_connection(&mut self, endpoint: &str, connection_id: String) {
        let mut connections = self.connections.write().await;
        let connection = Connection::new(connection_id, endpoint.to_string());
        connections.insert(endpoint.to_string(), connection);
        info!("Added persistent connection to pool: {}", endpoint);
    }

    pub async fn get_connection(&self, endpoint: &str) -> Option<String> {
        let connections = self.connections.read().await;
        connections.get(endpoint).map(|c| c.id.clone())
    }

    pub async fn remove_connection(&mut self, endpoint: &str) {
        let mut connections = self.connections.write().await;
        if connections.remove(endpoint).is_some() {
            info!("Removed connection from pool: {}", endpoint);
        }
    }

    pub async fn connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    pub async fn close_all(&mut self) {
        let mut connections = self.connections.write().await;
        connections.clear();
        info!("Closed all connections in pool");
    }
}
