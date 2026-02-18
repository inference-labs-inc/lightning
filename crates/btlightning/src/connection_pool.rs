use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
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

#[derive(Debug, Default)]
pub struct ConnectionPool {
    connections: HashMap<String, Connection>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_connection(&mut self, endpoint: &str, connection_id: String) {
        let connection = Connection::new(connection_id, endpoint.to_string());
        self.connections.insert(endpoint.to_string(), connection);
        info!("Added persistent connection to pool: {}", endpoint);
    }

    pub fn get_connection(&self, endpoint: &str) -> Option<String> {
        self.connections.get(endpoint).map(|c| c.id.clone())
    }

    pub fn remove_connection(&mut self, endpoint: &str) {
        if self.connections.remove(endpoint).is_some() {
            info!("Removed connection from pool: {}", endpoint);
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn close_all(&mut self) {
        self.connections.clear();
        info!("Closed all connections in pool");
    }
}
