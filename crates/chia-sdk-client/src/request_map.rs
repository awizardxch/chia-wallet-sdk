use std::{collections::HashMap, sync::Arc};

use chia_protocol::Message;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot};

#[derive(Debug)]
pub(crate) struct Request {
    sender: oneshot::Sender<Message>,
    _permit: OwnedSemaphorePermit,
}

impl Request {
    pub(crate) fn send(self, message: Message) {
        self.sender.send(message).ok();
    }
}

#[derive(Debug, Default)]
struct Items {
    requests: HashMap<u16, Request>,
    next_id: u16,
    closed: bool,
}

#[derive(Debug)]
pub(crate) struct RequestMap {
    items: Mutex<Items>,
    semaphore: Arc<Semaphore>,
}

impl RequestMap {
    pub(crate) fn new() -> Self {
        Self {
            items: Mutex::new(Items::default()),
            semaphore: Arc::new(Semaphore::new(u16::MAX as usize)),
        }
    }

    /// Tracks a new request and returns its id, or [`None`] if the connection is closed.
    ///
    /// Ids are handed out in a rolling sequence rather than reusing the lowest free id, so a
    /// late response to a request that timed out or was cancelled isn't mistaken for the
    /// response to the next request.
    pub(crate) async fn insert(&self, sender: oneshot::Sender<Message>) -> Option<u16> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");

        let mut items = self.items.lock().await;

        if items.closed {
            return None;
        }

        items.requests.retain(|_, v| !v.sender.is_closed());

        let start = items.next_id;
        let index = (0..=u16::MAX)
            .map(|offset| start.wrapping_add(offset))
            .find(|i| !items.requests.contains_key(i))
            .expect("exceeded expected number of requests");

        items.next_id = index.wrapping_add(1);
        items.requests.insert(
            index,
            Request {
                sender,
                _permit: permit,
            },
        );

        Some(index)
    }

    pub(crate) async fn remove(&self, id: u16) -> Option<Request> {
        self.items.lock().await.requests.remove(&id)
    }

    /// Drops every pending request so that it fails instead of waiting forever,
    /// and refuses new requests.
    pub(crate) async fn close(&self) {
        let mut items = self.items.lock().await;
        items.closed = true;
        items.requests.clear();
    }
}
