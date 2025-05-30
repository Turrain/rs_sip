//! Comprehensive Event System for Rust
//! 
//! This module provides a flexible event system with both synchronous and asynchronous support.
//! 
//! ## Key Features
//! - Type-safe event handling
//! - Both sync and async event handlers
//! - Auto-unsubscribe handles
//! - Priority-based event handling
//! - Global event bus
//! - Zero-cost abstractions
//! 
//! ## Important Notes on Async Handlers
//! Async handlers receive a **clone** of the event rather than a reference. This is necessary
//! to avoid lifetime issues with async functions. Make sure your event types implement `Clone`.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};
use std::future::Future;
use std::pin::Pin;
use std::marker::PhantomData;

/// Core event trait that all events must implement
/// Requirements: Clone + Send + Sync + 'static
/// The Clone requirement is necessary for async handlers
pub trait Event: Clone + Send + Sync + 'static {
    fn as_any(&self) -> &dyn Any;
}

/// Automatic implementation for any type that meets the requirements
impl<T: Clone + Send + Sync + 'static> Event for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Type alias for boxed sync event handlers
pub type SyncHandler<E> = Box<dyn Fn(&E) + Send + Sync>;

/// Type alias for boxed async event handlers that take owned event
/// Note: Async handlers receive a clone of the event to avoid lifetime issues
pub type AsyncHandler<E> = Box<
    dyn Fn(E) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync
>;

/// Handler ID for unsubscribing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandlerId(usize);

/// Event bus for managing and dispatching events
pub struct EventBus {
    sync_handlers: Arc<RwLock<HashMap<TypeId, Vec<(HandlerId, Box<dyn Any + Send + Sync>)>>>>,
    async_handlers: Arc<RwLock<HashMap<TypeId, Vec<(HandlerId, Box<dyn Any + Send + Sync>)>>>>,
    next_id: Arc<RwLock<usize>>,
}

impl EventBus {
    /// Create a new event bus
    pub fn new() -> Self {
        Self {
            sync_handlers: Arc::new(RwLock::new(HashMap::new())),
            async_handlers: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(0)),
        }
    }

    fn next_handler_id(&self) -> HandlerId {
        let mut id = self.next_id.write().unwrap();
        let handler_id = HandlerId(*id);
        *id += 1;
        handler_id
    }

    /// Register a sync event handler
    pub fn on<E: Event, F>(&self, handler: F) -> HandlerId
    where
        F: Fn(&E) + Send + Sync + 'static,
    {
        let mut handlers = self.sync_handlers.write().unwrap();
        let type_id = TypeId::of::<E>();
        let handler_id = self.next_handler_id();
        
        let boxed_handler: SyncHandler<E> = Box::new(handler);
        
        handlers
            .entry(type_id)
            .or_insert_with(Vec::new)
            .push((handler_id, Box::new(boxed_handler) as Box<dyn Any + Send + Sync>));
        
        handler_id
    }

    /// Register an async event handler that receives owned event
    pub fn on_async<E, F, Fut>(&self, handler: F) -> HandlerId
    where
        E: Event,
        F: Fn(E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let wrapper = move |event: E| -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(handler(event))
        };

        let mut handlers = self.async_handlers.write().unwrap();
        let type_id = TypeId::of::<E>();
        let handler_id = self.next_handler_id();
        
        let boxed_handler: AsyncHandler<E> = Box::new(wrapper);
        
        handlers
            .entry(type_id)
            .or_insert_with(Vec::new)
            .push((handler_id, Box::new(boxed_handler) as Box<dyn Any + Send + Sync>));
        
        handler_id
    }

    /// Remove a handler by ID
    pub fn off(&self, handler_id: HandlerId) {
        // Remove from sync handlers
        let mut sync = self.sync_handlers.write().unwrap();
        for handlers in sync.values_mut() {
            handlers.retain(|(id, _)| *id != handler_id);
        }
        
        // Remove from async handlers
        let mut async_handlers = self.async_handlers.write().unwrap();
        for handlers in async_handlers.values_mut() {
            handlers.retain(|(id, _)| *id != handler_id);
        }
    }

    /// Emit an event synchronously
    pub fn emit<E: Event>(&self, event: &E) {
        let type_id = TypeId::of::<E>();
        
        // Execute sync handlers
        let handlers_map = self.sync_handlers.read().unwrap();
        if let Some(handlers) = handlers_map.get(&type_id) {
            for (_, handler) in handlers {
                if let Some(h) = handler.downcast_ref::<SyncHandler<E>>() {
                    h(event);
                }
            }
        }
    }

    /// Emit an event asynchronously (handlers receive owned clone)
    /// This also executes sync handlers after async handlers complete
    pub async fn emit_async<E: Event>(&self, event: E) {
        let type_id = TypeId::of::<E>();
        
        // Collect async futures
        let mut futures = Vec::new();
        {
            let handlers_map = self.async_handlers.read().unwrap();
            if let Some(handlers) = handlers_map.get(&type_id) {
                for (_, handler) in handlers {
                    if let Some(h) = handler.downcast_ref::<AsyncHandler<E>>() {
                        futures.push(h(event.clone()));
                    }
                }
            }
        }
        
        // Execute all async handlers
        if !futures.is_empty() {
            futures::future::join_all(futures).await;
        }
        
        // Also execute sync handlers
        self.emit(&event);
    }

    /// Clear all handlers for a specific event type
    pub fn clear<E: Event>(&self) {
        let type_id = TypeId::of::<E>();
        self.sync_handlers.write().unwrap().remove(&type_id);
        self.async_handlers.write().unwrap().remove(&type_id);
    }

    /// Clear all handlers
    pub fn clear_all(&self) {
        self.sync_handlers.write().unwrap().clear();
        self.async_handlers.write().unwrap().clear();
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating configured EventBus instances
pub struct EventBusBuilder {
    // Future configuration options can be added here
}

impl EventBusBuilder {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn build(self) -> EventBus {
        EventBus::new()
    }
}

impl Default for EventBusBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A handle that automatically unsubscribes when dropped
pub struct AutoUnsubscribe {
    bus: Weak<EventBus>,
    handler_id: HandlerId,
}

impl Drop for AutoUnsubscribe {
    fn drop(&mut self) {
        if let Some(bus) = self.bus.upgrade() {
            bus.off(self.handler_id);
        }
    }
}

/// Extension trait for EventBus to support auto-unsubscribe
pub trait EventBusExt {
    fn on_auto<E: Event, F>(self: &Arc<Self>, handler: F) -> AutoUnsubscribe
    where
        F: Fn(&E) + Send + Sync + 'static;
    
    fn on_async_auto<E, F, Fut>(self: &Arc<Self>, handler: F) -> AutoUnsubscribe
    where
        E: Event,
        F: Fn(E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static;
}

impl EventBusExt for EventBus {
    fn on_auto<E: Event, F>(self: &Arc<Self>, handler: F) -> AutoUnsubscribe
    where
        F: Fn(&E) + Send + Sync + 'static,
    {
        let handler_id = self.on(handler);
        AutoUnsubscribe {
            bus: Arc::downgrade(self),
            handler_id,
        }
    }
    
    fn on_async_auto<E, F, Fut>(self: &Arc<Self>, handler: F) -> AutoUnsubscribe
    where
        E: Event,
        F: Fn(E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler_id = self.on_async(handler);
        AutoUnsubscribe {
            bus: Arc::downgrade(self),
            handler_id,
        }
    }
}

/// Macro to define events with automatic derive implementations
#[macro_export]
macro_rules! event {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field_name:ident: $field_type:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug)]
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field_name: $field_type,
            )*
        }
    };

    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug)]
        $vis struct $name;
    };
}

/// Macro to register event handlers more easily
#[macro_export]
macro_rules! on {
    ($bus:expr, $event:ty, $handler:expr) => {
        $bus.on::<$event, _>($handler)
    };
}

/// Macro to register async event handlers more easily
#[macro_export]
macro_rules! on_async {
    ($bus:expr, $event:ty, $handler:expr) => {
        $bus.on_async::<$event, _, _>($handler)
    };
}

/// Macro to emit events more easily
#[macro_export]
macro_rules! emit {
    ($bus:expr, $event:expr) => {
        $bus.emit(&$event)
    };
}

/// Macro to emit events asynchronously
#[macro_export]
macro_rules! emit_async {
    ($bus:expr, $event:expr) => {
        $bus.emit_async($event).await
    };
}

/// Once-handler that automatically unsubscribes after first execution
pub struct OnceHandler<E: Event> {
    bus: Arc<EventBus>,
    handler_id: Option<HandlerId>,
    _phantom: PhantomData<E>,
}

impl<E: Event> OnceHandler<E> {
    pub fn new<F>(bus: Arc<EventBus>, handler: F) -> Self
    where
        F: Fn(&E) + Send + Sync + 'static,
    {
        let bus_clone = bus.clone();
        let once_handler = Arc::new(RwLock::new(None::<HandlerId>));
        let once_handler_clone = once_handler.clone();
        
        let wrapped = move |event: &E| {
            handler(event);
            if let Some(id) = *once_handler_clone.read().unwrap() {
                bus_clone.off(id);
            }
        };
        
        let handler_id = bus.on(wrapped);
        *once_handler.write().unwrap() = Some(handler_id);
        
        Self {
            bus,
            handler_id: Some(handler_id),
            _phantom: PhantomData,
        }
    }
}

/// Priority event bus with handler priorities
pub struct PriorityEventBus {
    handlers: Arc<RwLock<HashMap<TypeId, Vec<(i32, HandlerId, Box<dyn Any + Send + Sync>)>>>>,
    next_id: Arc<RwLock<usize>>,
}

impl PriorityEventBus {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(0)),
        }
    }

    fn next_handler_id(&self) -> HandlerId {
        let mut id = self.next_id.write().unwrap();
        let handler_id = HandlerId(*id);
        *id += 1;
        handler_id
    }

    /// Register a handler with priority (higher priority = executed first)
    pub fn on_with_priority<E: Event, F>(&self, priority: i32, handler: F) -> HandlerId
    where
        F: Fn(&E) + Send + Sync + 'static,
    {
        let mut handlers = self.handlers.write().unwrap();
        let type_id = TypeId::of::<E>();
        let handler_id = self.next_handler_id();
        
        let boxed_handler: SyncHandler<E> = Box::new(handler);
        
        let entry = handlers.entry(type_id).or_insert_with(Vec::new);
        entry.push((priority, handler_id, Box::new(boxed_handler) as Box<dyn Any + Send + Sync>));
        entry.sort_by_key(|(p, _, _)| -p); // Sort in descending order
        
        handler_id
    }

    pub fn emit<E: Event>(&self, event: &E) {
        let type_id = TypeId::of::<E>();
        
        let handlers_map = self.handlers.read().unwrap();
        if let Some(handlers) = handlers_map.get(&type_id) {
            for (_, _, handler) in handlers {
                if let Some(h) = handler.downcast_ref::<SyncHandler<E>>() {
                    h(event);
                }
            }
        }
    }
}

impl Default for PriorityEventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe global event bus
pub mod global {
    use super::*;
    use once_cell::sync::Lazy;

    static GLOBAL_BUS: Lazy<EventBus> = Lazy::new(EventBus::new);

    pub fn on<E: Event, F>(handler: F) -> HandlerId
    where
        F: Fn(&E) + Send + Sync + 'static,
    {
        GLOBAL_BUS.on(handler)
    }

    pub fn on_async<E, F, Fut>(handler: F) -> HandlerId
    where
        E: Event,
        F: Fn(E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        GLOBAL_BUS.on_async(handler)
    }

    pub fn off(handler_id: HandlerId) {
        GLOBAL_BUS.off(handler_id);
    }

    pub fn emit<E: Event>(event: &E) {
        GLOBAL_BUS.emit(event);
    }

    pub async fn emit_async<E: Event>(event: E) {
        GLOBAL_BUS.emit_async(event).await;
    }

    pub fn clear<E: Event>() {
        GLOBAL_BUS.clear::<E>();
    }

    pub fn clear_all() {
        GLOBAL_BUS.clear_all();
    }
}

// Example usage and tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{sleep, Duration};

    event! {
        pub struct UserCreated {
            pub id: u64,
            pub name: String,
        }
    }

    event! {
        pub struct UserDeleted {
            pub id: u64,
        }
    }

    event! {
        pub struct SystemShutdown;
    }

    #[test]
    fn test_sync_events() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicUsize::new(0));
        
        let counter_clone = counter.clone();
        on!(bus, UserCreated, move |event: &UserCreated| {
            println!("User created: {} ({})", event.name, event.id);
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        emit!(bus, UserCreated {
            id: 1,
            name: "Alice".to_string(),
        });

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_async_events() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicUsize::new(0));
        
        let counter_clone = counter.clone();
        on_async!(bus, UserCreated, move |event: UserCreated| {
            let counter = counter_clone.clone();
            async move {
                println!("Async: User created: {} ({})", event.name, event.id);
                sleep(Duration::from_millis(10)).await;
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });

        emit_async!(bus, UserCreated {
            id: 2,
            name: "Bob".to_string(),
        });

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_handler_removal() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicUsize::new(0));
        
        let counter_clone = counter.clone();
        let handler_id = bus.on::<UserCreated, _>(move |_| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        emit!(bus, UserCreated {
            id: 1,
            name: "Test".to_string(),
        });
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        bus.off(handler_id);

        emit!(bus, UserCreated {
            id: 2,
            name: "Test2".to_string(),
        });
        assert_eq!(counter.load(Ordering::SeqCst), 1); // Should still be 1
    }

    #[test]
    fn test_priority_events() {
        let bus = PriorityEventBus::new();
        let order = Arc::new(RwLock::new(Vec::new()));
        
        let order_clone = order.clone();
        bus.on_with_priority::<UserCreated, _>(10, move |_| {
            order_clone.write().unwrap().push(1);
        });

        let order_clone = order.clone();
        bus.on_with_priority::<UserCreated, _>(20, move |_| {
            order_clone.write().unwrap().push(2);
        });

        let order_clone = order.clone();
        bus.on_with_priority::<UserCreated, _>(5, move |_| {
            order_clone.write().unwrap().push(3);
        });

        bus.emit(&UserCreated {
            id: 3,
            name: "Charlie".to_string(),
        });

        let result = order.read().unwrap().clone();
        assert_eq!(result, vec![2, 1, 3]); // Executed in priority order
    }

    #[test]
    fn test_global_bus() {
        let counter = Arc::new(AtomicUsize::new(0));
        
        let counter_clone = counter.clone();
        let handler_id = global::on::<SystemShutdown, _>(move |_| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        global::emit(&SystemShutdown);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        
        global::off(handler_id);
        global::emit(&SystemShutdown);
        assert_eq!(counter.load(Ordering::SeqCst), 1); // Should still be 1
    }

    #[tokio::test]
    async fn test_async_with_borrowed_data() {
        let bus = EventBus::new();
        let data = Arc::new(RwLock::new(Vec::<String>::new()));
        
        let data_clone = data.clone();
        bus.on_async::<UserCreated, _, _>(move |event: UserCreated| {
            let data = data_clone.clone();
            async move {
                sleep(Duration::from_millis(10)).await;
                data.write().unwrap().push(event.name);
            }
        });

        emit_async!(bus, UserCreated {
            id: 1,
            name: "Async User".to_string(),
        });

        assert_eq!(data.read().unwrap().len(), 1);
        assert_eq!(data.read().unwrap()[0], "Async User");
    }

    #[test]
    fn test_auto_unsubscribe() {
        let bus = Arc::new(EventBus::new());
        let counter = Arc::new(AtomicUsize::new(0));
        
        {
            let counter_clone = counter.clone();
            let _handle = bus.on_auto::<UserCreated, _>(move |_| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });
            
            emit!(bus, UserCreated {
                id: 1,
                name: "Test".to_string(),
            });
            assert_eq!(counter.load(Ordering::SeqCst), 1);
        } // _handle dropped here
        
        emit!(bus, UserCreated {
            id: 2,
            name: "Test2".to_string(),
        });
        assert_eq!(counter.load(Ordering::SeqCst), 1); // Should still be 1
    }
}

// Dependencies for Cargo.toml:
// [dependencies]
// futures = "0.3"
// once_cell = "1.19"
// 
// [dev-dependencies]
// tokio = { version = "1", features = ["full"] }