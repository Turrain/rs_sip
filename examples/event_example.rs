use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use rs_sip::{event, event_system::*};
use tokio::time::{sleep, timeout};
use tokio::sync::{Mutex, Semaphore};
use futures::future::join_all;
use chrono::{DateTime, Utc};

// Import the event system (assuming it's in a module called `event_system`)


// Define our events using the event! macro
event! {

    pub struct TaskCreated {
        pub id: u64,
        pub name: String,
        pub priority: i32,
        pub data: Vec<u8>,
        pub created_at: DateTime<Utc>,
    }
}

event! {

    pub struct TaskStarted {
        pub id: u64,
        pub worker_id: String,
        pub started_at: DateTime<Utc>,
    }
}

event! {

    pub struct TaskCompleted {
        pub id: u64,
        pub worker_id: String,
        pub result: TaskResult,
        pub duration_ms: u64,
        pub completed_at: DateTime<Utc>,
    }
}

event! {

    pub struct TaskFailed {
        pub id: u64,
        pub worker_id: String,
        pub error: String,
        pub retry_count: u32,
        pub failed_at: DateTime<Utc>,
    }
}

event! {
  
    pub struct WorkerStatusChanged {
        pub worker_id: String,
        pub status: WorkerStatus,
        pub active_tasks: usize,
        pub timestamp: DateTime<Utc>,
    }
}

event! {

    pub struct SystemMetricsUpdated {
        pub total_tasks: u64,
        pub completed_tasks: u64,
        pub failed_tasks: u64,
        pub average_duration_ms: f64,
        pub workers_online: usize,
        pub timestamp: DateTime<Utc>,
    }
}

#[derive(Clone, Debug)]
pub enum TaskResult {
    Success(String),
    PartialSuccess(String, Vec<String>), // Result + warnings
    Cached(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum WorkerStatus {
    Idle,
    Busy,
    Overloaded,
    Offline,
}

// Shared state structures
#[derive(Clone)]
pub struct TaskInfo {
    pub id: u64,
    pub name: String,
    pub status: TaskStatus,
    pub assigned_worker: Option<String>,
    pub retry_count: u32,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Clone)]
pub struct TaskProcessingSystem {
    pub event_bus: Arc<EventBus>,
    pub tasks: Arc<RwLock<HashMap<u64, TaskInfo>>>,
    pub workers: Arc<RwLock<HashMap<String, WorkerInfo>>>,
    pub metrics: Arc<Mutex<SystemMetrics>>,
    pub task_semaphore: Arc<Semaphore>,
    pub next_task_id: Arc<AtomicU64>,
}

pub struct WorkerInfo {
    pub id: String,
    pub status: WorkerStatus,
    pub active_tasks: Vec<u64>,
    pub max_concurrent_tasks: usize,
    pub last_heartbeat: Instant,
}

pub struct SystemMetrics {
    pub total_tasks: AtomicU64,
    pub completed_tasks: AtomicU64,
    pub failed_tasks: AtomicU64,
    pub total_duration_ms: AtomicU64,
    pub task_durations: Vec<u64>,
}

impl TaskProcessingSystem {
    pub fn new(max_concurrent_tasks: usize) -> Self {
        let system = Self {
            event_bus: Arc::new(EventBus::new()),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            workers: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(SystemMetrics {
                total_tasks: AtomicU64::new(0),
                completed_tasks: AtomicU64::new(0),
                failed_tasks: AtomicU64::new(0),
                total_duration_ms: AtomicU64::new(0),
                task_durations: Vec::new(),
            })),
            task_semaphore: Arc::new(Semaphore::new(max_concurrent_tasks)),
            next_task_id: Arc::new(AtomicU64::new(1)),
        };

        system.setup_handlers();
        system
    }

    fn setup_handlers(&self) {
        // Task creation handler - validates and stores task
        let tasks = self.tasks.clone();
        let metrics = self.metrics.clone();
        self.event_bus.on_async::<TaskCreated, _, _>(move |event: TaskCreated| {
            let tasks = tasks.clone();
            let metrics = metrics.clone();
            async move {
                println!("[TaskStore] Storing task {} with priority {}", event.id, event.priority);
                
                // Simulate validation delay
                sleep(Duration::from_millis(10)).await;
                
                let task_info = TaskInfo {
                    id: event.id,
                    name: event.name.clone(),
                    status: TaskStatus::Pending,
                    assigned_worker: None,
                    retry_count: 0,
                    created_at: event.created_at,
                    started_at: None,
                    completed_at: None,
                };
                
                tasks.write().unwrap().insert(event.id, task_info);
                
                let metrics_lock = metrics.lock().await;
                metrics_lock.total_tasks.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Task scheduler - assigns tasks to workers
        let tasks = self.tasks.clone();
        let workers = self.workers.clone();
        let event_bus = self.event_bus.clone();
        let semaphore = self.task_semaphore.clone();
        self.event_bus.on_async::<TaskCreated, _, _>(move |event: TaskCreated| {
            let tasks = tasks.clone();
            let workers = workers.clone();
            let event_bus = event_bus.clone();
            let semaphore = semaphore.clone();
            async move {
                // Wait for available capacity
                let _permit = semaphore.acquire().await.unwrap();
                
                // Simulate scheduling delay
                sleep(Duration::from_millis(50)).await;
                
                // Find available worker
                let worker_id = {
                    let workers_lock = workers.read().unwrap();
                    workers_lock
                        .iter()
                        .filter(|(_, w)| w.status == WorkerStatus::Idle || w.status == WorkerStatus::Busy)
                        .filter(|(_, w)| w.active_tasks.len() < w.max_concurrent_tasks)
                        .min_by_key(|(_, w)| w.active_tasks.len())
                        .map(|(id, _)| id.clone())
                };
                
                if let Some(worker_id) = worker_id {
                    println!("[Scheduler] Assigning task {} to worker {}", event.id, worker_id);
                    
                    // Update task assignment
                    {
                        let mut tasks_lock = tasks.write().unwrap();
                        if let Some(task) = tasks_lock.get_mut(&event.id) {
                            task.assigned_worker = Some(worker_id.clone());
                            task.status = TaskStatus::Running;
                            task.started_at = Some(Utc::now());
                        }
                    }
                    
                    // Update worker
                    {
                        let mut workers_lock = workers.write().unwrap();
                        if let Some(worker) = workers_lock.get_mut(&worker_id) {
                            worker.active_tasks.push(event.id);
                            if worker.active_tasks.len() >= worker.max_concurrent_tasks - 1 {
                                worker.status = WorkerStatus::Overloaded;
                            } else {
                                worker.status = WorkerStatus::Busy;
                            }
                        }
                    }
                    
                    // Emit task started event
                    event_bus.emit_async(TaskStarted {
                        id: event.id,
                        worker_id: worker_id.clone(),
                        started_at: Utc::now(),
                    }).await;
                } else {
                    println!("[Scheduler] No available workers for task {}", event.id);
                }
            }
        });

        // Worker simulator - processes tasks
        let tasks = self.tasks.clone();
        let workers = self.workers.clone();
        let event_bus = self.event_bus.clone();
        self.event_bus.on_async::<TaskStarted, _, _>(move |event: TaskStarted| {
            let tasks = tasks.clone();
            let workers = workers.clone();
            let event_bus = event_bus.clone();
            async move {
                let start_time = Instant::now();
                println!("[Worker {}] Starting task {}", event.worker_id, event.id);
                
                // Simulate task processing with timeout
                let processing_result = timeout(
                    Duration::from_secs(5),
                    simulate_task_processing(&event.worker_id, event.id)
                ).await;
                
                let duration_ms = start_time.elapsed().as_millis() as u64;
                
                match processing_result {
                    Ok(Ok(result)) => {
                        println!("[Worker {}] Task {} completed in {}ms", 
                            event.worker_id, event.id, duration_ms);
                        
                        event_bus.emit_async(TaskCompleted {
                            id: event.id,
                            worker_id: event.worker_id.clone(),
                            result,
                            duration_ms,
                            completed_at: Utc::now(),
                        }).await;
                    },
                    Ok(Err(error)) => {
                        let error_msg = error.to_string();
                        println!("[Worker {}] Task {} failed: {}", 
                            event.worker_id, event.id, error_msg);
                        
                        let retry_count = tasks.read().unwrap()
                            .get(&event.id)
                            .map(|t| t.retry_count)
                            .unwrap_or(0);
                        
                        event_bus.emit_async(TaskFailed {
                            id: event.id,
                            worker_id: event.worker_id.clone(),
                            error: error_msg,
                            retry_count,
                            failed_at: Utc::now(),
                        }).await;
                    }
                    Err(_) => {
                        let error_msg = "Task timeout".to_string();
                            
                        println!("[Worker {}] Task {} failed: {}", 
                            event.worker_id, event.id, error_msg);
                        
                        let retry_count = tasks.read().unwrap()
                            .get(&event.id)
                            .map(|t| t.retry_count)
                            .unwrap_or(0);
                        
                        event_bus.emit_async(TaskFailed {
                            id: event.id,
                            worker_id: event.worker_id.clone(),
                            error: error_msg,
                            retry_count,
                            failed_at: Utc::now(),
                        }).await;
                    }
                }
                
                // Update worker status
                {
                    let mut workers_lock = workers.write().unwrap();
                    if let Some(worker) = workers_lock.get_mut(&event.worker_id) {
                        worker.active_tasks.retain(|&id| id != event.id);
                        worker.status = if worker.active_tasks.is_empty() {
                            WorkerStatus::Idle
                        } else {
                            WorkerStatus::Busy
                        };
                        
                        // Emit worker status change
                        event_bus.emit(&WorkerStatusChanged {
                            worker_id: event.worker_id.clone(),
                            status: worker.status.clone(),
                            active_tasks: worker.active_tasks.len(),
                            timestamp: Utc::now(),
                        });
                    }
                }
            }
        });

        // Metrics collector
        let metrics = self.metrics.clone();
        let event_bus = self.event_bus.clone();
        let workers = self.workers.clone();
        self.event_bus.on_async::<TaskCompleted, _, _>(move |event: TaskCompleted| {
            let metrics = metrics.clone();
            let event_bus = event_bus.clone();
            let workers = workers.clone();
            async move {
                let mut metrics_lock = metrics.lock().await;
                metrics_lock.completed_tasks.fetch_add(1, Ordering::SeqCst);
                metrics_lock.total_duration_ms.fetch_add(event.duration_ms, Ordering::SeqCst);
                metrics_lock.task_durations.push(event.duration_ms);
                
                // Calculate average duration
                let avg_duration = if metrics_lock.task_durations.is_empty() {
                    0.0
                } else {
                    metrics_lock.task_durations.iter().sum::<u64>() as f64 
                        / metrics_lock.task_durations.len() as f64
                };
                
                let total_tasks = metrics_lock.total_tasks.load(Ordering::SeqCst);
                let completed_tasks = metrics_lock.completed_tasks.load(Ordering::SeqCst);
                let failed_tasks = metrics_lock.failed_tasks.load(Ordering::SeqCst);
                let workers_online = workers.read().unwrap()
                    .values()
                    .filter(|w| w.status != WorkerStatus::Offline)
                    .count();
                
                // Emit metrics update
                event_bus.emit(&SystemMetricsUpdated {
                    total_tasks,
                    completed_tasks,
                    failed_tasks,
                    average_duration_ms: avg_duration,
                    workers_online,
                    timestamp: Utc::now(),
                });
            }
        });

        // Retry handler for failed tasks
        let tasks = self.tasks.clone();
        let event_bus = self.event_bus.clone();
        self.event_bus.on_async::<TaskFailed, _, _>(move |event: TaskFailed| {
            let tasks = tasks.clone();
            let event_bus = event_bus.clone();
            async move {
                if event.retry_count < 3 {
                    println!("[RetryHandler] Scheduling retry {} for task {}", 
                        event.retry_count + 1, event.id);
                    
                    // Wait before retry
                    sleep(Duration::from_secs(2u64.pow(event.retry_count))).await;
                    
                    // Update retry count
                    {
                        let mut tasks_lock = tasks.write().unwrap();
                        if let Some(task) = tasks_lock.get_mut(&event.id) {
                            task.retry_count += 1;
                            task.status = TaskStatus::Pending;
                            task.assigned_worker = None;
                        }
                    }
                    
                    // Re-emit task created event for retry
                    let task_info = {
                        tasks.read().unwrap()
                            .get(&event.id)
                            .map(|task| (task.name.clone(), task.created_at))
                    };
                    
                    if let Some((name, created_at)) = task_info {
                        event_bus.emit_async(TaskCreated {
                            id: event.id,
                            name,
                            priority: 10, // Higher priority for retries
                            data: vec![], // Original data would be stored
                            created_at,
                        }).await;
                    }
                } else {
                    println!("[RetryHandler] Task {} exceeded max retries", event.id);
                    let mut tasks_lock = tasks.write().unwrap();
                    if let Some(task) = tasks_lock.get_mut(&event.id) {
                        task.status = TaskStatus::Failed;
                        task.completed_at = Some(Utc::now());
                    }
                }
            }
        });

        // Auto-cleanup handler using auto-unsubscribe
        let cleanup_bus = Arc::new(self.event_bus.clone());
        let tasks = self.tasks.clone();
        let _cleanup_handle = cleanup_bus.on_auto::<SystemMetricsUpdated, _>(move |event| {
            if event.completed_tasks + event.failed_tasks > 1000 {
                println!("[Cleanup] Removing old completed tasks");
                let mut tasks_lock = tasks.write().unwrap();
                tasks_lock.retain(|_, task| {
                    task.status == TaskStatus::Pending || task.status == TaskStatus::Running
                });
            }
        });
    }

    pub async fn add_worker(&self, worker_id: String, max_concurrent_tasks: usize) {
        let worker_info = WorkerInfo {
            id: worker_id.clone(),
            status: WorkerStatus::Idle,
            active_tasks: Vec::new(),
            max_concurrent_tasks,
            last_heartbeat: Instant::now(),
        };
        
        self.workers.write().unwrap().insert(worker_id.clone(), worker_info);
        
        self.event_bus.emit(&WorkerStatusChanged {
            worker_id,
            status: WorkerStatus::Idle,
            active_tasks: 0,
            timestamp: Utc::now(),
        });
    }

    pub async fn create_task(&self, name: String, priority: i32, data: Vec<u8>) -> u64 {
        let task_id = self.next_task_id.fetch_add(1, Ordering::SeqCst);
        
        self.event_bus.emit_async(TaskCreated {
            id: task_id,
            name,
            priority,
            data,
            created_at: Utc::now(),
        }).await;
        
        task_id
    }
}

// Simulate task processing
async fn simulate_task_processing(worker_id: &str, task_id: u64) -> Result<TaskResult, String> {
    // Simulate different processing times and outcomes
    let processing_time = Duration::from_millis(100 + (task_id % 10) * 100);
    sleep(processing_time).await;
    
    match task_id % 5 {
        0 => Err("Simulated error".to_string()),
        1 => Ok(TaskResult::Cached(format!("Cached result for task {}", task_id))),
        2 => Ok(TaskResult::PartialSuccess(
            format!("Partial result for task {}", task_id),
            vec!["Warning: Some data was skipped".to_string()]
        )),
        _ => Ok(TaskResult::Success(format!("Completed by worker {}", worker_id))),
    }
}

#[tokio::main]
async fn main() {
    println!("=== Complex Async Event System Demo ===\n");
    
    // Create the task processing system
    let system = TaskProcessingSystem::new(10);
    
    // Add some workers
    for i in 1..=3 {
        system.add_worker(format!("worker-{}", i), 3).await;
    }
    
    // Set up a monitoring handler
    let monitor_counter = Arc::new(AtomicUsize::new(0));
    let monitor_counter_clone = monitor_counter.clone();
    system.event_bus.on::<SystemMetricsUpdated, _>(move |event| {
        let count = monitor_counter_clone.fetch_add(1, Ordering::SeqCst);
        if count % 5 == 0 { // Print every 5th update
            println!("\n[Monitor] System Metrics Update:");
            println!("  Total tasks: {}", event.total_tasks);
            println!("  Completed: {}", event.completed_tasks);
            println!("  Failed: {}", event.failed_tasks);
            println!("  Avg duration: {:.2}ms", event.average_duration_ms);
            println!("  Workers online: {}\n", event.workers_online);
        }
    });
    
    // Create tasks concurrently
    let mut task_futures = Vec::new();
    for i in 0..20 {
        let system_clone = system.clone();
        let future = tokio::spawn(async move {
            let priority = if i % 4 == 0 { 100 } else { 50 };
            system_clone.create_task(
                format!("Task-{}", i),
                priority,
                vec![i as u8; 100]
            ).await
        });
        task_futures.push(future);
    }
    
    // Wait for all tasks to be created
    join_all(task_futures).await;
    
    // Let the system process for a while
    println!("\nProcessing tasks...\n");
    sleep(Duration::from_secs(10)).await;
    
    // Simulate a worker going offline
    {
        let mut workers = system.workers.write().unwrap();
        if let Some(worker) = workers.get_mut("worker-2") {
            worker.status = WorkerStatus::Offline;
            println!("[System] Worker-2 went offline!");
        }
    }
    
    // Create more tasks to see how the system handles with one less worker
    for i in 20..25 {
        system.create_task(
            format!("Task-{}", i),
            75,
            vec![i as u8; 50]
        ).await;
    }
    
    // Wait for completion
    sleep(Duration::from_secs(5)).await;
    
    // Final status
    println!("\n=== Final System State ===");
    let tasks = system.tasks.read().unwrap();
    let pending = tasks.values().filter(|t| t.status == TaskStatus::Pending).count();
    let running = tasks.values().filter(|t| t.status == TaskStatus::Running).count();
    let completed = tasks.values().filter(|t| t.status == TaskStatus::Completed).count();
    let failed = tasks.values().filter(|t| t.status == TaskStatus::Failed).count();
    
    println!("Tasks - Pending: {}, Running: {}, Completed: {}, Failed: {}", 
        pending, running, completed, failed);
    
    for (id, worker) in system.workers.read().unwrap().iter() {
        println!("Worker {} - Status: {:?}, Active tasks: {}", 
            id, worker.status, worker.active_tasks.len());
    }
}

// Required dependencies for Cargo.toml:
// [dependencies]
// tokio = { version = "1", features = ["full"] }
// futures = "0.3"
// chrono = { version = "0.4", features = ["serde"] }
// # Plus the event_system dependencies