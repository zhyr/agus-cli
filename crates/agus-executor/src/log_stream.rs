use serde::{Deserialize, Serialize};
use std::sync::mpsc;

/// 日志流消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessage {
    pub step_id: String,
    pub level: LogLevel,
    pub message: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Debug => "debug",
        }
    }
}

/// 日志流发送器
#[derive(Clone)]
pub struct LogStreamSender {
    sender: mpsc::Sender<LogMessage>,
}

impl LogStreamSender {
    pub fn new(sender: mpsc::Sender<LogMessage>) -> Self {
        Self { sender }
    }

    pub fn send(&self, step_id: &str, level: LogLevel, message: &str) {
        let log_msg = LogMessage {
            step_id: step_id.to_string(),
            level,
            message: message.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let _ = self.sender.send(log_msg);
    }

    pub fn info(&self, step_id: &str, message: &str) {
        self.send(step_id, LogLevel::Info, message);
    }

    pub fn warning(&self, step_id: &str, message: &str) {
        self.send(step_id, LogLevel::Warning, message);
    }

    pub fn error(&self, step_id: &str, message: &str) {
        self.send(step_id, LogLevel::Error, message);
    }

    pub fn debug(&self, step_id: &str, message: &str) {
        self.send(step_id, LogLevel::Debug, message);
    }
}

/// 日志流接收器
pub struct LogStreamReceiver {
    receiver: mpsc::Receiver<LogMessage>,
}

impl LogStreamReceiver {
    pub fn new(receiver: mpsc::Receiver<LogMessage>) -> Self {
        Self { receiver }
    }

    pub fn try_recv(&self) -> Result<LogMessage, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }

    pub fn recv(&self) -> Result<LogMessage, mpsc::RecvError> {
        self.receiver.recv()
    }

    pub fn recv_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<LogMessage, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    /// 获取内部的 receiver（用于转换为异步流）
    pub fn into_receiver(self) -> mpsc::Receiver<LogMessage> {
        self.receiver
    }
}

/// 创建日志流通道
pub fn create_log_stream() -> (LogStreamSender, LogStreamReceiver) {
    let (sender, receiver) = mpsc::channel();
    (
        LogStreamSender::new(sender),
        LogStreamReceiver::new(receiver),
    )
}

/// 空日志流（用于不需要日志流的场景）
pub struct NullLogStream;

impl NullLogStream {
    pub fn new() -> Self {
        Self
    }

    pub fn send(&self, _step_id: &str, _level: LogLevel, _message: &str) {
        // 什么都不做
    }

    pub fn info(&self, _step_id: &str, _message: &str) {}
    pub fn warning(&self, _step_id: &str, _message: &str) {}
    pub fn error(&self, _step_id: &str, _message: &str) {}
    pub fn debug(&self, _step_id: &str, _message: &str) {}
}
