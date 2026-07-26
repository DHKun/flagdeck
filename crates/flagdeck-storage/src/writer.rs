//! 单写线程运行时：`ProjectStore` 的所有写入经一个专属线程串行执行。
//! `WriterRuntime` 持有有界队列的发送端与线程句柄，`call` 把闭包投递给写线程并取回结果
//! （`Box<dyn Any>` 类型擦除 + downcast）。从单文件的 storage crate 里析出，逻辑不变。

use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::{self, JoinHandle};

use rusqlite::Connection;

use crate::{StorageError, WRITER_QUEUE_CAPACITY, open_writer_connection};

type WriteResult = Result<Box<dyn Any + Send>, StorageError>;
type WriteOperation = Box<dyn FnOnce(&mut Connection) -> WriteResult + Send>;

enum WriterCommand {
    Execute(WriteOperation, SyncSender<WriteResult>),
    Shutdown,
}

pub(crate) struct WriterRuntime {
    sender: SyncSender<WriterCommand>,
    join: Option<JoinHandle<()>>,
}

impl WriterRuntime {
    pub(crate) fn start(database: PathBuf) -> Result<Self, StorageError> {
        let (sender, receiver) = sync_channel(WRITER_QUEUE_CAPACITY);
        let (ready_sender, ready_receiver) = sync_channel(1);
        let join = thread::spawn(move || writer_loop(&database, &receiver, &ready_sender));
        ready_receiver
            .recv()
            .map_err(|_| StorageError::WriterStopped)??;
        Ok(Self {
            sender,
            join: Some(join),
        })
    }

    pub(crate) fn call<T, F>(&self, operation: F) -> Result<T, StorageError>
    where
        T: Any + Send,
        F: FnOnce(&mut Connection) -> Result<T, StorageError> + Send + 'static,
    {
        let (response_sender, response_receiver) = sync_channel(1);
        let erased: WriteOperation = Box::new(move |connection| {
            operation(connection).map(|value| Box::new(value) as Box<dyn Any + Send>)
        });
        self.sender
            .send(WriterCommand::Execute(erased, response_sender))
            .map_err(|_| StorageError::WriterStopped)?;
        let value = response_receiver
            .recv()
            .map_err(|_| StorageError::WriterStopped)??;
        value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| StorageError::WriterType)
    }
}

impl Drop for WriterRuntime {
    fn drop(&mut self) {
        let _ = self.sender.send(WriterCommand::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn writer_loop(
    database: &Path,
    receiver: &Receiver<WriterCommand>,
    ready: &SyncSender<Result<(), StorageError>>,
) {
    let mut connection = match open_writer_connection(database) {
        Ok(connection) => {
            let _ = ready.send(Ok(()));
            connection
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    while let Ok(command) = receiver.recv() {
        match command {
            WriterCommand::Execute(operation, response) => {
                let _ = response.send(operation(&mut connection));
            }
            WriterCommand::Shutdown => break,
        }
    }
}
