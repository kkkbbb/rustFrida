use crate::data::{
    encode_raw_event_chunk, encode_raw_event_into, raw_event_size, transcode_raw_chunk, TraceBundleEvent,
    TraceBundleEventKind,
};
use crate::state::{
    helper_log, log_trace_stats, reset_trace_stats, update_max, TraceChunk, TraceWriter, TRACE_CHUNK_SIZE,
    TRACE_FINALIZERS, TRACE_MAX_CHUNK_BYTES, TRACE_MERGE_NS, TRACE_NEXT_SEQ, TRACE_OUTPUT_DIR, TRACE_PUBLISHED_SESSION,
    TRACE_PUBLISH_LOCK, TRACE_QUEUE_BUDGET, TRACE_SESSION_SEQ, TRACE_SHARDS, TRACE_TRANSCODE_NS, TRACE_WRITER,
};
use crossbeam_channel::unbounded;
use std::fs::{remove_file, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::atomic::Ordering;
use std::thread;

thread_local! {
    pub(crate) static TRACE_CHUNK_BUFFER: std::cell::RefCell<Vec<u8>> =
        std::cell::RefCell::new(Vec::with_capacity(TRACE_CHUNK_SIZE));
}

pub(crate) fn shard_path(base: &str, session_id: u64, shard: usize) -> String {
    format!("{}/trace_bundle.pb.s{}.part{}", base, session_id, shard)
}

pub(crate) fn dynamic_shard_path(base: &str, session_id: u64, shard: usize) -> String {
    format!("{}/trace_bundle.dynamic.s{}.part{}", base, session_id, shard)
}

pub(crate) fn merged_bundle_tmp_path(base: &str, session_id: u64) -> String {
    format!("{}/trace_bundle.pb.s{}.tmp", base, session_id)
}

pub(crate) fn final_trace_path(base: &str) -> String {
    format!("{}/trace_bundle.pb", base)
}

fn spawn_trace_writer(base: &str, session_id: u64) -> Result<TraceWriter, String> {
    let mut shard_senders = Vec::with_capacity(TRACE_SHARDS);
    let mut dynamic_senders = Vec::with_capacity(TRACE_SHARDS);
    let mut joins = Vec::with_capacity(TRACE_SHARDS);

    for shard in 0..TRACE_SHARDS {
        let (sender, receiver) = unbounded::<TraceChunk>();
        let path = shard_path(base, session_id, shard);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|err| format!("open {} failed: {}", path, err))?;
        let join = thread::spawn(move || {
            let mut writer = BufWriter::new(file);
            let mut encoded = Vec::new();
            while let Ok(chunk) = receiver.recv() {
                let chunk_bytes = chunk.payload.len();
                encoded.clear();
                let transcode_start = std::time::Instant::now();
                let encoded_chunk = match transcode_raw_chunk(&chunk.payload) {
                    Ok(encoded_chunk) => encoded_chunk,
                    Err(err) => {
                        helper_log(&format!("[qbdi-helper] transcode raw chunk failed: {}", err));
                        TRACE_QUEUE_BUDGET.release(chunk_bytes);
                        continue;
                    }
                };
                TRACE_TRANSCODE_NS.fetch_add(transcode_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                encoded.extend_from_slice(&encoded_chunk);
                if writer.write_all(&chunk.seq.to_le_bytes()).is_err() {
                    helper_log("[qbdi-helper] write shard seq failed");
                    TRACE_QUEUE_BUDGET.release(chunk_bytes);
                    break;
                }
                let len = encoded.len() as u32;
                if writer.write_all(&len.to_le_bytes()).is_err() {
                    helper_log("[qbdi-helper] write shard len failed");
                    TRACE_QUEUE_BUDGET.release(chunk_bytes);
                    break;
                }
                if writer.write_all(&encoded).is_err() {
                    helper_log("[qbdi-helper] write shard payload failed");
                    TRACE_QUEUE_BUDGET.release(chunk_bytes);
                    break;
                }
                TRACE_QUEUE_BUDGET.release(chunk_bytes);
            }
            while let Ok(chunk) = receiver.try_recv() {
                TRACE_QUEUE_BUDGET.release(chunk.payload.len());
            }
            let _ = writer.flush();
        });
        shard_senders.push(sender);
        joins.push(join);
    }

    for shard in 0..TRACE_SHARDS {
        let (sender, receiver) = unbounded::<TraceChunk>();
        let path = dynamic_shard_path(base, session_id, shard);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|err| format!("open {} failed: {}", path, err))?;
        let join = thread::spawn(move || {
            let mut writer = BufWriter::new(file);
            let mut encoded = Vec::new();
            while let Ok(chunk) = receiver.recv() {
                let chunk_bytes = chunk.payload.len();
                encoded.clear();
                let transcode_start = std::time::Instant::now();
                let encoded_chunk = match transcode_raw_chunk(&chunk.payload) {
                    Ok(encoded_chunk) => encoded_chunk,
                    Err(err) => {
                        helper_log(&format!("[qbdi-helper] dynamic transcode failed: {}", err));
                        TRACE_QUEUE_BUDGET.release(chunk_bytes);
                        continue;
                    }
                };
                TRACE_TRANSCODE_NS.fetch_add(transcode_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                encoded.extend_from_slice(&encoded_chunk);
                if writer.write_all(&chunk.seq.to_le_bytes()).is_err() {
                    helper_log("[qbdi-helper] write dynamic shard seq failed");
                    TRACE_QUEUE_BUDGET.release(chunk_bytes);
                    break;
                }
                let len = encoded.len() as u32;
                if writer.write_all(&len.to_le_bytes()).is_err() {
                    helper_log("[qbdi-helper] write dynamic shard len failed");
                    TRACE_QUEUE_BUDGET.release(chunk_bytes);
                    break;
                }
                if writer.write_all(&encoded).is_err() {
                    helper_log("[qbdi-helper] write dynamic shard payload failed");
                    TRACE_QUEUE_BUDGET.release(chunk_bytes);
                    break;
                }
                TRACE_QUEUE_BUDGET.release(chunk_bytes);
            }
            while let Ok(chunk) = receiver.try_recv() {
                TRACE_QUEUE_BUDGET.release(chunk.payload.len());
            }
            let _ = writer.flush();
        });
        dynamic_senders.push(sender);
        joins.push(join);
    }

    Ok(TraceWriter {
        session_id,
        shard_senders,
        dynamic_senders,
        joins,
        base: base.to_string(),
    })
}

fn reap_finished_finalizers() {
    let mut finalizers = TRACE_FINALIZERS.lock().unwrap_or_else(|e| e.into_inner());
    let mut idx = 0usize;
    while idx < finalizers.len() {
        if finalizers[idx].is_finished() {
            let handle = finalizers.swap_remove(idx);
            let _ = handle.join();
        } else {
            idx += 1;
        }
    }
}

pub(crate) fn start_trace_writer() -> Result<(), String> {
    let Some(base) = TRACE_OUTPUT_DIR.get() else {
        return Err("output dir not set".to_string());
    };
    reap_finished_finalizers();
    let mut guard = TRACE_WRITER.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return Err("trace session already active".to_string());
    }
    let session_id = TRACE_SESSION_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    TRACE_NEXT_SEQ.store(0, Ordering::Relaxed);
    reset_trace_stats();
    let writer = spawn_trace_writer(base, session_id)?;
    *guard = Some(writer);
    Ok(())
}

fn submit_chunk(payload: Vec<u8>) {
    submit_chunk_inner(payload, false);
}

fn submit_dynamic_chunk(payload: Vec<u8>) {
    submit_chunk_inner(payload, true);
}

fn submit_chunk_inner(payload: Vec<u8>, dynamic: bool) {
    if payload.is_empty() {
        return;
    }
    let seq = TRACE_NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
    let shard = (seq as usize) % TRACE_SHARDS;
    let payload_len = payload.len();
    update_max(&TRACE_MAX_CHUNK_BYTES, payload_len as u64);
    let sender = {
        let guard = TRACE_WRITER.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .and_then(|writer| {
                if dynamic {
                    writer.dynamic_senders.get(shard)
                } else {
                    writer.shard_senders.get(shard)
                }
            })
            .cloned()
    };
    match sender {
        Some(sender) => {
            TRACE_QUEUE_BUDGET.reserve(payload_len);
            match sender.send(TraceChunk { seq, payload }) {
                Ok(()) => {
                    if dynamic {
                        crate::state::TRACE_DYNAMIC_CHUNKS_SUBMITTED.fetch_add(1, Ordering::Relaxed);
                    } else {
                        crate::state::TRACE_CHUNKS_SUBMITTED.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(err) => {
                    let chunk = err.into_inner();
                    TRACE_QUEUE_BUDGET.release(payload_len);
                    if dynamic {
                        crate::state::TRACE_DYNAMIC_CHUNKS_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
                        crate::state::TRACE_DYNAMIC_BYTES_DROPPED_DISCONNECTED
                            .fetch_add(chunk.payload.len() as u64, Ordering::Relaxed);
                    } else {
                        crate::state::TRACE_CHUNKS_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
                        crate::state::TRACE_BYTES_DROPPED_DISCONNECTED
                            .fetch_add(chunk.payload.len() as u64, Ordering::Relaxed);
                    }
                }
            }
        }
        None => helper_log("[qbdi-helper] shard sender missing"),
    }
}

pub(crate) fn flush_thread_local_chunk() {
    TRACE_CHUNK_BUFFER.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        if !buffer.is_empty() {
            let payload = std::mem::take(&mut *buffer);
            buffer.reserve(TRACE_CHUNK_SIZE);
            submit_chunk(payload);
        }
    });
}

pub(crate) fn trace_send(event: TraceBundleEvent) {
    let raw_len = raw_event_size(&event);
    crate::state::TRACE_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::state::TRACE_RAW_BYTES.fetch_add(raw_len as u64, Ordering::Relaxed);
    if raw_len > TRACE_CHUNK_SIZE {
        match event.kind.as_ref().expect("trace event kind exists") {
            TraceBundleEventKind::DynamicExecChunk(_) => submit_dynamic_chunk(encode_raw_event_chunk(&event)),
            _ => submit_chunk(encode_raw_event_chunk(&event)),
        }
        return;
    }

    TRACE_CHUNK_BUFFER.with(|buffer| {
        let mut buffer = buffer.borrow_mut();
        if buffer.len() + raw_len > TRACE_CHUNK_SIZE {
            let payload = std::mem::take(&mut *buffer);
            buffer.reserve(TRACE_CHUNK_SIZE);
            submit_chunk(payload);
        }
        match event.kind.as_ref().expect("trace event kind exists") {
            TraceBundleEventKind::DynamicExecChunk(_) => submit_dynamic_chunk(encode_raw_event_chunk(&event)),
            _ => encode_raw_event_into(&mut *buffer, &event),
        }
    });
}

fn read_shard_chunk(reader: &mut BufReader<File>) -> std::io::Result<Option<TraceChunk>> {
    let mut seq_buf = [0u8; 8];
    match reader.read_exact(&mut seq_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(Some(TraceChunk {
        seq: u64::from_le_bytes(seq_buf),
        payload,
    }))
}

fn publish_merged_bundle(base: &str, session_id: u64, tmp_path: &str) -> Result<(), String> {
    let final_path = final_trace_path(base);
    let _guard = TRACE_PUBLISH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let published = TRACE_PUBLISHED_SESSION.load(Ordering::Relaxed);
    if session_id < published {
        let _ = remove_file(tmp_path);
        return Ok(());
    }
    std::fs::rename(tmp_path, &final_path).map_err(|err| format!("publish {} failed: {}", final_path, err))?;
    TRACE_PUBLISHED_SESSION.store(session_id, Ordering::Relaxed);
    Ok(())
}

fn merge_trace_shards(base: &str, session_id: u64) -> Result<(), String> {
    let merge_start = std::time::Instant::now();
    let tmp_path = merged_bundle_tmp_path(base, session_id);
    let mut final_file = BufWriter::new(
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|err| format!("open {} failed: {}", tmp_path, err))?,
    );
    final_file
        .write_all(crate::state::TRACE_BUNDLE_MAGIC)
        .map_err(|err| format!("write header failed: {}", err))?;

    let mut readers = Vec::with_capacity(TRACE_SHARDS);
    let mut current = Vec::with_capacity(TRACE_SHARDS);
    for shard in 0..TRACE_SHARDS {
        let path = shard_path(base, session_id, shard);
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|err| format!("open {} failed: {}", path, err))?;
        let mut reader = BufReader::new(file);
        let head = read_shard_chunk(&mut reader).map_err(|err| format!("read {} failed: {}", path, err))?;
        readers.push(reader);
        current.push(head);
    }
    for shard in 0..TRACE_SHARDS {
        let path = dynamic_shard_path(base, session_id, shard);
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|err| format!("open {} failed: {}", path, err))?;
        let mut reader = BufReader::new(file);
        let head = read_shard_chunk(&mut reader).map_err(|err| format!("read {} failed: {}", path, err))?;
        readers.push(reader);
        current.push(head);
    }

    loop {
        let next = current
            .iter()
            .enumerate()
            .filter_map(|(idx, chunk)| chunk.as_ref().map(|chunk| (idx, chunk.seq)))
            .min_by_key(|(_, seq)| *seq)
            .map(|(idx, _)| idx);
        let Some(idx) = next else {
            break;
        };
        let chunk = current[idx].take().expect("current shard chunk exists");
        final_file
            .write_all(&chunk.payload)
            .map_err(|err| format!("write {} failed: {}", tmp_path, err))?;
        current[idx] =
            read_shard_chunk(&mut readers[idx]).map_err(|err| format!("read shard {} failed: {}", idx, err))?;
    }

    final_file
        .flush()
        .map_err(|err| format!("flush {} failed: {}", tmp_path, err))?;
    for shard in 0..TRACE_SHARDS {
        let path = shard_path(base, session_id, shard);
        let _ = remove_file(&path);
        let path = dynamic_shard_path(base, session_id, shard);
        let _ = remove_file(&path);
    }
    TRACE_MERGE_NS.fetch_add(merge_start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    publish_merged_bundle(base, session_id, &tmp_path)?;
    Ok(())
}

fn finalize_trace_writer(writer: TraceWriter) {
    let session_id = writer.session_id;
    let base = writer.base.clone();
    drop(writer.shard_senders);
    drop(writer.dynamic_senders);
    for join in writer.joins {
        let _ = join.join();
    }
    if let Err(err) = merge_trace_shards(&base, session_id) {
        helper_log(&format!("[qbdi-helper] merge shards failed: {}", err));
    }
    log_trace_stats(&base);
}

pub(crate) fn finalize_trace_session_async() {
    flush_thread_local_chunk();
    let writer = {
        let mut guard = TRACE_WRITER.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if let Some(writer) = writer {
        let handle = std::thread::spawn(move || finalize_trace_writer(writer));
        TRACE_FINALIZERS.lock().unwrap_or_else(|e| e.into_inner()).push(handle);
    }
}

pub(crate) fn shutdown_trace_writer() {
    finalize_trace_session_async();
    let finalizers = {
        let mut guard = TRACE_FINALIZERS.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    };
    for handle in finalizers {
        let _ = handle.join();
    }
}
