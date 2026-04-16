use prost::{Message, Oneof};

pub(crate) const RAW_EVENT_INSTRUCTION: u8 = 1;
pub(crate) const RAW_EVENT_MEM_ACCESS: u8 = 2;
pub(crate) const RAW_EVENT_EXTERNAL_RETURN: u8 = 3;
pub(crate) const RAW_EVENT_DYNAMIC_EXEC_CHUNK: u8 = 4;
pub(crate) const RAW_EVENT_TRACE_CONTEXT: u8 = 5;
pub(crate) const RAW_EVENT_TRACE_BUNDLE_METADATA: u8 = 6;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MemAccess {
    #[prost(uint64, tag = "1")]
    pub(crate) inst_addr: u64,
    #[prost(uint64, tag = "2")]
    pub(crate) access_addr: u64,
    #[prost(uint64, tag = "3")]
    pub(crate) value: u64,
    #[prost(uint32, tag = "4")]
    pub(crate) size: u32,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct ExternalReturn {
    #[prost(uint64, tag = "1")]
    pub(crate) return_addr: u64,
    #[prost(uint64, tag = "2")]
    pub(crate) return_value: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct DynamicExecChunk {
    #[prost(uint64, tag = "1")]
    pub(crate) start_addr: u64,
    #[prost(uint64, tag = "2")]
    pub(crate) end_addr: u64,
    #[prost(uint32, tag = "3")]
    pub(crate) perm: u32,
    #[prost(string, tag = "4")]
    pub(crate) path: String,
    #[prost(uint64, tag = "5")]
    pub(crate) chunk_offset: u64,
    #[prost(bytes, tag = "6")]
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct TraceContext {
    #[prost(uint64, repeated, tag = "1")]
    pub(crate) x: Vec<u64>,
    #[prost(uint64, tag = "2")]
    pub(crate) sp: u64,
    #[prost(uint64, tag = "3")]
    pub(crate) pc: u64,
    #[prost(uint64, tag = "4")]
    pub(crate) nzcv: u64,
    #[prost(uint64, tag = "5")]
    pub(crate) tpidr_el0: u64,
    #[prost(uint64, repeated, tag = "6")]
    pub(crate) q: Vec<u64>,
    #[prost(uint64, tag = "7")]
    pub(crate) fpcr: u64,
    #[prost(uint64, tag = "8")]
    pub(crate) fpsr: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct TraceBundleMetadata {
    #[prost(string, tag = "1")]
    pub(crate) module_path: String,
    #[prost(uint64, tag = "2")]
    pub(crate) module_base: u64,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct TraceBundleEvent {
    #[prost(oneof = "TraceBundleEventKind", tags = "1, 2, 3, 4, 5, 6")]
    pub(crate) kind: Option<TraceBundleEventKind>,
}

#[derive(Clone, PartialEq, Oneof)]
pub(crate) enum TraceBundleEventKind {
    #[prost(uint64, tag = "1")]
    InstructionAddr(u64),
    #[prost(message, tag = "2")]
    MemAccess(MemAccess),
    #[prost(message, tag = "3")]
    ExternalReturn(ExternalReturn),
    #[prost(message, tag = "4")]
    DynamicExecChunk(DynamicExecChunk),
    #[prost(message, tag = "5")]
    TraceContext(TraceContext),
    #[prost(message, tag = "6")]
    TraceBundleMetadata(TraceBundleMetadata),
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn read_u32(cursor: &mut usize, data: &[u8]) -> Result<u32, String> {
    let end = *cursor + 4;
    let bytes = data
        .get(*cursor..end)
        .ok_or_else(|| "raw chunk truncated while reading u32".to_string())?;
    *cursor = end;
    Ok(u32::from_le_bytes(bytes.try_into().expect("slice len is 4")))
}

fn read_u64(cursor: &mut usize, data: &[u8]) -> Result<u64, String> {
    let end = *cursor + 8;
    let bytes = data
        .get(*cursor..end)
        .ok_or_else(|| "raw chunk truncated while reading u64".to_string())?;
    *cursor = end;
    Ok(u64::from_le_bytes(bytes.try_into().expect("slice len is 8")))
}

fn read_bytes(cursor: &mut usize, data: &[u8], len: usize) -> Result<Vec<u8>, String> {
    let end = *cursor + len;
    let bytes = data
        .get(*cursor..end)
        .ok_or_else(|| "raw chunk truncated while reading bytes".to_string())?;
    *cursor = end;
    Ok(bytes.to_vec())
}

pub(crate) fn raw_event_size(event: &TraceBundleEvent) -> usize {
    match event.kind.as_ref().expect("trace event kind exists") {
        TraceBundleEventKind::InstructionAddr(_) => 1 + 8,
        TraceBundleEventKind::MemAccess(_) => 1 + 8 + 8 + 8 + 4,
        TraceBundleEventKind::ExternalReturn(_) => 1 + 8 + 8,
        TraceBundleEventKind::DynamicExecChunk(chunk) => {
            1 + 8 + 8 + 4 + 8 + 4 + 4 + chunk.path.len() + chunk.data.len()
        }
        TraceBundleEventKind::TraceContext(_) => 1 + (31 + 4 + 64 + 2) * 8,
        TraceBundleEventKind::TraceBundleMetadata(meta) => 1 + 4 + meta.module_path.len() + 8,
    }
}

pub(crate) fn encode_raw_event_into(buf: &mut Vec<u8>, event: &TraceBundleEvent) {
    match event.kind.as_ref().expect("trace event kind exists") {
        TraceBundleEventKind::InstructionAddr(addr) => {
            buf.push(RAW_EVENT_INSTRUCTION);
            put_u64(buf, *addr);
        }
        TraceBundleEventKind::MemAccess(access) => {
            buf.push(RAW_EVENT_MEM_ACCESS);
            put_u64(buf, access.inst_addr);
            put_u64(buf, access.access_addr);
            put_u64(buf, access.value);
            put_u32(buf, access.size);
        }
        TraceBundleEventKind::ExternalReturn(ret) => {
            buf.push(RAW_EVENT_EXTERNAL_RETURN);
            put_u64(buf, ret.return_addr);
            put_u64(buf, ret.return_value);
        }
        TraceBundleEventKind::DynamicExecChunk(chunk) => {
            buf.push(RAW_EVENT_DYNAMIC_EXEC_CHUNK);
            put_u64(buf, chunk.start_addr);
            put_u64(buf, chunk.end_addr);
            put_u32(buf, chunk.perm);
            put_u64(buf, chunk.chunk_offset);
            put_u32(buf, chunk.path.len() as u32);
            put_u32(buf, chunk.data.len() as u32);
            buf.extend_from_slice(chunk.path.as_bytes());
            buf.extend_from_slice(&chunk.data);
        }
        TraceBundleEventKind::TraceContext(ctx) => {
            buf.push(RAW_EVENT_TRACE_CONTEXT);
            for reg in &ctx.x {
                put_u64(buf, *reg);
            }
            put_u64(buf, ctx.sp);
            put_u64(buf, ctx.pc);
            put_u64(buf, ctx.nzcv);
            put_u64(buf, ctx.tpidr_el0);
            for word in &ctx.q {
                put_u64(buf, *word);
            }
            put_u64(buf, ctx.fpcr);
            put_u64(buf, ctx.fpsr);
        }
        TraceBundleEventKind::TraceBundleMetadata(meta) => {
            buf.push(RAW_EVENT_TRACE_BUNDLE_METADATA);
            put_u32(buf, meta.module_path.len() as u32);
            buf.extend_from_slice(meta.module_path.as_bytes());
            put_u64(buf, meta.module_base);
        }
    }
}

pub(crate) fn encode_raw_event_chunk(event: &TraceBundleEvent) -> Vec<u8> {
    let mut payload = Vec::with_capacity(raw_event_size(event));
    encode_raw_event_into(&mut payload, event);
    payload
}

pub(crate) fn transcode_raw_chunk(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = 0usize;
    let mut payload = Vec::with_capacity(raw.len());
    while cursor < raw.len() {
        let tag = *raw
            .get(cursor)
            .ok_or_else(|| "raw chunk truncated while reading tag".to_string())?;
        cursor += 1;
        let event = match tag {
            RAW_EVENT_INSTRUCTION => TraceBundleEvent {
                kind: Some(TraceBundleEventKind::InstructionAddr(read_u64(&mut cursor, raw)?)),
            },
            RAW_EVENT_MEM_ACCESS => TraceBundleEvent {
                kind: Some(TraceBundleEventKind::MemAccess(MemAccess {
                    inst_addr: read_u64(&mut cursor, raw)?,
                    access_addr: read_u64(&mut cursor, raw)?,
                    value: read_u64(&mut cursor, raw)?,
                    size: read_u32(&mut cursor, raw)?,
                })),
            },
            RAW_EVENT_EXTERNAL_RETURN => TraceBundleEvent {
                kind: Some(TraceBundleEventKind::ExternalReturn(ExternalReturn {
                    return_addr: read_u64(&mut cursor, raw)?,
                    return_value: read_u64(&mut cursor, raw)?,
                })),
            },
            RAW_EVENT_DYNAMIC_EXEC_CHUNK => {
                let start_addr = read_u64(&mut cursor, raw)?;
                let end_addr = read_u64(&mut cursor, raw)?;
                let perm = read_u32(&mut cursor, raw)?;
                let chunk_offset = read_u64(&mut cursor, raw)?;
                let path_len = read_u32(&mut cursor, raw)? as usize;
                let data_len = read_u32(&mut cursor, raw)? as usize;
                let path = String::from_utf8(read_bytes(&mut cursor, raw, path_len)?)
                    .map_err(|_| "raw chunk path is not utf-8".to_string())?;
                let data = read_bytes(&mut cursor, raw, data_len)?;
                TraceBundleEvent {
                    kind: Some(TraceBundleEventKind::DynamicExecChunk(DynamicExecChunk {
                        start_addr,
                        end_addr,
                        perm,
                        path,
                        chunk_offset,
                        data,
                    })),
                }
            }
            RAW_EVENT_TRACE_CONTEXT => TraceBundleEvent {
                kind: Some(TraceBundleEventKind::TraceContext(TraceContext {
                    x: (0..31)
                        .map(|_| read_u64(&mut cursor, raw))
                        .collect::<Result<Vec<_>, _>>()?,
                    sp: read_u64(&mut cursor, raw)?,
                    pc: read_u64(&mut cursor, raw)?,
                    nzcv: read_u64(&mut cursor, raw)?,
                    tpidr_el0: read_u64(&mut cursor, raw)?,
                    q: (0..64)
                        .map(|_| read_u64(&mut cursor, raw))
                        .collect::<Result<Vec<_>, _>>()?,
                    fpcr: read_u64(&mut cursor, raw)?,
                    fpsr: read_u64(&mut cursor, raw)?,
                })),
            },
            RAW_EVENT_TRACE_BUNDLE_METADATA => {
                let path_len = read_u32(&mut cursor, raw)? as usize;
                let module_path = String::from_utf8(read_bytes(&mut cursor, raw, path_len)?)
                    .map_err(|_| "raw metadata path is not utf-8".to_string())?;
                let module_base = read_u64(&mut cursor, raw)?;
                TraceBundleEvent {
                    kind: Some(TraceBundleEventKind::TraceBundleMetadata(TraceBundleMetadata {
                        module_path,
                        module_base,
                    })),
                }
            }
            other => return Err(format!("unknown raw event tag {}", other)),
        };
        event
            .encode_length_delimited(&mut payload)
            .map_err(|_| "encode bundle event failed".to_string())?;
    }
    Ok(payload)
}
