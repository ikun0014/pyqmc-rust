use pyo3::prelude::*;
use pyo3::types::PyByteArray;

use crate::rc4::hash::hash;
use crate::rc4::rc4::RC4;
use crate::rc4::segment_key::get_segment_key;
use std::cmp::min;

const FIRST_SEGMENT_SIZE: usize = 0x0080;
const OTHER_SEGMENT_SIZE: usize = 0x1400;
const RC4_STREAM_CACHE_SIZE: usize = OTHER_SEGMENT_SIZE + 512;

#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct QMC2RC4 {
    hash: f64,
    key: Box<[u8]>,
    key_stream: Box<[u8; RC4_STREAM_CACHE_SIZE]>,
}

#[pymethods]
impl QMC2RC4 {
    #[new]
    pub fn new(key: Vec<u8>) -> Self {
        let mut rc4 = RC4::new(&key);
        let mut key_stream = Box::new([0u8; RC4_STREAM_CACHE_SIZE]);
        rc4.derive(&mut key_stream[..]);

        Self {
            hash: hash(&key),
            key: key.into_boxed_slice(),
            key_stream,
        }
    }

    // PyO3 方法接受 PyByteArray 的 Bound 引用
    pub fn decrypt(&self, data: Bound<'_, PyByteArray>, offset: usize) -> PyResult<()> {
        // 使用 as_bytes_mut 方法获取可变字节切片
        let buffer = unsafe { data.as_bytes_mut() };
        self.decrypt_internal(buffer, offset);
        Ok(())
    }
}

// 将内部实现方法移出 #[pymethods] 块
impl QMC2RC4 {
    fn process_first_segment(&self, data: &mut [u8], offset: usize) {
        let n = self.key.len();

        for (datum, offset) in data.iter_mut().zip(offset..) {
            let idx = get_segment_key(offset as u64, self.key[offset % n], self.hash);
            let idx = idx % (n as u64);
            *datum ^= self.key[idx as usize];
        }
    }

    fn process_other_segment(&self, data: &mut [u8], offset: usize) {
        let n = self.key.len();

        let id = offset / OTHER_SEGMENT_SIZE;
        let block_offset = offset % OTHER_SEGMENT_SIZE;

        let seed = self.key[id % n];
        let skip = get_segment_key(id as u64, seed, self.hash);
        let skip = (skip & 0x1FF) as usize;

        debug_assert!(data.len() <= OTHER_SEGMENT_SIZE - block_offset);
        let key_stream = self.key_stream.iter().skip(skip + block_offset);
        for (datum, &key) in data.iter_mut().zip(key_stream) {
            *datum ^= key;
        }
    }

    fn decrypt_internal(&self, buffer: &mut [u8], mut offset: usize) {
        let mut buffer = buffer;

        if offset < FIRST_SEGMENT_SIZE {
            let n = min(FIRST_SEGMENT_SIZE - offset, buffer.len());
            let (block, rest) = buffer.split_at_mut(n);
            buffer = rest;
            self.process_first_segment(block, offset);
            offset += n;
        }

        match offset % OTHER_SEGMENT_SIZE {
            0 => {} // we are already in the boundary, nothing to do.
            excess => {
                let n = min(OTHER_SEGMENT_SIZE - excess, buffer.len());
                let (block, rest) = buffer.split_at_mut(n);
                buffer = rest;
                self.process_other_segment(block, offset);
                offset += n;
            }
        };

        while !buffer.is_empty() {
            let n = min(OTHER_SEGMENT_SIZE, buffer.len());
            let (block, rest) = buffer.split_at_mut(n);
            buffer = rest;
            self.process_other_segment(block, offset);
            offset += n;
        }
    }
}