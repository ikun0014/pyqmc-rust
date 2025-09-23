use pyo3::prelude::*;
use pyo3::types::PyByteArray;

mod key;

use crate::v1::cipher::{qmc1_transform, V1_KEY_SIZE};
use crate::map::key::key_compress;
use crate::QmcCryptoError;

#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub struct QMC2Map {
    key: [u8; V1_KEY_SIZE],
}

#[pymethods]
impl QMC2Map {
    #[new]
    pub fn new(key: Vec<u8>) -> PyResult<Self> {
        let key = key_compress(&key)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Ok(Self { key })
    }

    // PyO3 版本的 decrypt 方法，接受 PyByteArray
    pub fn decrypt(&self, data: Bound<'_, PyByteArray>, offset: usize) -> PyResult<()> {
        let buffer = unsafe { data.as_bytes_mut() };
        self.decrypt_mut(buffer, offset);
        Ok(())
    }
}

// 非 PyO3 的内部实现方法
impl QMC2Map {
    // 内部使用的可变切片版本
    pub fn decrypt_mut(&self, data: &mut [u8], offset: usize) {
        for (i, datum) in data.iter_mut().enumerate() {
            *datum = qmc1_transform(&self.key, *datum, offset + i);
        }
    }
    
    // 用于内部创建，不需要 PyResult
    pub fn new_internal(key: Vec<u8>) -> Result<Self, QmcCryptoError> {
        let key = key_compress(&key)?;
        Ok(Self { key })
    }
}

#[test]
fn test_decrypt() {
    let key = (b'a'..=b'z')
        .chain(b'A'..=b'Z')
        .chain(b'0'..=b'9')
        .cycle()
        .take(325)
        .collect::<Vec<u8>>();

    let cipher = QMC2Map::new_internal(key).expect("should not fail");
    let mut actual = [
        0x00u8, 0x9e, 0x41, 0xc1, 0x71, 0x36, 0x00, 0x80, 0xf4, 0x00, 0x75, 0x9e, 0x36, 0x00, 0x14,
        0x8a,
    ];
    cipher.decrypt_mut(&mut actual, 32760);
    assert_eq!(actual, [0u8; 0x10]);
}