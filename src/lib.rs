use pyo3::prelude::*;
use pyo3::types::PyByteArray;

use crate::map::QMC2Map;
use crate::rc4::cipher::QMC2RC4;
use thiserror::Error;

pub mod v1;
pub mod ekey;
pub mod map;
pub mod rc4;

#[derive(Error, Debug)]
pub enum QmcCryptoError {
    #[error("QMC V2/Map Cipher: Key is empty")]
    QMCV2MapKeyEmpty,

    #[error("EKey: {0}")]
    EKeyParseError(#[from] ekey::EKeyDecryptError),
}

#[pyclass]
#[derive(Debug, PartialEq, Clone)]
pub enum QMCv2Cipher {
    MapL(QMC2Map),
    RC4(QMC2RC4),
}

#[pymethods]
impl QMCv2Cipher {
    #[new]
    pub fn new(key: Vec<u8>) -> PyResult<Self> {
        if key.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "QMC V2/Map Cipher: Key is empty"
            ));
        }
        
        let cipher = match key.len() {
            1..=300 => {
                // 使用 QMC2Map 的内部构造函数，然后转换错误
                let map = QMC2Map::new_internal(key).map_err(|e| 
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string())
                )?;
                QMCv2Cipher::MapL(map)
            },
            _ => QMCv2Cipher::RC4(QMC2RC4::new(key)),
        };
        Ok(cipher)
    }

    #[staticmethod]
    pub fn new_from_ekey(ekey_str: Vec<u8>) -> PyResult<Self> {
        let key = ekey::decrypt(&ekey_str)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Self::new(key)
    }

    pub fn decrypt(&self, data: Bound<'_, PyByteArray>, offset: usize) -> PyResult<()> {
        match self {
            QMCv2Cipher::MapL(cipher) => cipher.decrypt(data, offset),
            QMCv2Cipher::RC4(cipher) => cipher.decrypt(data, offset),
        }
    }
}

#[cfg(test)]
mod test {
    pub fn generate_key(len: usize) -> Vec<u8> {
        (1..=len).map(|i| i as u8).collect()
    }

    #[cfg(test)]
    pub fn generate_key_128() -> [u8; 128] {
        generate_key(128)
            .try_into()
            .expect("failed to make test key")
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn pyqmc_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<QMCv2Cipher>()?;
    Ok(())
}