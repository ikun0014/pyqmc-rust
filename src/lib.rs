use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyByteArray;

use crate::map::QMC2Map;
use crate::rc4::cipher::QMC2RC4;
use thiserror::Error;

pub mod ekey;
pub mod map;
pub mod rc4;
pub mod v1;

// 创建自定义的 Python 异常类型
create_exception!(pyqmc_rust, QMCKeyEmptyError, PyException);
create_exception!(pyqmc_rust, QMCEKeyDecryptError, PyException);
create_exception!(pyqmc_rust, QMCEKeyTooShortError, QMCEKeyDecryptError);
create_exception!(pyqmc_rust, QMCEKeyV1DecryptError, QMCEKeyDecryptError);
create_exception!(pyqmc_rust, QMCEKeyV2DecryptError, QMCEKeyDecryptError);
create_exception!(pyqmc_rust, QMCBase64DecodeError, QMCEKeyDecryptError);

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
            return Err(QMCKeyEmptyError::new_err("QMC V2/Map Cipher: Key is empty"));
        }

        let cipher = match key.len() {
            1..=300 => {
                let map = QMC2Map::new_internal(key).map_err(|e| match e {
                    QmcCryptoError::QMCV2MapKeyEmpty => QMCKeyEmptyError::new_err(e.to_string()),
                    QmcCryptoError::EKeyParseError(ekey_err) => convert_ekey_error_to_py(ekey_err),
                })?;
                QMCv2Cipher::MapL(map)
            }
            _ => QMCv2Cipher::RC4(QMC2RC4::new(key)),
        };
        Ok(cipher)
    }

    #[staticmethod]
    pub fn new_from_ekey(ekey_str: String) -> PyResult<Self> {
        let key = ekey::decrypt(&ekey_str.as_bytes().to_vec())
            .map_err(|e| convert_ekey_error_to_py(e))?;
        Self::new(key)
    }

    pub fn decrypt(&self, data: Bound<'_, PyByteArray>, offset: usize) -> PyResult<()> {
        match self {
            QMCv2Cipher::MapL(cipher) => cipher.decrypt(data, offset),
            QMCv2Cipher::RC4(cipher) => cipher.decrypt(data, offset),
        }
    }
}

// 辅助函数：将 EKeyDecryptError 转换为对应的 Python 异常
fn convert_ekey_error_to_py(error: ekey::EKeyDecryptError) -> PyErr {
    use ekey::EKeyDecryptError;
    match error {
        EKeyDecryptError::EKeyTooShort => {
            QMCEKeyTooShortError::new_err("EKey is too short for decryption")
        }
        EKeyDecryptError::FailDecryptV1(e) => {
            QMCEKeyV1DecryptError::new_err(format!("Error when decrypting ekey v1: {}", e))
        }
        EKeyDecryptError::FailDecryptV2(e) => {
            QMCEKeyV2DecryptError::new_err(format!("Error when decrypting ekey v2: {}", e))
        }
        EKeyDecryptError::Base64Decode(e) => {
            QMCBase64DecodeError::new_err(format!("Failed to decode base64 content: {}", e))
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

#[pymodule]
fn pyqmc_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // 注册 Cipher 类
    m.add_class::<QMCv2Cipher>()?;

    // 注册所有自定义异常类型
    m.add("QMCKeyEmptyError", m.py().get_type::<QMCKeyEmptyError>())?;
    m.add(
        "QMCEKeyDecryptError",
        m.py().get_type::<QMCEKeyDecryptError>(),
    )?;
    m.add(
        "QMCEKeyTooShortError",
        m.py().get_type::<QMCEKeyTooShortError>(),
    )?;
    m.add(
        "QMCEKeyV1DecryptError",
        m.py().get_type::<QMCEKeyV1DecryptError>(),
    )?;
    m.add(
        "QMCEKeyV2DecryptError",
        m.py().get_type::<QMCEKeyV2DecryptError>(),
    )?;
    m.add(
        "QMCBase64DecodeError",
        m.py().get_type::<QMCBase64DecodeError>(),
    )?;

    Ok(())
}
