# SPDX-License-Identifier: (Apache-2.0 OR MIT)

# 异常类型定义
class QMCKeyEmptyError(Exception):
    """密钥为空时抛出的异常"""

    ...

class QMCEKeyDecryptError(Exception):
    """EKey 解密失败的基类异常"""

    ...

class QMCEKeyTooShortError(QMCEKeyDecryptError):
    """EKey 太短无法解密时抛出的异常"""

    ...

class QMCEKeyV1DecryptError(QMCEKeyDecryptError):
    """EKey V1 解密失败时抛出的异常"""

    ...

class QMCEKeyV2DecryptError(QMCEKeyDecryptError):
    """EKey V2 解密失败时抛出的异常"""

    ...

class QMCBase64DecodeError(QMCEKeyDecryptError):
    """Base64 解码失败时抛出的异常"""

    ...

# Cipher 类型定义
class QMCv2Cipher:
    """QMC V2 解密器"""

    def __init__(self, key: bytes) -> None:
        """
        创建新的 QMCv2Cipher 实例

        Args:
            key: 解密密钥

        Raises:
            QMCKeyEmptyError: 当密钥为空时
        """
        ...

    @staticmethod
    def new_from_ekey(ekey_str: str) -> "QMCv2Cipher":
        """
        从 EKey 字符串创建新的 QMCv2Cipher 实例

        Args:
            ekey_str: EKey 字符串

        Returns:
            QMCv2Cipher 实例

        Raises:
            QMCEKeyTooShortError: 当 EKey 太短时
            QMCEKeyV1DecryptError: 当 V1 解密失败时
            QMCEKeyV2DecryptError: 当 V2 解密失败时
            QMCBase64DecodeError: 当 Base64 解码失败时
            QMCKeyEmptyError: 当解密后的密钥为空时
        """
        ...

    def decrypt(self, data: bytearray, offset: int) -> None:
        """
        解密数据（就地修改）

        Args:
            data: 要解密的数据
            offset: 偏移量
        """
        ...
