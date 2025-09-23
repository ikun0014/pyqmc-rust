import pyqmc_rust


def decrypt_with_ekey():
    ekey = "aWw0MjNSVWxDu8nvoETp6fPi/JwEf9RVZv+gE2M1KsaCSD47MKiip61QnoD+Q/aAbH3KmX9MY9j17b3L9iYBxdXJ0n20aJKqFbryGqq3BXwrAUzd53WbmNS4/5DkyOgVsZXSFEBbfmpiBTic8BsQsqplMsqA6gxBz7vRFUZXBQpgBzSKA/CtpdnI8+13ru8vDppfP66TxPktwH6ccFAXnE+ZzG4TB0RadbniHeVSzOAX7HqN8phn6tTOdfCy1EvIaC1kbArfd0qH7jfdC2Tv/OpTt6Z+HuiA3PK0dLmp5WQl/1IBKVdRRYT9U6vBk6/Es7uxpgEs/7AbZKzpaVujnadJ0T62TJvIR0V1WBC+cVxW0ZorD5ohI1R6ihg8pXYhUIV3kfiYogQupcdFWK7mVGM42H5GBM8g9ox1HTVXv3Yqw2NNryGFdOFsgAGOw2n8Rnn0ms48cH3UDgzvCH0H6UjsqSo3KPp+YFjvE5JvWmCyWspnIzYy0vBSZZ758ONCPh0D7tD6nvTEvf+wxw2KfuEku7U7r7bl8cPi0vMmyVTVAafI+i/rN/qMx9h1rVnwgNO5SV8a7YjCxobrVcMSbkGCaVBRLNVVoZ1doz1TU2y5Eg0fbOheg6Or/+OS2KdIVbbFvg21kx/UO7wElMZB5KjopT/TEqrc2kaONu4F0JtufpVaUOp/xL/BBPLEYsB8"

    cipher = pyqmc_rust.QMCv2Cipher.new_from_ekey(ekey.encode())

    with open("AIM0002QpiAq45fm0g.mflac", "rb") as f:
        data = bytearray(f.read())

    cipher.decrypt(data, 0)

    with open("t.flac", "wb") as f:
        f.write(data)


decrypt_with_ekey()
