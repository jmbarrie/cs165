import pytest
from md5_crypt import MD5_Crypt

@pytest.fixture
def crypt():
    password = 'zhgnnd'
    salt = 'hfT7jp2q'
    password_length = 6

    return MD5_Crypt(password, salt, password_length)

def test_alternate_sum(crypt):
    solution = b'\x3f\xfc\x86\xe7\xc7\x8f\x47\xa8\x16\x4f\xe2\x85\xc0\xfa\x22\x55'
    assert crypt._calculate_alternate_sum().hexdigest() == solution.hex()

def test_intermediate_sum(crypt):
    solution = b'\xed\x7a\x53\x07\x58\x8e\x49\xed\x3a\x27\x77\xd9\x26\xd6\x2f\x96'
    value = crypt._calculate_intermediate().hexdigest()
    assert value == solution.hex() 

def test_loop(crypt):
    solution = b'\xff\x20\x2f\x2e\x9b\x6a\xc6\xe4\x95\x57\x05\x36\xfc\x89\xfd\x2a'
    intermediate = b'\xed\x7a\x53\x07\x58\x8e\x49\xed\x3a\x27\x77\xd9\x26\xd6\x2f\x96'
    value = crypt._loop(intermediate).hex()
    assert value == solution.hex()
    
def test_integration(crypt):
    solution = '$1$hfT7jp2q$wPwz7GC6xLt9eQZ9eJkaq.'
    value = crypt.get_hash()
    assert value == solution