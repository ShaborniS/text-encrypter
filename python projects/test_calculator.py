from library import multiply
def test_positive():
    assert multiply(2)==4
    assert multiply(3)==9
def test_negative():
    assert multiply(-2)==4
    assert multiply(-3)==9
def test_zero():
    assert multiply(0)==0