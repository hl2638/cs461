#!/usr/bin/env python3
# -*- coding: latin-1 -*-
blob = """
    Z����_�T��t:��_�����Ьd �>Ir"�E���Rx��O0dZ  j<��ˏ�E6q�-Y�g��6/U�κ��Es�-��(�v��[OM�A%N����s�+�����"�b��y0y�gͮ1�U�"""
from hashlib import sha256
print(sha256(blob.encode()).hexdigest())
