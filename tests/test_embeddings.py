"""Tests for embeddings module."""

import math
import struct

from src.ai.embeddings import (
    EMBEDDING_DIMS,
    EMBEDDING_MODEL,
    cosine_similarity,
    from_blob,
    to_blob,
)


def test_embedding_model_set():
    assert EMBEDDING_MODEL == "qwen2.5"
    assert EMBEDDING_DIMS == 3584


def test_to_blob_and_back():
    vec = [1.0, 2.0, 3.0, 0.5, -0.5]
    blob = to_blob(vec)
    assert isinstance(blob, bytes)
    assert len(blob) == len(vec) * 4
    recovered = from_blob(blob)
    for a, b in zip(vec, recovered):
        assert abs(a - b) < 1e-6


def test_cosine_similarity_identical():
    vec = [1.0, 2.0, 3.0]
    assert abs(cosine_similarity(vec, vec) - 1.0) < 1e-6


def test_cosine_similarity_orthogonal():
    a = [1.0, 0.0]
    b = [0.0, 1.0]
    assert abs(cosine_similarity(a, b)) < 1e-6


def test_cosine_similarity_opposite():
    a = [1.0, 0.0]
    b = [-1.0, 0.0]
    assert abs(cosine_similarity(a, b) - (-1.0)) < 1e-6


def test_cosine_similarity_zero_vector():
    a = [0.0, 0.0]
    b = [1.0, 2.0]
    assert cosine_similarity(a, b) == 0.0


def test_from_blob_empty():
    blob = b""
    assert from_blob(blob) == []


def test_to_blob_single():
    vec = [42.0]
    blob = to_blob(vec)
    assert len(blob) == 4
    assert from_blob(blob) == [42.0]
