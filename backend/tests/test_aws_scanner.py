"""Tests for aws_scanner helper functions (no AWS credentials needed)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aws_scanner import _get_name_tag, get_regions


class TestGetRegions:
    def test_returns_list(self):
        regions = get_regions()
        assert isinstance(regions, list)
        assert len(regions) == 16

    def test_region_structure(self):
        for r in get_regions():
            assert "id" in r
            assert "name" in r

    def test_known_regions(self):
        ids = {r["id"] for r in get_regions()}
        assert "us-east-1" in ids
        assert "eu-west-1" in ids
        assert "ap-southeast-1" in ids


class TestGetNameTag:
    def test_with_name_tag(self):
        tags = [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Name", "Value": "my-server"},
        ]
        assert _get_name_tag(tags) == "my-server"

    def test_without_name_tag(self):
        tags = [{"Key": "Environment", "Value": "prod"}]
        assert _get_name_tag(tags) == ""

    def test_none_tags(self):
        assert _get_name_tag(None) == ""

    def test_empty_tags(self):
        assert _get_name_tag([]) == ""
