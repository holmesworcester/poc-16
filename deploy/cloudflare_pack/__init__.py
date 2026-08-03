"""Cloudflare-only data plane for immutable writer packs.

The package intentionally imports nothing: the native PUT Worker can import
``put`` without loading the control-plane SigV4 issuer.
"""
