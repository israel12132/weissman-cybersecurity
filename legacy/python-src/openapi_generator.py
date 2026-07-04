"""
src/openapi_generator.py
=========================
OpenAPI 3.0 specification generator for Weissman Cybersecurity API.

Generates interactive Swagger UI documentation for all API endpoints.

Usage:
    python -m src.openapi_generator > openapi.json

    # Or serve with Swagger UI
    from src.openapi_generator import get_openapi_spec, serve_swagger_ui
    serve_swagger_ui(port=8081)
"""

import json
import logging
from typing import Dict, Any

logger = logging.getLogger("weissman.openapi")

# API metadata
API_VERSION = "1.0.0"
API_TITLE = "Weissman Cybersecurity API"
API_DESCRIPTION = """
Enterprise-grade offensive security testing platform with 250+ attack engines.

Features:
- Multi-tenant architecture with RLS
- Real-time WebSocket updates
- Threat intelligence correlation
- PDF/Excel report generation
- MFA and RBAC

Authentication: JWT Bearer tokens
Rate Limiting: Per-tenant sliding window
"""

API_CONTACT = {
    "name": "Weissman Security Team",
    "email": "security@weissman.local",
    "url": "https://weissman.local",
}

API_LICENSE = {
    "name": "Proprietary",
    "url": "https://weissman.local/license",
}


def get_openapi_spec() -> Dict[str, Any]:
    """
    Generate complete OpenAPI 3.0 specification.

    Returns
    -------
    dict
        OpenAPI 3.0 spec
    """
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": API_TITLE,
            "description": API_DESCRIPTION,
            "version": API_VERSION,
            "contact": API_CONTACT,
            "license": API_LICENSE,
        },
        "servers": [
            {
                "url": "http://localhost:8080",
                "description": "Development server",
            },
            {
                "url": "https://api.weissman.local",
                "description": "Production server",
            },
        ],
        "tags": [
            {"name": "auth", "description": "Authentication and authorization"},
            {"name": "scans", "description": "Security scan operations"},
            {"name": "findings", "description": "Vulnerability findings"},
            {"name": "exports", "description": "Report generation"},
            {"name": "correlation", "description": "Threat intelligence"},
            {"name": "admin", "description": "Admin operations"},
        ],
        "paths": _get_paths(),
        "components": _get_components(),
        "security": [{"bearerAuth": []}],
    }

    return spec


def _get_paths() -> Dict[str, Any]:
    """Define all API endpoints."""
    return {
        "/api/auth/login": {
            "post": {
                "tags": ["auth"],
                "summary": "Login with email and password",
                "description": "Authenticate user and return JWT token",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LoginRequest"},
                            "example": {
                                "email": "analyst@example.com",
                                "password": "SecurePass123!",
                            },
                        },
                    },
                },
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginResponse"},
                            },
                        },
                    },
                    "401": {"description": "Invalid credentials"},
                    "429": {"description": "Rate limit exceeded"},
                },
            },
        },
        "/api/auth/mfa/verify": {
            "post": {
                "tags": ["auth"],
                "summary": "Verify MFA token",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/MFAVerifyRequest"},
                        },
                    },
                },
                "responses": {
                    "200": {"description": "MFA verified successfully"},
                    "401": {"description": "Invalid MFA token"},
                },
            },
        },
        "/api/scan/run-all": {
            "post": {
                "tags": ["scans"],
                "summary": "Trigger comprehensive security scan",
                "description": "Run all enabled attack engines against target",
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ScanRequest"},
                            "example": {
                                "target": "https://example.com",
                                "engines": ["xss", "sqli", "csrf", "xxe"],
                                "depth": 3,
                            },
                        },
                    },
                },
                "responses": {
                    "202": {
                        "description": "Scan queued successfully",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanQueuedResponse"},
                            },
                        },
                    },
                    "400": {"description": "Invalid request"},
                    "403": {"description": "Target out of scope"},
                    "429": {"description": "Rate limit exceeded"},
                },
            },
        },
        "/api/scan/status/{scan_id}": {
            "get": {
                "tags": ["scans"],
                "summary": "Get scan status",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Scan status retrieved",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanStatus"},
                            },
                        },
                    },
                    "404": {"description": "Scan not found"},
                },
            },
        },
        "/api/scan/results/{scan_id}": {
            "get": {
                "tags": ["scans"],
                "summary": "Get scan results",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Scan results retrieved",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ScanResults"},
                            },
                        },
                    },
                    "404": {"description": "Scan not found"},
                },
            },
        },
        "/api/findings": {
            "get": {
                "tags": ["findings"],
                "summary": "List all findings for tenant",
                "parameters": [
                    {
                        "name": "severity",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                    },
                    {
                        "name": "status",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "enum": ["new", "confirmed", "false_positive", "fixed"],
                        },
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "default": 100},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Findings list",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "findings": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/Finding"},
                                        },
                                        "total": {"type": "integer"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "/api/export/pdf/{scan_id}": {
            "post": {
                "tags": ["exports"],
                "summary": "Generate PDF report",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    },
                ],
                "responses": {
                    "200": {
                        "description": "PDF generated successfully",
                        "content": {
                            "application/pdf": {
                                "schema": {"type": "string", "format": "binary"},
                            },
                        },
                    },
                    "404": {"description": "Scan not found"},
                },
            },
        },
        "/api/correlation/run": {
            "post": {
                "tags": ["correlation"],
                "summary": "Run threat intelligence correlation",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "feeds": {
                                        "type": "array",
                                        "items": {
                                            "type": "string",
                                            "enum": ["nvd", "github", "osv", "otx", "hibp"],
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                "responses": {
                    "202": {"description": "Correlation job queued"},
                    "429": {"description": "Rate limit exceeded"},
                },
            },
        },
        "/metrics": {
            "get": {
                "tags": ["admin"],
                "summary": "Prometheus metrics endpoint",
                "description": "Metrics for monitoring and alerting",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Prometheus metrics",
                        "content": {
                            "text/plain": {
                                "schema": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
        "/health": {
            "get": {
                "tags": ["admin"],
                "summary": "Health check endpoint",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Service healthy",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthResponse"},
                            },
                        },
                    },
                },
            },
        },
    }


def _get_components() -> Dict[str, Any]:
    """Define reusable schemas and security schemes."""
    return {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT token from /api/auth/login",
            },
        },
        "schemas": {
            "LoginRequest": {
                "type": "object",
                "required": ["email", "password"],
                "properties": {
                    "email": {"type": "string", "format": "email"},
                    "password": {"type": "string", "minLength": 12},
                },
            },
            "LoginResponse": {
                "type": "object",
                "properties": {
                    "access_token": {"type": "string"},
                    "token_type": {"type": "string", "enum": ["Bearer"]},
                    "expires_in": {"type": "integer"},
                    "mfa_required": {"type": "boolean"},
                },
            },
            "MFAVerifyRequest": {
                "type": "object",
                "required": ["email", "token"],
                "properties": {
                    "email": {"type": "string", "format": "email"},
                    "token": {"type": "string", "pattern": "^[0-9]{6}$"},
                },
            },
            "ScanRequest": {
                "type": "object",
                "required": ["target"],
                "properties": {
                    "target": {"type": "string", "format": "uri"},
                    "engines": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of engine IDs to run",
                    },
                    "depth": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5,
                        "default": 2,
                    },
                },
            },
            "ScanQueuedResponse": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "format": "uuid"},
                    "status": {"type": "string", "enum": ["queued"]},
                    "estimated_duration": {"type": "integer"},
                },
            },
            "ScanStatus": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["queued", "running", "completed", "failed"],
                    },
                    "progress": {"type": "integer", "minimum": 0, "maximum": 100},
                    "started_at": {"type": "string", "format": "date-time"},
                    "completed_at": {"type": "string", "format": "date-time"},
                },
            },
            "ScanResults": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "findings": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Finding"},
                    },
                    "summary": {
                        "type": "object",
                        "properties": {
                            "total_findings": {"type": "integer"},
                            "critical": {"type": "integer"},
                            "high": {"type": "integer"},
                            "medium": {"type": "integer"},
                            "low": {"type": "integer"},
                            "info": {"type": "integer"},
                        },
                    },
                },
            },
            "Finding": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
                    "cwe_id": {"type": "string"},
                    "url": {"type": "string", "format": "uri"},
                    "proof_of_concept": {"type": "string"},
                    "remediation": {"type": "string"},
                    "references": {
                        "type": "array",
                        "items": {"type": "string", "format": "uri"},
                    },
                },
            },
            "HealthResponse": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["healthy", "degraded"]},
                    "version": {"type": "string"},
                    "database": {"type": "boolean"},
                    "redis": {"type": "boolean"},
                    "vault": {"type": "boolean"},
                },
            },
        },
    }


def save_openapi_spec(output_path: str = "openapi.json"):
    """
    Save OpenAPI spec to file.

    Parameters
    ----------
    output_path : str
        Output file path
    """
    spec = get_openapi_spec()

    with open(output_path, "w") as f:
        json.dump(spec, f, indent=2)

    logger.info("openapi: saved specification to %s", output_path)


# DEPRECATED: Flask-based Swagger UI server removed
# Swagger UI is now served by the Rust backend (weissman-server).
# Access it at: http://localhost:8000/docs or configure with WEISSMAN_SWAGGER_UI_PATH
#
# The serve_swagger_ui() function below is kept as a standalone development utility only.
# It requires: pip install flask flask-swagger-ui
# Usage: python -c "from src.openapi_generator import serve_swagger_ui; serve_swagger_ui()"


def serve_swagger_ui(port: int = 8081):
    """
    [DEPRECATED - Development utility only]
    Serve Swagger UI for API documentation using Flask.

    This function is deprecated for production use. The Rust backend now serves Swagger UI.
    Use this only for standalone development/testing of OpenAPI specs.

    Parameters
    ----------
    port : int
        HTTP server port (default: 8081)

    Requires
    --------
    Flask and flask-swagger-ui (not in production requirements.txt)

    Examples
    --------
    >>> serve_swagger_ui(port=8081)
    # Open browser: http://localhost:8081/docs
    """
    try:
        from flask import Flask, jsonify
        from flask_swagger_ui import get_swaggerui_blueprint

        app = Flask(__name__)

        # Swagger UI configuration
        SWAGGER_URL = "/docs"
        API_URL = "/openapi.json"

        swaggerui_blueprint = get_swaggerui_blueprint(
            SWAGGER_URL,
            API_URL,
            config={"app_name": API_TITLE},
        )

        app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

        @app.route("/openapi.json")
        def openapi_json():
            return jsonify(get_openapi_spec())

        logger.info("openapi: Swagger UI available at http://localhost:%d/docs", port)
        logger.warning("openapi: serve_swagger_ui() is deprecated - use Rust backend for production")
        app.run(port=port)

    except ImportError as exc:
        logger.error("openapi: Flask or flask-swagger-ui not installed (%s)", exc)
        print("Install with: pip install flask flask-swagger-ui")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        serve_swagger_ui()
    else:
        spec = get_openapi_spec()
        print(json.dumps(spec, indent=2))
