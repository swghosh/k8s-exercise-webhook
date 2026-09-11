#!/usr/bin/env python3
"""Validating Admission Webhook that rejects container images from unapproved registries."""

import argparse
import json
import ssl
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

APPROVED_REGISTRIES = []


def extract_registry(image: str) -> str:
    """Extract the registry from a container image reference.

    Examples:
        docker.io/library/nginx -> docker.io
        gcr.io/my-project/app:v1 -> gcr.io
        nginx:latest -> docker.io  (implicit default)
        my-registry.com:5000/app -> my-registry.com:5000
    """
    # Remove tag/digest
    ref = image.split("@")[0].split(":")[0] if "@" in image else image
    if "@" not in image and ":" in image:
        # Could be registry:port/image or image:tag
        parts = image.split("/")
        if len(parts) == 1:
            # image:tag — no registry, default to docker.io
            return "docker.io"
        # Reconstruct without the tag on the last component
        ref = "/".join(parts[:-1] + [parts[-1].split(":")[0]])

    parts = ref.split("/")
    if len(parts) == 1:
        # bare image name like "nginx"
        return "docker.io"
    first = parts[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    # e.g. "library/nginx" — docker.io implicit
    return "docker.io"


def validate_request(admission_review: dict) -> dict:
    """Validate the AdmissionReview request and return a response."""
    request = admission_review["request"]
    uid = request["uid"]
    obj = request.get("object", {})

    # Collect all container images from the pod spec
    containers = []
    # Handle Pod directly
    pod_spec = None
    kind = request.get("kind", {}).get("kind", "")
    if kind == "Pod":
        pod_spec = obj.get("spec", {})
    else:
        # Deployment, ReplicaSet, Job, etc.
        pod_spec = obj.get("spec", {}).get("template", {}).get("spec", {})

    if pod_spec:
        for c in pod_spec.get("containers", []):
            containers.append(c)
        for c in pod_spec.get("initContainers", []):
            containers.append(c)
        for c in pod_spec.get("ephemeralContainers", []):
            containers.append(c)

    denied_images = []
    for c in containers:
        image = c.get("image", "")
        registry = extract_registry(image)
        if not any(registry == approved or registry.endswith("." + approved)
                   for approved in APPROVED_REGISTRIES):
            denied_images.append(f"{c.get('name', '?')}: {image} (registry: {registry})")

    allowed = len(denied_images) == 0
    response = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed,
        },
    }
    if not allowed:
        response["response"]["status"] = {
            "code": 403,
            "message": (
                f"Images from unapproved registries are not allowed. "
                f"Approved registries: {APPROVED_REGISTRIES}. "
                f"Rejected: {'; '.join(denied_images)}"
            ),
        }
    return response


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            admission_review = json.loads(body)
            response = validate_request(admission_review)
        except Exception as e:
            response = {
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "response": {
                    "uid": "",
                    "allowed": False,
                    "status": {"code": 500, "message": str(e)},
                },
            }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        print(f"[webhook] {args[0]} {args[1]} {args[2]}")


def main():
    parser = argparse.ArgumentParser(description="Image registry validating webhook")
    parser.add_argument(
        "--approved-registries",
        required=True,
        help="Comma-separated list of approved registries (e.g. docker.io,gcr.io,quay.io)",
    )
    parser.add_argument("--tls-cert", required=True, help="Path to TLS certificate file")
    parser.add_argument("--tls-key", required=True, help="Path to TLS private key file")
    parser.add_argument("--port", type=int, default=8443, help="Port to listen on (default: 8443)")
    args = parser.parse_args()

    global APPROVED_REGISTRIES
    APPROVED_REGISTRIES = [r.strip() for r in args.approved_registries.split(",") if r.strip()]
    print(f"Approved registries: {APPROVED_REGISTRIES}")

    server = HTTPServer(("0.0.0.0", args.port), WebhookHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.tls_cert, args.tls_key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"Webhook server listening on :{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
